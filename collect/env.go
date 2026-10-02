package collect

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// EnvOf derives the environment (OS, privileges, virtualisation, distro,
// package manager) from a bundle's meta sections.
func EnvOf(b *Bundle) model.Env {
	o := b.Options.WithDefaults()
	env := model.Env{OS: b.OS, SinceDays: o.SinceDays, Now: b.Finished}
	switch b.OS {
	case OSLinux:
		id := b.Get("meta.ident").KV()
		env.Root = id["uid"] == "0"
		if t, err := time.Parse(time.RFC3339, id["now"]); err == nil {
			env.Now = t
		}
		osr := ParseOSRelease(b.Get("meta.osrelease").Text())
		env.Distro, env.DistroVer, env.Like = osr["ID"], osr["VERSION_ID"], osr["ID_LIKE"]
		if env.Distro == "debian" && b.Get("meta.virt") != nil {
			// Proxmox VE reports ID=debian; the kernel name gives it away.
			if strings.Contains(id["kernel"], "-pve") {
				env.Distro = "proxmox"
			}
		}
		pm := b.Get("meta.pm").KV()
		for _, p := range []string{"dnf", "yum", "apt-get", "zypper", "apk", "pacman"} {
			if pm[p] == "1" {
				env.PM = strings.TrimSuffix(p, "-get")
				break
			}
		}
		env.Virtual, env.Container = linuxVirt(b.Get("meta.virt").KV())
	case OSWindows:
		var id []struct {
			Admin bool   `json:"admin"`
			Now   string `json:"now"`
			Build string `json:"build"`
		}
		if DecodeJSON(b.Get("meta.ident").Text(), &id) == nil && len(id) > 0 {
			env.Root = id[0].Admin
			if t, ok := WinTime(id[0].Now); ok {
				env.Now = t
			}
			env.DistroVer = id[0].Build
		}
		env.Distro = "windows"
		var v []struct {
			Manufacturer     string `json:"manufacturer"`
			Model            string `json:"model"`
			BiosManufacturer string `json:"biosManufacturer"`
			BiosVersion      string `json:"biosVersion"`
		}
		if DecodeJSON(b.Get("meta.virt").Text(), &v) == nil && len(v) > 0 {
			env.Virtual = classifyVirt(v[0].Manufacturer, v[0].Model)
			if env.Virtual == "" {
				env.Virtual = classifyBIOS(v[0].BiosManufacturer, v[0].BiosVersion)
			}
		}
	case OSBMC:
		env.Root = true
	}
	if env.Now.IsZero() {
		env.Now = b.Finished
	}
	return env
}

// ParseOSRelease parses /etc/os-release.
func ParseOSRelease(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		m[k] = v
	}
	return m
}

func linuxVirt(kv map[string]string) (virtual string, container bool) {
	if kv["wsl"] == "1" {
		return "wsl", true
	}
	for _, k := range []string{"container", "pid1_container"} {
		if c := kv[k]; c != "" && c != "none" {
			return c, true
		}
	}
	switch {
	case kv["openvz"] == "1":
		return "openvz", true
	case kv["dockerenv"] == "1":
		return "docker", true
	case kv["containerenv"] == "1":
		return "podman", true
	}
	if vm := kv["vm"]; vm != "" && vm != "none" {
		return vm, false
	}
	if _, ok := kv["vm"]; ok {
		return "", false // systemd-detect-virt said "none": trust it
	}
	if v := classifyVirt(kv["sys_vendor"], kv["product_name"]); v != "" {
		return v, false
	}
	if kv["hypervisor_flag"] == "1" {
		return "vm", false
	}
	return "", false
}

// classifyVirt recognises virtual machines from SMBIOS vendor/product.
func classifyVirt(vendor, product string) string {
	v, p := strings.ToLower(vendor), strings.ToLower(product)
	switch {
	case strings.Contains(v, "red hat") && (strings.Contains(p, " pc (") || strings.Contains(p, "kvm") || strings.Contains(p, "rhel") || strings.Contains(p, "openstack")):
		return "kvm" // RHEL/oVirt/RHV KVM guests: "Red Hat" / "RHEL 7.6.0 PC (i440FX + PIIX, 1996)"
	case strings.Contains(v, "ovirt") || strings.Contains(p, "ovirt"):
		return "kvm"
	case strings.Contains(v, "bhyve") || strings.Contains(p, "bhyve"):
		return "bhyve"
	case strings.Contains(v, "hetzner") && strings.Contains(p, "vserver"):
		return "kvm"
	case strings.Contains(p, "vmware") || strings.Contains(v, "vmware"):
		return "vmware"
	case strings.Contains(p, "virtualbox") || strings.Contains(v, "innotek"):
		return "oracle"
	case strings.Contains(v, "microsoft") && strings.Contains(p, "virtual"):
		return "microsoft"
	case strings.Contains(p, "kvm") || strings.Contains(v, "qemu") || strings.Contains(p, "standard pc (") || strings.Contains(p, "bochs"):
		return "kvm"
	case strings.Contains(p, "hvm domu") || strings.Contains(v, "xen"):
		return "xen"
	case strings.Contains(v, "amazon ec2") || strings.Contains(p, "amazon ec2"):
		return "amazon"
	case strings.Contains(p, "google compute engine"):
		return "google"
	case strings.Contains(p, "openstack"):
		return "kvm"
	case strings.Contains(v, "alibaba") || strings.Contains(p, "alibaba cloud"):
		return "alibaba"
	case strings.Contains(v, "digitalocean") || p == "droplet":
		return "kvm"
	case strings.Contains(v, "parallels"):
		return "parallels"
	case strings.Contains(v, "nutanix") && strings.Contains(p, "ahv"):
		return "kvm"
	}
	return ""
}

// classifyBIOS recognises virtual firmware when the SMBIOS system strings
// are customised (Windows guests): SeaBIOS/OVMF (KVM), Hyper-V "VRTUAL",
// VMware "VMW..." BIOS versions, Xen.
func classifyBIOS(maker, version string) string {
	m, ver := strings.ToLower(maker), strings.ToLower(version)
	switch {
	case strings.Contains(m, "seabios") || strings.Contains(ver, "seabios") || strings.Contains(m, "ovmf") || strings.Contains(ver, "ovmf") || strings.Contains(m, "development kit ii"):
		return "kvm"
	case strings.HasPrefix(ver, "vrtual") || strings.Contains(ver, "hyper-v"):
		return "microsoft"
	case strings.HasPrefix(ver, "vmw") || strings.Contains(m, "vmware"):
		return "vmware"
	case strings.Contains(m, "xen") || strings.Contains(ver, "xen"):
		return "xen"
	case strings.Contains(m, "innotek") || strings.Contains(ver, "virtualbox"):
		return "oracle"
	}
	return ""
}

// DecodeJSON decodes JSON written by the Windows collector. DW-Json always
// writes an array, but this also accepts a single object where v is a
// pointer to a slice.
func DecodeJSON(s string, v any) error {
	s = strings.TrimSpace(strings.TrimPrefix(s, string(rune(0xFEFF))))
	if s == "" {
		s = "[]"
	}
	err := json.Unmarshal([]byte(s), v)
	if err != nil && strings.HasPrefix(s, "{") {
		if err2 := json.Unmarshal([]byte("["+s+"]"), v); err2 == nil {
			return nil
		}
	}
	return err
}

// WinTime parses a time written by PowerShell: ISO 8601 (what the
// collector writes) or the 5.1 "\/Date(1700000000000)\/" form.
func WinTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if strings.HasPrefix(s, "/Date(") || strings.HasPrefix(s, `\/Date(`) {
		in := s[strings.IndexByte(s, '(')+1:]
		if i := strings.IndexAny(in, ")+-"); i > 0 {
			in = in[:i]
		}
		var ms int64
		for _, c := range in {
			if c < '0' || c > '9' {
				return time.Time{}, false
			}
			ms = ms*10 + int64(c-'0')
		}
		return time.UnixMilli(ms).UTC(), true
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
