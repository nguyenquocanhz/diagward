// Package hint builds the "how to enable this check" texts that coverage
// entries carry: install commands for the right package manager, "run as
// root", "this is a VM".
package hint

import (
	"strings"

	"github.com/nguyenquocanhz/diagward/model"
)

// Package names per tool and distribution family. "" means "same as the tool".
var packages = map[string]map[string]string{
	"smartctl":   {"*": "smartmontools"},
	"sensors":    {"rhel": "lm_sensors", "debian": "lm-sensors", "suse": "sensors", "arch": "lm_sensors", "alpine": "lm-sensors"},
	"ipmitool":   {"*": "ipmitool"},
	"memtester":  {"*": "memtester"},
	"ras-mc-ctl": {"*": "rasdaemon"},
	"mcelog":     {"*": "mcelog"},
	"mdadm":      {"*": "mdadm"},
	"nvme":       {"*": "nvme-cli"},
	"dmidecode":  {"*": "dmidecode"},
	"ethtool":    {"*": "ethtool"},
	"lspci":      {"*": "pciutils"},
	"edac-util":  {"debian": "edac-utils", "rhel": "edac-utils"},
	"lsblk":      {"*": "util-linux"},
	"zpool":      {"debian": "zfsutils-linux", "rhel": "zfs", "*": "zfs"},
	"journalctl": {"*": "systemd"},
	"lscpu":      {"*": "util-linux"},
	"sar":        {"*": "sysstat"},
	"hdparm":     {"*": "hdparm"},
	"storcli":    {},
	"perccli":    {},
	"ssacli":     {},
	"arcconf":    {},
}

// Vendor tools that are not in distribution repositories.
var vendorTools = map[string]model.Text{
	"storcli": model.T("Install Broadcom StorCLI (storcli64) from broadcom.com for LSI/Broadcom MegaRAID controllers.",
		"Cài Broadcom StorCLI (storcli64) từ broadcom.com cho card RAID LSI/Broadcom MegaRAID."),
	"perccli": model.T("Install Dell PERC CLI (perccli64) from dell.com/support for PERC controllers.",
		"Cài Dell PERC CLI (perccli64) từ dell.com/support cho card RAID PERC."),
	"ssacli": model.T("Install HPE Smart Storage Administrator CLI (ssacli) from the HPE Service Pack for ProLiant or HPE's repository.",
		"Cài HPE Smart Storage Administrator CLI (ssacli) từ HPE Service Pack for ProLiant hoặc kho phần mềm của HPE."),
	"arcconf": model.T("Install Microchip/Adaptec ARCCONF from microchip.com for Adaptec SmartRAID/HBA controllers.",
		"Cài Microchip/Adaptec ARCCONF từ microchip.com cho card Adaptec SmartRAID/HBA."),
}

// Family returns the distribution family of env: rhel, debian, suse, arch,
// alpine, windows or "".
func Family(env model.Env) string {
	if env.OS == "windows" {
		return "windows"
	}
	ids := strings.Fields(strings.ToLower(env.Distro + " " + env.Like))
	for _, id := range ids {
		switch id {
		case "rhel", "centos", "fedora", "almalinux", "rocky", "ol", "amzn", "cloudlinux", "eurolinux", "virtuozzo":
			return "rhel"
		case "debian", "ubuntu", "proxmox", "linuxmint", "raspbian", "pop":
			return "debian"
		case "suse", "opensuse", "sles", "sled", "opensuse-leap", "opensuse-tumbleweed":
			return "suse"
		case "arch", "manjaro", "endeavouros":
			return "arch"
		case "alpine":
			return "alpine"
		}
	}
	switch env.PM {
	case "dnf", "yum":
		return "rhel"
	case "apt":
		return "debian"
	case "zypper":
		return "suse"
	case "pacman":
		return "arch"
	case "apk":
		return "alpine"
	}
	return ""
}

// Package returns the package that provides tool on env's distribution.
func Package(env model.Env, tool string) string {
	m, ok := packages[tool]
	if !ok {
		return tool
	}
	if p := m[Family(env)]; p != "" {
		return p
	}
	if p := m["*"]; p != "" {
		return p
	}
	return ""
}

// InstallCommand returns the shell command that installs the packages, or ""
// when the package manager is unknown.
func InstallCommand(env model.Env, pkgs ...string) string {
	if len(pkgs) == 0 {
		return ""
	}
	var cmd string
	switch env.PM {
	case "dnf":
		cmd = "dnf install -y "
	case "yum":
		cmd = "yum install -y "
	case "apt":
		cmd = "apt-get install -y "
	case "zypper":
		cmd = "zypper install -y "
	case "apk":
		cmd = "apk add "
	case "pacman":
		cmd = "pacman -S --noconfirm "
	default:
		switch Family(env) {
		case "rhel":
			cmd = "dnf install -y "
		case "debian":
			cmd = "apt-get install -y "
		default:
			return ""
		}
	}
	cmd += strings.Join(pkgs, " ")
	if !env.Root {
		cmd = "sudo " + cmd
	}
	return cmd
}

// needsEPEL lists packages that RHEL-family systems only get from EPEL.
var needsEPEL = map[string]bool{"memtester": true, "edac-utils": true}

// Install returns the coverage Fix text for a missing tool.
func Install(env model.Env, tool string) model.Text {
	if env.OS == "windows" {
		switch tool {
		case "smartctl":
			return model.T("Install smartmontools for Windows (https://www.smartmontools.org/wiki/Download) and run Diagward again.",
				"Cài smartmontools cho Windows (https://www.smartmontools.org/wiki/Download) rồi chạy lại Diagward.")
		}
		if t, ok := vendorTools[tool]; ok {
			return t
		}
		return model.Tf("Install %s and run Diagward again.", "Cài %s rồi chạy lại Diagward.", tool)
	}
	if t, ok := vendorTools[tool]; ok {
		return t
	}
	pkg := Package(env, tool)
	if pkg == "" {
		return model.Tf("Install %s and run Diagward again.", "Cài %s rồi chạy lại Diagward.", tool)
	}
	cmd := InstallCommand(env, pkg)
	if cmd == "" {
		return model.Tf("Install the %s package and run Diagward again.", "Cài gói %s rồi chạy lại Diagward.", pkg)
	}
	if needsEPEL[pkg] && Family(env) == "rhel" {
		epel := InstallCommand(env, "epel-release")
		return model.Tf("Enable EPEL and install it: %s && %s", "Bật kho EPEL rồi cài: %s && %s", epel, cmd)
	}
	return model.Tf("Install it: %s", "Cài đặt: %s", cmd)
}

// NeedRoot is the coverage reason for checks that need root/Administrator.
func NeedRoot(env model.Env) model.Text {
	if env.OS == "windows" {
		return model.T("Needs Administrator rights.", "Cần quyền Administrator.")
	}
	return model.T("Needs root.", "Cần quyền root.")
}

// RunAsRoot is the matching Fix text.
func RunAsRoot(env model.Env) model.Text {
	if env.OS == "windows" {
		return model.T("Run Diagward from a terminal opened with \"Run as administrator\".",
			"Chạy Diagward trong cửa sổ dòng lệnh mở bằng \"Run as administrator\".")
	}
	return model.T("Run it as root: sudo diagward", "Chạy với quyền root: sudo diagward")
}

// Virtual is the coverage reason for hardware checks on a virtual machine or
// container.
func Virtual(env model.Env) model.Text {
	kind := env.Virtual
	if kind == "" {
		kind = "vm"
	}
	if env.Container {
		return model.Tf("This is a container (%s): the hardware belongs to the host. Check the host machine.",
			"Đây là container (%s): phần cứng thuộc về máy chủ vật lý chứa nó. Hãy kiểm tra máy host.", kind)
	}
	return model.Tf("This is a virtual machine (%s): the hardware belongs to the host. Check the host or ask the provider.",
		"Đây là máy ảo (%s): phần cứng thuộc về máy chủ vật lý. Hãy kiểm tra máy host hoặc hỏi nhà cung cấp.", kind)
}

// Missing returns the coverage reason for a missing tool.
func Missing(tool string) model.Text {
	return model.Tf("%s is not installed.", "Chưa cài %s.", tool)
}
