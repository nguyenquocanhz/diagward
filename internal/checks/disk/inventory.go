package disk

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// blockDev is one whole disk from lsblk (or /sys/block).
type blockDev struct {
	Name, Path, Type    string
	Bytes               uint64
	Rota                *bool
	Tran, Model, Serial string
	Vendor, Rev, State  string
	HCTL, WWN           string
	Mounts              []string // mountpoints of the disk and its partitions
	matched             bool
}

// flexStr decodes a JSON string, number, boolean or null into a string.
// util-linux < 2.33 writes every lsblk value as a string; newer versions use
// numbers and booleans (v2.33 release notes).
type flexStr string

func (f *flexStr) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	switch {
	case s == "null":
		*f = ""
	case strings.HasPrefix(s, `"`):
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*f = flexStr(v)
	default:
		*f = flexStr(s)
	}
	return nil
}

type lsblkNode struct {
	Name       flexStr     `json:"name"`
	KName      flexStr     `json:"kname"`
	Path       flexStr     `json:"path"`
	Type       flexStr     `json:"type"`
	Size       flexStr     `json:"size"`
	Rota       flexStr     `json:"rota"`
	Tran       flexStr     `json:"tran"`
	Model      flexStr     `json:"model"`
	Serial     flexStr     `json:"serial"`
	Vendor     flexStr     `json:"vendor"`
	Rev        flexStr     `json:"rev"`
	State      flexStr     `json:"state"`
	HCTL       flexStr     `json:"hctl"`
	WWN        flexStr     `json:"wwn"`
	Mountpoint flexStr     `json:"mountpoint"`
	PKName     flexStr     `json:"pkname"`
	Children   []lsblkNode `json:"children"`
}

// parseLsblk reads `lsblk -J -b` or `lsblk -P -b` output and returns the
// whole disks (TYPE "disk"), with the mountpoints of their children.
func parseLsblk(out string) ([]*blockDev, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, errors.New("empty output")
	}
	if strings.HasPrefix(out, "{") {
		var top struct {
			Blockdevices []lsblkNode `json:"blockdevices"`
		}
		if err := json.Unmarshal([]byte(out), &top); err != nil {
			return nil, err
		}
		var disks []*blockDev
		for _, n := range top.Blockdevices {
			if strings.TrimSpace(string(n.Type)) != "disk" {
				continue
			}
			bd := nodeToDev(n)
			collectMounts(n, &bd.Mounts)
			disks = append(disks, bd)
		}
		return disks, nil
	}
	return parseLsblkPairs(out)
}

func nodeToDev(n lsblkNode) *blockDev {
	bd := &blockDev{
		Name: strings.TrimSpace(string(n.Name)), Path: strings.TrimSpace(string(n.Path)),
		Type: strings.TrimSpace(string(n.Type)), Tran: clean(string(n.Tran)),
		Model: clean(string(n.Model)), Serial: clean(string(n.Serial)), Vendor: clean(string(n.Vendor)),
		Rev: clean(string(n.Rev)), State: clean(string(n.State)), HCTL: clean(string(n.HCTL)),
		WWN: clean(string(n.WWN)),
	}
	if k := strings.TrimSpace(string(n.KName)); k != "" && bd.Name == "" {
		bd.Name = k
	}
	if bd.Path == "" && bd.Name != "" {
		bd.Path = "/dev/" + bd.Name
	}
	bd.Bytes, _ = strconv.ParseUint(strings.TrimSpace(string(n.Size)), 10, 64)
	bd.Rota = parseRota(string(n.Rota))
	return bd
}

func collectMounts(n lsblkNode, out *[]string) {
	if m := strings.TrimSpace(string(n.Mountpoint)); m != "" && len(*out) < 8 {
		*out = append(*out, m)
	}
	for _, c := range n.Children {
		collectMounts(c, out)
	}
}

func parseRota(s string) *bool {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "1", "true":
		return boolp(true)
	case "0", "false":
		return boolp(false)
	}
	return nil
}

var rePair = regexp.MustCompile(`([A-Z][A-Z:\-]*)="((?:[^"\\]|\\.)*)"`)

// parseLsblkPairs reads `lsblk -P` output: one device per line,
// KEY="value" pairs, with unsafe characters hex-escaped (\x20).
func parseLsblkPairs(out string) ([]*blockDev, error) {
	var disks []*blockDev
	byName := map[string]*blockDev{}
	var parts []map[string]string
	for _, line := range strings.Split(out, "\n") {
		ms := rePair.FindAllStringSubmatch(line, -1)
		if len(ms) == 0 {
			continue
		}
		kv := map[string]string{}
		for _, m := range ms {
			kv[m[1]] = unescapeLsblk(m[2])
		}
		if kv["TYPE"] != "disk" {
			parts = append(parts, kv)
			continue
		}
		n := lsblkNode{
			Name: flexStr(kv["NAME"]), KName: flexStr(kv["KNAME"]), Path: flexStr(kv["PATH"]),
			Type: flexStr(kv["TYPE"]), Size: flexStr(kv["SIZE"]), Rota: flexStr(kv["ROTA"]),
			Tran: flexStr(kv["TRAN"]), Model: flexStr(kv["MODEL"]), Serial: flexStr(kv["SERIAL"]),
			Vendor: flexStr(kv["VENDOR"]), Rev: flexStr(kv["REV"]), State: flexStr(kv["STATE"]),
			HCTL: flexStr(kv["HCTL"]), WWN: flexStr(kv["WWN"]),
		}
		bd := nodeToDev(n)
		if m := kv["MOUNTPOINT"]; m != "" {
			bd.Mounts = append(bd.Mounts, m)
		}
		disks = append(disks, bd)
		byName[bd.Name] = bd
	}
	for _, kv := range parts {
		if bd := byName[kv["PKNAME"]]; bd != nil && kv["MOUNTPOINT"] != "" && len(bd.Mounts) < 8 {
			bd.Mounts = append(bd.Mounts, kv["MOUNTPOINT"])
		}
	}
	if len(disks) == 0 && len(parts) == 0 {
		return nil, errors.New("no lsblk records")
	}
	return disks, nil
}

func unescapeLsblk(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseSysBlock reads the disk.sysblock dump ("/sys/block/sda/size=976773168").
func parseSysBlock(kv map[string]string) []*blockDev {
	byName := map[string]*blockDev{}
	var order []string
	for k, v := range kv {
		rest, ok := strings.CutPrefix(k, "/sys/block/")
		if !ok {
			continue
		}
		name, attr, ok := strings.Cut(rest, "/")
		if !ok || skipBlockName(name) {
			continue
		}
		bd := byName[name]
		if bd == nil {
			bd = &blockDev{Name: name, Path: "/dev/" + name, Type: "disk"}
			byName[name] = bd
			order = append(order, name)
		}
		switch attr {
		case "size": // 512-byte sectors, always (include/linux/blk_types.h)
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				bd.Bytes = n * 512
			}
		case "queue/rotational":
			bd.Rota = parseRota(v)
		case "device/vendor":
			bd.Vendor = clean(v)
		case "device/model":
			bd.Model = clean(v)
		case "device/rev", "device/firmware_rev":
			bd.Rev = clean(v)
		case "device/serial":
			bd.Serial = clean(v)
		case "device/state":
			bd.State = clean(v)
		}
	}
	sortStrings(order)
	out := make([]*blockDev, 0, len(order))
	for _, n := range order {
		out = append(out, byName[n])
	}
	return out
}

// skipBlockName drops block devices that are never physical disks.
func skipBlockName(n string) bool {
	for _, p := range []string{"loop", "ram", "zram", "nbd", "rbd", "drbd", "dm-", "md", "sr", "fd", "zd", "bcache"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// scanEntry is one line of `smartctl --scan-open`.
type scanEntry struct {
	Dev, Type, Comment string
	OpenFailed         bool
	Reason             string
}

// parseScan reads `smartctl --scan-open` text output:
//
//	/dev/sda -d sat # /dev/sda [SAT], ATA device
//	/dev/bus/0 -d megaraid,8 # /dev/bus/0 [megaraid_disk_08], SCSI device
//	# /dev/sdb -d scsi # /dev/sdb, SCSI device open failed: ...
//
// It also accepts the JSON form (smartctl -j --scan-open).
func parseScan(out string) []scanEntry {
	t := strings.TrimSpace(out)
	if strings.HasPrefix(t, "{") {
		var j struct {
			Devices []struct {
				Name     string `json:"name"`
				InfoName string `json:"info_name"`
				Type     string `json:"type"`
				OpenErr  string `json:"open_error"`
			} `json:"devices"`
		}
		if json.Unmarshal([]byte(t), &j) == nil {
			var es []scanEntry
			for _, d := range j.Devices {
				es = append(es, scanEntry{Dev: d.Name, Type: d.Type, Comment: d.InfoName, OpenFailed: d.OpenErr != "", Reason: d.OpenErr})
			}
			return es
		}
	}
	var es []scanEntry
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		failed := false
		if strings.HasPrefix(l, "#") {
			l = strings.TrimSpace(strings.TrimPrefix(l, "#"))
			if !strings.HasPrefix(l, "/") {
				continue
			}
			failed = true
		}
		f := strings.Fields(l)
		if len(f) == 0 || !(strings.HasPrefix(f[0], "/") || strings.Contains(f[0], ":")) {
			continue
		}
		e := scanEntry{Dev: f[0], OpenFailed: failed}
		if len(f) >= 3 && f[1] == "-d" {
			e.Type = f[2]
		}
		if _, c, ok := strings.Cut(l, "#"); ok {
			e.Comment = strings.TrimSpace(c)
			if i := strings.Index(e.Comment, "open failed:"); i >= 0 {
				e.Reason = strings.TrimSpace(e.Comment[i+len("open failed:"):])
				e.OpenFailed = true
			}
		}
		es = append(es, e)
	}
	return es
}
