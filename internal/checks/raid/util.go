package raid

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// splitKV splits "Key : Value" / "Key: Value" at the first colon.
func splitKV(line string) (key, val string, ok bool) {
	k, v, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

// atoi parses the leading integer of s ("12", " 3 ", "7 errors"); -1 when
// there is none.
func atoi(s string) int64 {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return -1
	}
	n, err := strconv.ParseInt(s[:end], 10, 64)
	if err != nil {
		return -1
	}
	return n
}

var pctRe = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*%`)

// pct extracts the first percentage in s, or -1.
func pct(s string) float64 {
	m := pctRe.FindStringSubmatch(s)
	if m == nil {
		return -1
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return -1
	}
	return f
}

func fmtPct(p float64) string {
	if p < 0 {
		return ""
	}
	return strings.TrimSuffix(strconv.FormatFloat(p, 'f', 1, 64), ".0") + "%"
}

// collapse trims s and folds runs of blanks into one space.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// lines returns the non-empty lines of s (CR stripped).
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func indentOf(l string) int {
	n := 0
	for _, c := range l {
		switch c {
		case ' ':
			n++
		case '\t':
			n += 8
		default:
			return n
		}
	}
	return n
}

func uniq(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func joinOr(ss []string, empty string) string {
	if len(ss) == 0 {
		return empty
	}
	return strings.Join(ss, ", ")
}

// errText summarises a section's stderr for coverage reasons.
func errText(s *collect.Section) string {
	if s == nil {
		return ""
	}
	e := strings.TrimSpace(s.Err)
	if e == "" {
		e = strings.TrimSpace(s.Out)
	}
	if r := []rune(e); len(r) > 200 {
		e = string(r[:200]) + "…"
	}
	if e == "" {
		e = "exit code " + strconv.Itoa(s.RC)
	}
	return e
}

func ev(ls []string) []string { return units.Evidence(ls, 10) }

// ---- disk identities from /dev/disk/by-id ----

// diskID is what udev's by-id name tells about a disk.
type diskID struct {
	ID     string // by-id name
	Model  string
	Serial string
}

// byID maps kernel disk names (sda, nvme0n1) to their identity.
type byID map[string]diskID

// parseByID reads "name ../../sdb" lines (raid.byid).
func parseByID(s *collect.Section) byID {
	m := byID{}
	if s == nil {
		return m
	}
	rank := map[string]int{}
	for _, l := range s.Lines() {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		name, target := f[0], f[1]
		if strings.Contains(name, "-part") {
			continue
		}
		dev := target[strings.LastIndexByte(target, '/')+1:]
		id, r := idFromName(name)
		if r == 0 || dev == "" {
			continue
		}
		if r > rank[dev] {
			rank[dev] = r
			m[dev] = id
		}
	}
	return m
}

// idFromName decodes a by-id name. The rank says how useful it is (0 = no
// model/serial in it, e.g. wwn-0x5000... or nvme-eui...).
func idFromName(name string) (diskID, int) {
	bus, rest, ok := strings.Cut(name, "-")
	if !ok || rest == "" {
		return diskID{}, 0
	}
	r := 0
	switch bus {
	case "ata", "nvme":
		r = 3
		if strings.HasPrefix(rest, "eui.") || strings.HasPrefix(rest, "nvme.") {
			return diskID{}, 0
		}
	case "scsi":
		// scsi-0/1/S<vendor_model_serial> carry text; scsi-2/3 are NAA hex.
		if len(rest) < 2 || (rest[0] != '0' && rest[0] != '1' && rest[0] != 'S') {
			return diskID{}, 0
		}
		rest = rest[1:]
		rest = strings.TrimPrefix(rest, "ATA_")
		r = 2
	case "usb":
		r = 1
	default:
		return diskID{}, 0
	}
	i := strings.LastIndexByte(rest, '_')
	if i <= 0 || i == len(rest)-1 {
		return diskID{ID: name, Model: strings.ReplaceAll(rest, "_", " ")}, 1
	}
	return diskID{ID: name, Model: strings.ReplaceAll(rest[:i], "_", " "), Serial: rest[i+1:]}, r
}

var partRe = regexp.MustCompile(`^((?:nvme\d+n\d+|mmcblk\d+|loop\d+|nbd\d+|md\d+))p\d+$`)
var trailDigits = regexp.MustCompile(`^((?:sd|vd|hd|xvd)[a-z]+)\d+$`)

// diskOf returns the whole-disk kernel name for a partition name
// (sdb1 -> sdb, nvme0n1p2 -> nvme0n1). Paths are accepted.
func diskOf(dev string) string {
	dev = strings.TrimPrefix(dev, "/dev/")
	if m := partRe.FindStringSubmatch(dev); m != nil {
		return m[1]
	}
	if m := trailDigits.FindStringSubmatch(dev); m != nil {
		return m[1]
	}
	return dev
}

// diskPart builds the replace-this Part for a Linux block device (or a
// by-id path) using the by-id identities.
func (ids byID) diskPart(dev, location string) *model.Part {
	p := &model.Part{Kind: "disk", Location: location}
	base := dev[strings.LastIndexByte(dev, '/')+1:]
	if strings.Contains(dev, "/by-id/") || strings.HasPrefix(base, "ata-") || strings.HasPrefix(base, "nvme-") || strings.HasPrefix(base, "scsi-") {
		name := base
		if i := strings.Index(name, "-part"); i > 0 {
			name = name[:i]
		}
		if id, r := idFromName(name); r > 0 {
			p.Model, p.Serial = id.Model, id.Serial
		}
		return p
	}
	if id, ok := ids[diskOf(base)]; ok {
		p.Model, p.Serial = id.Model, id.Serial
	}
	return p
}

// partText renders a Part for actions: "model X, serial Y".
func partText(p *model.Part) (en, vi string) {
	if p == nil {
		return "", ""
	}
	var e, v []string
	if p.Model != "" {
		e = append(e, "model "+p.Model)
		v = append(v, "model "+p.Model)
	}
	if p.Serial != "" {
		e = append(e, "serial "+p.Serial)
		v = append(v, "serial "+p.Serial)
	}
	if p.Location != "" {
		e = append(e, p.Location)
		v = append(v, p.Location)
	}
	if len(e) == 0 {
		return "", ""
	}
	return " (" + strings.Join(e, ", ") + ")", " (" + strings.Join(v, ", ") + ")"
}

// installPkg is hint.Install for a package hint does not know.
func installPkg(env model.Env, pkg string) model.Text {
	if cmd := hint.InstallCommand(env, pkg); cmd != "" {
		return model.Tf("Install it: %s", "Cài đặt: %s", cmd)
	}
	return model.Tf("Install the %s package and run Diagward again.", "Cài gói %s rồi chạy lại Diagward.", pkg)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
