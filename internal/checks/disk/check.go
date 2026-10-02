// Package disk is the "disk" domain check: block device inventory (lsblk,
// Get-PhysicalDisk), S.M.A.R.T. health (smartctl for ATA, NVMe and SCSI/SAS
// disks, including disks behind MegaRAID/Smart Array controllers), Windows
// storage reliability counters, smartd monitoring and the opt-in sequential
// speed test.
//
// Sections read (see collect/linux/30-disk.sh and collect/windows/30-disk.ps1):
// disk.lsblk, disk.sysblock, disk.smart_version, disk.smart_scan,
// disk.smart:<dev>[,<type>], disk.smartd, disk.bench, disk.win_physical,
// disk.win_reliability, disk.win_predict, disk.win_diskdrive.
package disk

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "disk"

// Facts is the typed data the disk check exposes in Result.Facts.
type Facts struct {
	Disks           []DiskFact  `json:"disks"`
	SmartctlVersion string      `json:"smartctlVersion,omitempty"`
	SmartctlJSON    bool        `json:"smartctlJson,omitempty"`
	Smartd          *SmartdFact `json:"smartd,omitempty"`
	Bench           *BenchFact  `json:"bench,omitempty"`
}

// DiskFact describes one disk.
type DiskFact struct {
	Device               string            `json:"device"`                // /dev/sda, /dev/bus/0 [megaraid,3], PhysicalDisk0
	SmartDevice          string            `json:"smartDevice,omitempty"` // smartctl device and -d type
	Protocol             string            `json:"protocol,omitempty"`    // ATA, NVMe, SCSI
	Kind                 string            `json:"kind,omitempty"`        // HDD, SSD, NVMe, Virtual, RAID volume
	Interface            string            `json:"interface,omitempty"`   // SATA, SAS, NVMe, USB...
	Vendor               string            `json:"vendor,omitempty"`
	Model                string            `json:"model,omitempty"`
	Serial               string            `json:"serial,omitempty"`
	Firmware             string            `json:"firmware,omitempty"`
	SizeBytes            uint64            `json:"sizeBytes,omitempty"`
	Location             string            `json:"location,omitempty"`
	Health               string            `json:"health,omitempty"`
	SmartPassed          *bool             `json:"smartPassed,omitempty"`
	TemperatureC         *int              `json:"temperatureC,omitempty"`
	PowerOnHours         *uint64           `json:"powerOnHours,omitempty"`
	Reallocated          *uint64           `json:"reallocated,omitempty"`
	Pending              *uint64           `json:"pending,omitempty"`
	OfflineUncorrectable *uint64           `json:"offlineUncorrectable,omitempty"`
	ReportedUncorrect    *uint64           `json:"reportedUncorrect,omitempty"`
	CRCErrors            *uint64           `json:"crcErrors,omitempty"`
	PercentUsed          *int              `json:"percentUsed,omitempty"`
	NVMeCriticalWarning  *int              `json:"nvmeCriticalWarning,omitempty"`
	NVMeMediaErrors      *uint64           `json:"nvmeMediaErrors,omitempty"`
	NVMeErrorLogEntries  *uint64           `json:"nvmeErrorLogEntries,omitempty"`
	AvailableSpare       *int              `json:"availableSpare,omitempty"`
	GrownDefects         *uint64           `json:"grownDefects,omitempty"`
	UncorrectedErrors    map[string]uint64 `json:"uncorrectedErrors,omitempty"`
	Standby              bool              `json:"standby,omitempty"`
	Virtual              bool              `json:"virtual,omitempty"`
	RAIDVolume           bool              `json:"raidVolume,omitempty"`
	BehindRAID           bool              `json:"behindRaid,omitempty"`
	SmartError           string            `json:"smartError,omitempty"`
	Status               model.Severity    `json:"status"`
}

// diskInfo is the working record for one disk, merged from lsblk, smartctl
// and (on Windows) the storage cmdlets.
type diskInfo struct {
	Dev         string // /dev path, or "PhysicalDisk<N>" on Windows
	SmartDev    string // device as passed to smartctl
	SmartType   string // smartctl -d type
	Vendor      string
	Model       string
	Serial      string
	Firmware    string
	Bytes       uint64
	Iface       string
	HCTL        string
	Location    string
	Mounts      []string
	Smart       *smartData
	SmartErr    string
	SmartTO     bool
	Virtual     bool
	RAIDVol     bool
	SAN         bool // LUN of a SAN/iSCSI array (also marked Virtual: not local hardware)
	Passthrough bool
	Block       *blockDev
	Win         *winDisk
	WinIndex    int // Windows disk number, -1 if none

	sev    model.Severity
	health string
}

// target is how findings and the table name the disk.
func (d *diskInfo) target() string {
	if d.Passthrough {
		return fmt.Sprintf("%s [%s]", d.SmartDev, d.SmartType)
	}
	if d.Dev != "" {
		return d.Dev
	}
	return d.SmartDev
}

// ident is "Seagate ST4000NM0035, serial ZC1234" for action texts.
func (d *diskInfo) ident() string {
	s := strings.TrimSpace(d.Vendor + " " + d.Model)
	if d.Vendor != "" && strings.HasPrefix(strings.ToUpper(d.Model), strings.ToUpper(d.Vendor)) {
		s = d.Model
	}
	if s == "" {
		s = d.target()
	}
	if d.Serial != "" {
		s += ", serial " + d.Serial
	}
	return s
}

func (d *diskInfo) part() *model.Part {
	return &model.Part{Kind: "disk", Vendor: d.Vendor, Model: d.Model, Serial: d.Serial,
		Firmware: d.Firmware, Size: sizeText(d.Bytes), Location: d.location()}
}

func (d *diskInfo) location() string {
	var parts []string
	switch {
	case d.Passthrough:
		parts = append(parts, fmt.Sprintf("behind RAID controller %s (smartctl -d %s)", d.SmartDev, d.SmartType))
		if n := devID(d.SmartType); n != "" {
			parts = append(parts, "controller device ID "+n)
		}
	case d.Dev != "":
		parts = append(parts, d.Dev)
	}
	if d.HCTL != "" {
		parts = append(parts, "HCTL "+d.HCTL)
	}
	if d.Location != "" {
		parts = append(parts, d.Location)
	}
	return strings.Join(parts, ", ")
}

// devID returns N from "megaraid,N" / "sat+megaraid,N" / "cciss,N".
func devID(t string) string {
	if i := strings.LastIndexByte(t, ','); i >= 0 && i+1 < len(t) {
		if _, err := strconv.Atoi(t[i+1:]); err == nil {
			return t[i+1:]
		}
	}
	return ""
}

// Check analyzes the bundle for the disk domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	if b == nil || !hasDiskSections(b) {
		return res
	}
	c := &checker{b: b, env: env, res: &res, facts: &Facts{}}
	c.run()
	res.Facts = c.facts
	return res
}

func hasDiskSections(b *collect.Bundle) bool {
	for _, s := range b.Sections {
		if s != nil && strings.HasPrefix(s.Name, "disk.") {
			return true
		}
	}
	return false
}

type checker struct {
	b     *collect.Bundle
	env   model.Env
	res   *model.Result
	facts *Facts
	disks []*diskInfo

	scanFailed []scanEntry
	smartRan   bool            // smartctl scan ran
	standby    []string        // disks smartctl left asleep (-n standby)
	ignored    map[string]bool // devices that are not disks (BMC virtual media)
}

func (c *checker) add(f model.Finding) {
	c.res.Findings = append(c.res.Findings, f)
}

func (c *checker) cover(id string, name model.Text, state string, reason, fix model.Text) {
	c.coverCmd(id, name, state, reason, fix, "")
}

// coverCmd is cover with the one command that enables the check.
func (c *checker) coverCmd(id string, name model.Text, state string, reason, fix model.Text, cmd string) {
	c.res.Coverage = append(c.res.Coverage, model.Coverage{
		ID: domain + "." + id, Component: model.CompDisk, Name: name, State: state, Reason: reason, Fix: fix, Cmd: cmd,
	})
}

func (c *checker) run() {
	if c.b.OS == collect.OSWindows {
		c.windowsInventory()
	} else {
		c.linuxInventory()
	}
	c.smart()
	for _, d := range c.disks {
		c.analyze(d)
	}
	c.summary()
	c.smartd()
	c.bench()
	c.table()
}

// ---- inventory ----

var covInventory = model.T("Disk inventory", "Danh sách ổ cứng")

func (c *checker) linuxInventory() {
	ls := c.b.Get("disk.lsblk")
	sb := c.b.Get("disk.sysblock")
	if ls == nil && sb == nil {
		return
	}
	var devs []*blockDev
	state, reason, fix := model.CovRan, model.Text{}, model.Text{}
	invCmd := ""
	switch {
	case ls == nil:
		state, reason = model.CovPartial, model.T("Only /sys/block was available.", "Chỉ đọc được /sys/block.")
	case ls.Missing != "":
		state, reason = model.CovPartial, hint.Missing("lsblk")
		fix, invCmd = hint.InstallFix(c.env, "lsblk")
	case !ls.Ran():
		state, reason = model.CovSkipped, model.Tf("lsblk was not run (%s).", "lsblk không được chạy (%s).", ls.Skipped)
	default:
		var err error
		devs, err = parseLsblk(ls.Text())
		if err != nil {
			state = model.CovFailed
			reason = model.Tf("lsblk output could not be read (%s). %s", "Không đọc được kết quả lsblk (%s). %s", err.Error(), firstLine(ls.Err))
		}
	}
	if len(devs) == 0 && sb.Ran() {
		devs = parseSysBlock(sb.KV())
		if len(devs) > 0 && state == model.CovFailed {
			state = model.CovPartial
		}
	}
	for _, bd := range devs {
		if skipBlockName(bd.Name) {
			continue
		}
		if bmcVirtualMedia(bd.Vendor, bd.Model) {
			c.ignore(bd.Path)
			continue
		}
		d := &diskInfo{Dev: bd.Path, Vendor: bd.Vendor, Model: bd.Model, Serial: bd.Serial, Firmware: bd.Rev,
			Bytes: bd.Bytes, HCTL: bd.HCTL, Mounts: bd.Mounts, Block: bd, WinIndex: -1}
		d.Iface = tranName(bd.Tran)
		d.Virtual = virtualModel(bd.Vendor, bd.Model) || strings.HasPrefix(bd.Name, "vd") || strings.HasPrefix(bd.Name, "xvd")
		if sanVolume(bd.Vendor, bd.Model, bd.Tran) {
			d.SAN, d.Virtual = true, true
		}
		if !d.Virtual && raidVolume(bd.Vendor, bd.Model) {
			d.RAIDVol = true
		}
		if v := vendorFromModel(d.Model); v != "" && (d.Vendor == "" || strings.EqualFold(d.Vendor, "ATA")) {
			d.Vendor = v
		}
		if strings.EqualFold(d.Vendor, "ATA") {
			d.Vendor = ""
		}
		c.disks = append(c.disks, d)
	}
	c.coverCmd("inventory", covInventory, state, reason, fix, invCmd)
}

func (c *checker) ignore(dev string) {
	if dev == "" {
		return
	}
	if c.ignored == nil {
		c.ignored = map[string]bool{}
	}
	c.ignored[dev] = true
}

func tranName(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "":
		return ""
	case "sata", "ata":
		return "SATA"
	case "sas":
		return "SAS"
	case "nvme":
		return "NVMe"
	case "usb":
		return "USB"
	case "fc":
		return "Fibre Channel"
	case "iscsi":
		return "iSCSI"
	case "spi":
		return "SCSI"
	}
	return strings.TrimSpace(t)
}

// ---- S.M.A.R.T. ----

var covSmart = model.T("S.M.A.R.T. health", "Tình trạng S.M.A.R.T.")

func (c *checker) smart() {
	if v := c.b.Get("disk.smart_version"); v.OK() {
		if m := reVersion.FindStringSubmatch(strings.TrimSpace(v.Text())); m != nil {
			c.facts.SmartctlVersion = m[1]
			if n, err := strconv.Atoi(strings.SplitN(m[1], ".", 2)[0]); err == nil {
				c.facts.SmartctlJSON = n >= 7
			}
		}
	}
	for _, s := range c.b.Prefix("disk.smart:") {
		c.smartSection(s)
	}
	// After the sections: they may reveal devices to ignore (BMC media).
	if scan := c.b.Get("disk.smart_scan"); scan.Ran() {
		c.smartRan = true
		for _, e := range parseScan(scan.Text()) {
			if e.OpenFailed && !c.ignored[e.Dev] {
				c.scanFailed = append(c.scanFailed, e)
			}
		}
	}
}

func (c *checker) smartSection(s *collect.Section) {
	dev, typ := splitSmartInstance(strings.TrimPrefix(s.Name, "disk.smart:"))
	if !s.Ran() || c.ignored[dev] {
		return
	}
	var sd *smartData
	perr := ""
	out := strings.TrimSpace(s.Text())
	if strings.HasPrefix(out, "{") {
		var err error
		if sd, err = decodeSmartJSON(out); err != nil {
			perr, sd = "unreadable smartctl JSON: "+err.Error(), nil
		}
	} else if out != "" {
		if d, ok := parseSmartText(out); ok {
			sd = d
		}
	}
	if sd != nil && sd.Exit < 0 && s.RC >= 0 && s.RC < 124 {
		sd.Exit = s.RC
	}
	if sd != nil && typ == "" && bmcVirtualMedia(firstNonEmpty(sd.Vendor, vendorFromModel(sd.Model)), firstNonEmpty(sd.Product, sd.Model)) {
		c.ignore(dev)
		return
	}
	d := c.findOrAdd(dev, typ, sd)
	d.SmartDev, d.SmartType = dev, typ
	if typ == "" && sd != nil {
		d.SmartType = sd.DevType
	}
	d.Passthrough = passthroughType(typ)
	switch {
	case s.Timeout || s.RC == 124 || s.RC == 137:
		d.SmartTO = true
		d.SmartErr = fmt.Sprintf("smartctl did not answer within %d s", c.b.Options.WithDefaults().Timeout)
	case sd == nil && perr != "":
		d.SmartErr = perr
	case sd == nil:
		d.SmartErr = firstLine(firstNonEmpty(s.Err, out, fmt.Sprintf("smartctl exit status %d", s.RC)))
	case !hasHealth(sd) && sd.Standby == "":
		d.SmartErr = firstLine(firstNonEmpty(strings.Join(sd.ErrorMessages, "; "), s.Err, smartUnavailableText(sd)))
	}
	if sd == nil {
		return
	}
	d.Smart = sd
	c.mergeSmart(d, sd)
}

// winNVMeMatch ties smartctl's /dev/nvmeN on Windows to a Get-PhysicalDisk
// entry. The /dev/nvmeN number is not the disk number, and Windows often
// shows the namespace EUI-64 as the serial
// ("0000_0000_0000_0000_0026_B738_4082_5615.") while smartctl prints the
// real one, so match on the EUI-64 first, then on a model that only one
// free disk has.
func (c *checker) winNVMeMatch(dev string, sd *smartData, free func(*diskInfo) bool) *diskInfo {
	if c.b.OS != collect.OSWindows || sd == nil || (sd.Protocol != "NVMe" && !strings.HasPrefix(dev, "/dev/nvme")) {
		return nil
	}
	if sd.EUI64 != "" && strings.Trim(sd.EUI64, "0") != "" {
		for _, d := range c.disks {
			if free(d) && d.Win != nil && strings.HasSuffix(normSerial(d.Serial), sd.EUI64) {
				return d
			}
		}
	}
	var hit *diskInfo
	n := 0
	for _, d := range c.disks {
		if free(d) && d.Win != nil && sd.Model != "" && strings.EqualFold(strings.TrimSpace(d.Model), sd.Model) {
			hit = d
			n++
		}
	}
	if n == 1 {
		return hit
	}
	return nil
}

// splitSmartInstance splits a disk.smart:<instance> name into the smartctl
// device and -d type: "/dev/bus/0,megaraid,3" -> "/dev/bus/0", "megaraid,3".
// The type starts with a letter; a comma followed by a digit belongs to the
// device name (smartctl on Windows: "/dev/csmi0,1" = CSMI port 1).
func splitSmartInstance(inst string) (dev, typ string) {
	for i := 1; i+1 < len(inst); i++ {
		if inst[i] == ',' {
			if c := inst[i+1]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return inst[:i], inst[i+1:]
			}
		}
	}
	return inst, ""
}

func smartUnavailableText(s *smartData) string {
	if s.SmartAvailable != nil && !*s.SmartAvailable {
		return "device lacks SMART capability"
	}
	return "no S.M.A.R.T. data returned"
}

// findOrAdd returns the inventory record for a smartctl device, matching
// by path (NVMe namespaces map to their controller), by Windows disk number
// or by serial number, or adds a new record. Passthrough devices never
// match an OS disk: the OS only sees the RAID volume.
func (c *checker) findOrAdd(dev, typ string, sd *smartData) *diskInfo {
	free := func(d *diskInfo) bool { return d.Smart == nil && d.SmartErr == "" && d.SmartDev == "" }
	if !passthroughType(typ) {
		for _, d := range c.disks {
			if !free(d) {
				continue
			}
			if d.Block != nil && d.Dev != "" && (d.Dev == dev || nvmeController(d.Dev) == dev) {
				return d
			}
			if c.b.OS == collect.OSWindows && d.WinIndex >= 0 && winSmartIndex(dev) == d.WinIndex {
				return d
			}
		}
		if sd != nil && normSerial(sd.Serial) != "" {
			for _, d := range c.disks {
				if free(d) && normSerial(d.Serial) == normSerial(sd.Serial) {
					return d
				}
			}
		}
		if d := c.winNVMeMatch(dev, sd, free); d != nil {
			return d
		}
	}
	d := &diskInfo{Dev: dev, WinIndex: -1}
	if passthroughType(typ) || strings.HasPrefix(dev, "/dev/bus/") {
		d.Dev = ""
	}
	c.disks = append(c.disks, d)
	return d
}

// mergeSmart fills identity fields from smartctl (more precise than lsblk).
func (c *checker) mergeSmart(d *diskInfo, s *smartData) {
	if s.Model != "" {
		d.Model = s.Model
	}
	if s.Serial != "" {
		d.Serial = s.Serial
	}
	if s.Firmware != "" {
		d.Firmware = s.Firmware
	}
	if s.Bytes > 0 {
		d.Bytes = s.Bytes
	}
	switch {
	case s.Vendor != "" && !strings.EqualFold(s.Vendor, "ATA"):
		d.Vendor = s.Vendor
		// SCSI model_name is "VENDOR PRODUCT"; keep the product as the model.
		if p := strings.TrimSpace(s.Product); p != "" {
			d.Model = p
		}
	case vendorFromModel(d.Model) != "":
		d.Vendor = vendorFromModel(d.Model)
	case s.PCIVendor != 0 && pciVendors[s.PCIVendor] != "":
		d.Vendor = pciVendors[s.PCIVendor]
	}
	if v := vendorFromModel(d.Model); v != "" && (d.Vendor == "" || strings.EqualFold(d.Vendor, "ATA")) {
		d.Vendor = v
	}
	if strings.EqualFold(d.Vendor, "ATA") {
		d.Vendor = ""
	}
	switch s.Protocol {
	case "NVMe":
		d.Iface = "NVMe"
	case "SCSI":
		if t := strings.ToUpper(s.Transport); strings.HasPrefix(t, "SAS") {
			d.Iface = "SAS"
		} else if d.Iface == "" && s.Transport != "" {
			d.Iface = s.Transport
		}
	case "ATA":
		if d.Iface == "" || d.Iface == "SAS" {
			d.Iface = "SATA"
		}
		if strings.Contains(strings.ToLower(s.DevType), "usb") || strings.Contains(strings.ToLower(s.InfoName), "usb") {
			d.Iface = "USB"
		}
	}
	if virtualModel(s.Vendor, s.Model) {
		d.Virtual = true
	}
	if s.Protocol == "SCSI" && sanVolume(s.Vendor, firstNonEmpty(s.Product, s.Model), "") {
		d.SAN, d.Virtual = true, true
	}
	// SCSI logical drives (PERC, MegaRAID, Smart Array) and ATA ones (Dell
	// BOSS "DELLBOSS VD") answer without any S.M.A.R.T. data.
	if (s.Protocol == "SCSI" || s.Protocol == "ATA" || s.Protocol == "") && !hasHealth(s) && raidVolume(s.Vendor, firstNonEmpty(s.Product, s.Model)) {
		d.RAIDVol = true
	}
}

// hasHealth reports whether smartctl returned any health data at all.
func hasHealth(s *smartData) bool {
	return s.Passed != nil || len(s.Attrs) > 0 || s.NVMe != nil || s.GrownDefects != nil || s.Uncorrected != nil
}

// kind classifies the disk for thresholds and the table.
func (d *diskInfo) kind() string {
	switch {
	case d.SAN:
		return "SAN LUN"
	case d.Virtual:
		return "Virtual"
	case d.RAIDVol:
		return "RAID volume"
	}
	s := d.Smart
	if (s != nil && s.Protocol == "NVMe") || d.Iface == "NVMe" || strings.HasPrefix(d.Dev, "/dev/nvme") {
		return "NVMe"
	}
	if s != nil {
		switch {
		case s.RPM > 0:
			return "HDD"
		case s.RPM == 0:
			return "SSD"
		}
		if s.Endurance != nil || len(wearCandidates(s)) > 0 {
			return "SSD"
		}
	}
	if d.Block != nil && d.Block.Rota != nil {
		if *d.Block.Rota {
			return "HDD"
		}
		return "SSD"
	}
	if d.Win != nil {
		switch d.Win.mediaType() {
		case "HDD":
			return "HDD"
		case "SSD", "SCM":
			return "SSD"
		}
	}
	return ""
}

// ---- coverage and the OK summary ----

func (c *checker) summary() {
	var physical, healthy, standby, unreadable, virtual, san, raidVols, passthrough int
	var unreadableNames, raidNames, healthyNames []string
	winOnly := 0
	for _, d := range c.disks {
		switch {
		case d.SAN:
			san++
			continue
		case d.Virtual:
			virtual++
			continue
		case d.RAIDVol:
			raidVols++
			raidNames = append(raidNames, strings.TrimSpace(d.target()+" ("+strings.TrimSpace(d.Vendor+" "+d.Model)+")"))
			continue
		}
		physical++
		if d.Passthrough {
			passthrough++
		}
		checked := (d.Smart != nil && hasHealth(d.Smart)) || (d.Win != nil && d.Win.HealthStatus != "")
		switch {
		case d.Smart != nil && d.Smart.Standby != "":
			standby++
			c.standby = append(c.standby, d.target())
		case checked:
			if d.sev <= model.Info {
				healthy++
				healthyNames = append(healthyNames, d.target())
				if (d.Smart == nil || !hasHealth(d.Smart)) && d.Win != nil && d.Win.Rel == nil && d.Win.Predict == nil {
					winOnly++
				}
			}
		case c.smartRan || d.Smart != nil || d.SmartErr != "":
			unreadable++
			unreadableNames = append(unreadableNames, d.target())
		}
	}

	if c.b.OS == collect.OSWindows {
		c.windowsCoverage(raidNames)
	} else {
		c.linuxSmartCoverage(physical, unreadable, virtual, san, raidVols, passthrough, unreadableNames, raidNames)
	}

	if healthy > 0 {
		names := strings.Join(healthyNames, ", ")
		if len(healthyNames) > 8 {
			names = strings.Join(healthyNames[:8], ", ") + ", …"
		}
		f := model.Finding{
			ID: "disk.smart_healthy", Component: model.CompDisk, Severity: model.OK,
			Title:  model.Tf("%d disk(s) passed the health check", "%d ổ cứng đạt kiểm tra sức khỏe", healthy),
			Detail: model.Tf("No S.M.A.R.T. warning signs on: %s.", "Không thấy dấu hiệu lỗi S.M.A.R.T. trên: %s.", names),
		}
		if winOnly == healthy {
			f.Detail = model.Tf("Windows reports these disks as Healthy: %s. Detailed S.M.A.R.T. counters were not available (they need Administrator rights or smartmontools).",
				"Windows báo các ổ này ở trạng thái Healthy: %s. Chưa đọc được chi tiết S.M.A.R.T. (cần quyền Administrator hoặc smartmontools).", names)
		}
		if standby > 0 {
			f.Detail.EN += fmt.Sprintf(" %d disk(s) were asleep (standby) and were not woken up, so they were not checked.", standby)
			f.Detail.VI += fmt.Sprintf(" %d ổ đang ngủ (standby) nên không bị đánh thức để kiểm tra.", standby)
		}
		c.add(f)
	}
}

func (c *checker) linuxSmartCoverage(physical, unreadable, virtual, san, raidVols, passthrough int, unreadableNames, raidNames []string) {
	scan := c.b.Get("disk.smart_scan")
	smartSecs := c.b.Prefix("disk.smart:")
	if scan == nil && len(smartSecs) == 0 {
		return
	}
	if scan != nil && !scan.Ran() {
		switch {
		case scan.Skipped == "container" || c.env.Container:
			c.cover("smart", covSmart, model.CovSkipped, hint.Virtual(c.env), model.Text{})
		case scan.Skipped == "not-root":
			c.cover("smart", covSmart, model.CovSkipped, hint.NeedRoot(c.env), hint.RunAsRoot(c.env))
		case scan.Missing != "" && !c.env.Bare():
			c.cover("smart", covSmart, model.CovSkipped, hint.Virtual(c.env), model.Text{})
		case scan.Missing != "":
			fix, cmd := hint.InstallFix(c.env, "smartctl")
			c.coverCmd("smart", covSmart, model.CovSkipped, hint.Missing("smartctl"), fix, cmd)
		default:
			c.cover("smart", covSmart, model.CovSkipped, model.Tf("Skipped (%s).", "Bỏ qua (%s).", scan.Skipped), model.Text{})
		}
		return
	}
	if scan != nil && !scan.OK() && len(smartSecs) == 0 {
		c.cover("smart", covSmart, model.CovFailed,
			model.Tf("smartctl --scan-open failed (exit %d): %s", "smartctl --scan-open bị lỗi (mã %d): %s", scan.RC, firstLine(firstNonEmpty(scan.Err, scan.Text()))),
			model.Text{})
		return
	}
	if physical == 0 {
		switch {
		case raidVols > 0:
			c.cover("smart", covSmart, model.CovPartial, raidHiddenText(raidNames), raidHiddenFix(raidNames))
		case san > 0 && virtual == 0 && c.env.Bare():
			c.cover("smart", covSmart, model.CovSkipped,
				model.T("Only SAN/iSCSI volumes are attached: their disks are inside the storage array, not in this server.", "Chỉ có ổ SAN/iSCSI: các ổ vật lý nằm trong thiết bị lưu trữ, không nằm trong máy chủ này."),
				model.T("Check disk health with the storage array's own management tool.", "Kiểm tra sức khỏe ổ bằng công cụ quản lý của thiết bị lưu trữ."))
		case virtual > 0 || !c.env.Bare():
			c.cover("smart", covSmart, model.CovSkipped, hint.Virtual(c.env), model.Text{})
		default:
			c.cover("smart", covSmart, model.CovPartial,
				model.T("smartctl found no disks it could read.", "smartctl không tìm thấy ổ nào đọc được."),
				model.T("Check that the disks are visible to the OS (lsblk) and run smartctl --scan-open by hand.",
					"Kiểm tra hệ điều hành có thấy ổ không (lsblk) và chạy thử smartctl --scan-open."))
		}
		return
	}
	var reasons []model.Text
	if unreadable > 0 {
		reasons = append(reasons, model.Tf("S.M.A.R.T. data could not be read from: %s.", "Không đọc được S.M.A.R.T. của: %s.", strings.Join(unreadableNames, ", ")))
	}
	if raidVols > 0 && passthrough == 0 {
		reasons = append(reasons, raidHiddenText(raidNames))
	}
	if len(c.scanFailed) > 0 {
		var n []string
		for _, e := range c.scanFailed {
			n = append(n, e.Dev)
		}
		reasons = append(reasons, model.Tf("smartctl could not open: %s.", "smartctl không mở được: %s.", strings.Join(n, ", ")))
	}
	if len(c.standby) > 0 {
		reasons = append(reasons, standbyText(c.standby))
	}
	if len(reasons) == 0 {
		c.cover("smart", covSmart, model.CovRan, model.Text{}, model.Text{})
		return
	}
	fix := model.Text{}
	if raidVols > 0 && passthrough == 0 {
		fix = raidHiddenFix(raidNames)
	}
	c.cover("smart", covSmart, model.CovPartial, joinTexts(reasons), fix)
}

func joinTexts(ts []model.Text) model.Text {
	var r model.Text
	for _, t := range ts {
		r.EN = strings.TrimSpace(r.EN + " " + t.EN)
		r.VI = strings.TrimSpace(r.VI + " " + t.VI)
	}
	return r
}

func raidHiddenText(names []string) model.Text {
	return model.Tf("The physical disks behind the hardware RAID controller are not visible to smartctl (the OS only sees the logical volume %s), so their S.M.A.R.T. data was not checked.",
		"Các ổ vật lý nằm sau card RAID cứng không hiện ra với smartctl (hệ điều hành chỉ thấy ổ logic %s), nên chưa kiểm tra được S.M.A.R.T. của từng ổ.",
		strings.Join(names, ", "))
}

func raidHiddenFix(names []string) model.Text {
	all := strings.ToLower(strings.Join(names, " "))
	switch {
	case strings.Contains(all, "dellboss") || strings.Contains(all, "boss vd") || strings.Contains(all, "boss-"):
		return model.T("Dell BOSS: the M.2 drives of the boot mirror are only visible to the BOSS controller. Check them in iDRAC (Storage > Physical Disks) or with Dell's BOSS CLI (mvcli info -o pd on BOSS-S1).",
			"Dell BOSS: các ổ M.2 của cặp mirror khởi động chỉ hiện với card BOSS. Kiểm tra trong iDRAC (Storage > Physical Disks) hoặc bằng BOSS CLI của Dell (mvcli info -o pd với BOSS-S1).")
	case strings.Contains(all, "logical volume") || strings.Contains(all, "smart array"):
		return model.T("HPE Smart Array: read each disk with smartctl -a -d cciss,N /dev/sdX (N = 0, 1, 2...), or check the controller with ssacli (see the RAID section).",
			"HPE Smart Array: đọc từng ổ bằng smartctl -a -d cciss,N /dev/sdX (N = 0, 1, 2...), hoặc kiểm tra card bằng ssacli (xem phần RAID).")
	case strings.Contains(all, "adaptec") || strings.Contains(all, "asr"):
		return model.T("Adaptec/Microchip: read each disk with smartctl -a -d aacraid,H,L,ID /dev/sdX, or check the controller with arcconf (see the RAID section).",
			"Adaptec/Microchip: đọc từng ổ bằng smartctl -a -d aacraid,H,L,ID /dev/sdX, hoặc kiểm tra card bằng arcconf (xem phần RAID).")
	}
	return model.T("MegaRAID/PERC: read each disk with smartctl -a -d megaraid,N /dev/sdX (N = device ID from storcli /c0 /eall /sall show), or check the controller with storcli/perccli (see the RAID section).",
		"MegaRAID/PERC: đọc từng ổ bằng smartctl -a -d megaraid,N /dev/sdX (N là Device ID lấy từ storcli /c0 /eall /sall show), hoặc kiểm tra card bằng storcli/perccli (xem phần RAID).")
}

// ---- table and facts ----

func (c *checker) table() {
	if len(c.disks) == 0 {
		return
	}
	sort.SliceStable(c.disks, func(i, j int) bool { return lessDev(c.disks[i].target(), c.disks[j].target()) })
	t := model.Table{
		ID:    "disk.disks",
		Title: model.T("Disks", "Ổ cứng"),
		Columns: []model.Text{
			model.T("Device", "Thiết bị"), model.T("Model", "Model"), model.T("Serial", "Serial"),
			model.T("Size", "Dung lượng"), model.T("Type", "Loại"), model.T("Interface", "Giao tiếp"),
			model.T("Health", "Sức khỏe"), model.T("Temp", "Nhiệt độ"), model.T("Power-on", "Thời gian chạy"),
			model.T("Key counters", "Chỉ số chính"), model.T("Status", "Trạng thái"),
		},
	}
	anyStandby := false
	for _, d := range c.disks {
		row, fact := c.row(d)
		if fact.Standby {
			anyStandby = true
		}
		t.Rows = append(t.Rows, row)
		c.facts.Disks = append(c.facts.Disks, fact)
	}
	if anyStandby {
		t.Note = model.T("Disks in standby were not woken up (smartctl -n standby); run Diagward again while they are active to check them.",
			"Ổ đang standby không bị đánh thức (smartctl -n standby); chạy lại Diagward khi ổ đang hoạt động để kiểm tra.")
	}
	c.res.Tables = append(c.res.Tables, t)
}

func (c *checker) row(d *diskInfo) (model.Row, DiskFact) {
	s := d.Smart
	f := DiskFact{
		Device: d.target(), Kind: d.kind(), Interface: d.Iface, Vendor: d.Vendor, Model: d.Model,
		Serial: d.Serial, Firmware: d.Firmware, SizeBytes: d.Bytes, Location: d.location(),
		Virtual: d.Virtual, RAIDVolume: d.RAIDVol, BehindRAID: d.Passthrough, SmartError: d.SmartErr, Status: d.sev,
	}
	if d.SmartDev != "" {
		f.SmartDevice = d.SmartDev
		if d.SmartType != "" {
			f.SmartDevice += " -d " + d.SmartType
		}
	}
	counters := ""
	health := d.health
	if s != nil {
		f.Protocol = s.Protocol
		f.SmartPassed = s.Passed
		f.TemperatureC = validTemp(s.TempC)
		f.PowerOnHours = s.POH
		f.PercentUsed, _ = wearUsed(s)
		f.Standby = s.Standby != ""
		var cs []string
		if len(s.Attrs) > 0 {
			f.Reallocated = attrCount(s, 5)
			f.Pending = attrCount(s, 197)
			f.OfflineUncorrectable = attrCount(s, 198)
			f.ReportedUncorrect = attrCount(s, 187)
			f.CRCErrors = attrCount(s, 199)
			for _, x := range []struct {
				p     *uint64
				label string
			}{{f.Reallocated, "realloc"}, {f.Pending, "pending"}, {f.OfflineUncorrectable, "offline-unc"}, {f.CRCErrors, "CRC"}} {
				if x.p != nil {
					cs = append(cs, fmt.Sprintf("%s %s", x.label, units.Thousands(*x.p)))
				}
			}
		}
		if n := s.NVMe; n != nil {
			f.NVMeCriticalWarning, f.NVMeMediaErrors, f.NVMeErrorLogEntries, f.AvailableSpare = n.CriticalWarning, n.MediaErrors, n.NumErrLogEntries, n.AvailableSpare
			if n.CriticalWarning != nil && *n.CriticalWarning != 0 {
				cs = append(cs, fmt.Sprintf("critical warning 0x%02x", *n.CriticalWarning))
			}
			if n.AvailableSpare != nil {
				cs = append(cs, fmt.Sprintf("spare %d%%", *n.AvailableSpare))
			}
			if n.MediaErrors != nil {
				cs = append(cs, "media errors "+units.Thousands(*n.MediaErrors))
			}
		}
		if s.GrownDefects != nil {
			f.GrownDefects = s.GrownDefects
			cs = append(cs, "grown defects "+units.Thousands(*s.GrownDefects))
		}
		if s.Uncorrected != nil {
			f.UncorrectedErrors = s.Uncorrected
			var tot uint64
			for _, v := range s.Uncorrected {
				tot += v
			}
			cs = append(cs, "uncorrected "+units.Thousands(tot))
		}
		if f.PercentUsed != nil {
			cs = append(cs, fmt.Sprintf("used %d%%", *f.PercentUsed))
		}
		counters = strings.Join(cs, ", ")
		if health == "" {
			switch {
			case s.Standby != "":
				health = "standby"
			case s.Passed != nil && *s.Passed:
				health = "PASSED"
			case s.Passed != nil:
				health = "FAILED"
			}
		}
	}
	if w := d.Win; w != nil {
		if f.TemperatureC == nil {
			f.TemperatureC = w.temp()
		}
		if f.PowerOnHours == nil {
			f.PowerOnHours = w.poh()
		}
		if f.PercentUsed == nil {
			f.PercentUsed = w.wear()
		}
		if counters == "" {
			counters = w.counters()
		}
		if health == "" {
			health = w.HealthStatus
		}
	}
	if health == "" {
		switch {
		case d.SAN:
			health = "n/a (SAN LUN)"
		case d.Virtual:
			health = "n/a (virtual)"
		case d.RAIDVol:
			health = "n/a (RAID volume)"
		case d.SmartTO:
			health = "timeout"
		case d.SmartErr != "":
			health = "unreadable"
		default:
			health = "not checked"
		}
	}
	f.Health = health
	temp, poh := "", ""
	if f.TemperatureC != nil {
		temp = fmt.Sprintf("%d °C", *f.TemperatureC)
	}
	if f.PowerOnHours != nil {
		poh = units.Hours(*f.PowerOnHours).EN
	}
	status := d.sev.String()
	switch {
	case f.Standby:
		status = "standby"
	case d.Virtual || d.RAIDVol:
		status = "n/a"
	case d.sev == model.OK && (health == "not checked" || health == "unreadable" || health == "timeout"):
		status = "unknown"
	}
	mdl := strings.TrimSpace(d.Vendor + " " + d.Model)
	if d.Vendor != "" && strings.HasPrefix(strings.ToUpper(d.Model), strings.ToUpper(d.Vendor)) {
		mdl = d.Model
	}
	row := model.Row{Status: d.sev, Cells: []string{
		d.target(), mdl, d.Serial, sizeText(d.Bytes), f.Kind, d.Iface, health, temp, poh, counters, status,
	}}
	return row, f
}

func attrCount(s *smartData, id int) *uint64 {
	a := s.attr(id)
	if a == nil {
		return nil
	}
	n := a.count()
	return &n
}

// lessDev sorts /dev/sda < /dev/sdb < /dev/sdaa and /dev/nvme2 < /dev/nvme10.
func lessDev(a, b string) bool {
	if len(a) != len(b) && strings.TrimRight(a, "0123456789") == strings.TrimRight(b, "0123456789") {
		return len(a) < len(b)
	}
	if len(a) != len(b) && strings.HasPrefix(a, "/dev/sd") && strings.HasPrefix(b, "/dev/sd") &&
		!strings.ContainsAny(a[7:], "0123456789") && !strings.ContainsAny(b[7:], "0123456789") {
		return len(a) < len(b)
	}
	return a < b
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func validTemp(t *int) *int {
	if t == nil || *t <= 0 || *t >= 128 {
		return nil
	}
	return t
}

// standbyText explains disks that were not checked because smartctl -n
// standby did not wake them.
func standbyText(names []string) model.Text {
	return model.Tf("Asleep (standby) and not woken up, so S.M.A.R.T. was not read: %s. Run Diagward again while the disks are active.",
		"Ổ đang ngủ (standby) nên không bị đánh thức, chưa đọc được S.M.A.R.T.: %s. Chạy lại Diagward khi ổ đang hoạt động.",
		strings.Join(names, ", "))
}
