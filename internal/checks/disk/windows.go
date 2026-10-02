package disk

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

// Windows sections (collect/windows/30-disk.ps1):
//
//	disk.win_physical     Get-PhysicalDisk (MSFT_PhysicalDisk)
//	disk.win_reliability  Get-StorageReliabilityCounter per disk (admin)
//	disk.win_predict      root\wmi MSStorageDriver_FailurePredictStatus (admin)
//	disk.win_diskdrive    Win32_DiskDrive
//
// Enum properties are written as strings by the collector, but PowerShell
// versions differ (the Storage module's type data turns them into names on
// 5.1; raw CIM values are numbers), so both forms are accepted.

// flexVal decodes a JSON string, number, bool, null or array into text.
type flexVal string

func (f *flexVal) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	switch {
	case s == "null":
		*f = ""
	case strings.HasPrefix(s, `"`):
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*f = flexVal(v)
	case strings.HasPrefix(s, "["):
		var vs []flexVal
		if err := json.Unmarshal(b, &vs); err != nil {
			return err
		}
		var parts []string
		for _, v := range vs {
			if v != "" {
				parts = append(parts, string(v))
			}
		}
		*f = flexVal(strings.Join(parts, ","))
	default:
		*f = flexVal(s)
	}
	return nil
}

func (f flexVal) uint() (uint64, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(string(f)), 10, 64)
	return n, err == nil
}

type winPhysical struct {
	FriendlyName      flexVal `json:"FriendlyName"`
	SerialNumber      flexVal `json:"SerialNumber"`
	MediaType         flexVal `json:"MediaType"`
	BusType           flexVal `json:"BusType"`
	Size              flexVal `json:"Size"`
	HealthStatus      flexVal `json:"HealthStatus"`
	OperationalStatus flexVal `json:"OperationalStatus"`
	FirmwareVersion   flexVal `json:"FirmwareVersion"`
	DeviceID          flexVal `json:"DeviceId"`
	SpindleSpeed      flexVal `json:"SpindleSpeed"`
	Model             flexVal `json:"Model"`
	Manufacturer      flexVal `json:"Manufacturer"`
	PhysicalLocation  flexVal `json:"PhysicalLocation"`
}

type winReliability struct {
	DiskDeviceID           flexVal `json:"DiskDeviceId"`
	DeviceID               flexVal `json:"DeviceId"`
	Temperature            *int    `json:"Temperature"`
	TemperatureMax         *int    `json:"TemperatureMax"`
	Wear                   *int    `json:"Wear"`
	ReadErrorsTotal        *uint64 `json:"ReadErrorsTotal"`
	ReadErrorsCorrected    *uint64 `json:"ReadErrorsCorrected"`
	ReadErrorsUncorrected  *uint64 `json:"ReadErrorsUncorrected"`
	WriteErrorsTotal       *uint64 `json:"WriteErrorsTotal"`
	WriteErrorsCorrected   *uint64 `json:"WriteErrorsCorrected"`
	WriteErrorsUncorrected *uint64 `json:"WriteErrorsUncorrected"`
	PowerOnHours           *uint64 `json:"PowerOnHours"`
	StartStopCycleCount    *uint64 `json:"StartStopCycleCount"`
	LoadUnloadCycleCount   *uint64 `json:"LoadUnloadCycleCount"`
	ReadLatencyMax         *uint64 `json:"ReadLatencyMax"`
	WriteLatencyMax        *uint64 `json:"WriteLatencyMax"`
	FlushLatencyMax        *uint64 `json:"FlushLatencyMax"`
	ManufactureDate        flexVal `json:"ManufactureDate"`
}

type winPredict struct {
	InstanceName   flexVal `json:"InstanceName"`
	Active         *bool   `json:"Active"`
	PredictFailure *bool   `json:"PredictFailure"`
	Reason         *int    `json:"Reason"`
}

type winDiskDrive struct {
	Index            *int    `json:"Index"`
	Model            flexVal `json:"Model"`
	SerialNumber     flexVal `json:"SerialNumber"`
	Status           flexVal `json:"Status"`
	InterfaceType    flexVal `json:"InterfaceType"`
	PNPDeviceID      flexVal `json:"PNPDeviceID"`
	Size             flexVal `json:"Size"`
	FirmwareRevision flexVal `json:"FirmwareRevision"`
}

// winDisk is everything Windows says about one disk.
type winDisk struct {
	Index        int
	HealthStatus string // Healthy, Warning, Unhealthy, Unknown
	OpStatus     string
	Media        string
	Bus          string
	Location     string
	Rel          *winReliability
	Predict      *winPredict
	Drive        *winDiskDrive
}

var winHealth = map[string]string{"0": "Healthy", "1": "Warning", "2": "Unhealthy", "5": "Unknown"}

// MSFT_PhysicalDisk.MediaType: 0 Unspecified, 3 HDD, 4 SSD, 5 SCM.
var winMedia = map[string]string{"0": "Unspecified", "3": "HDD", "4": "SSD", "5": "SCM"}

// MSFT_PhysicalDisk.BusType (Storage Management API documentation).
var winBus = map[string]string{
	"0": "Unknown", "1": "SCSI", "2": "ATAPI", "3": "ATA", "4": "1394", "5": "SSA", "6": "Fibre Channel",
	"7": "USB", "8": "RAID", "9": "iSCSI", "10": "SAS", "11": "SATA", "12": "SD", "13": "MMC",
	"14": "Virtual", "15": "File Backed Virtual", "16": "Storage Spaces", "17": "NVMe", "18": "SCM", "19": "UFS",
}

// MSFT_PhysicalDisk.OperationalStatus values, as mapped by the Windows Storage
// module (Storage.types.ps1xml, Windows 10 / Server 2016+).
var winOpStatus = map[string]string{
	"0": "Unknown", "1": "Other", "2": "OK", "3": "Degraded", "4": "Stressed", "5": "Predictive Failure",
	"6": "Error", "7": "Non-Recoverable Error", "8": "Starting", "9": "Stopping", "10": "Stopped",
	"11": "In Service", "12": "No Contact", "13": "Lost Communication", "14": "Aborted", "15": "Dormant",
	"16": "Supporting Entity in Error", "17": "Completed", "18": "Power Mode", "19": "Relocating",
	"53252": "Failed Media", "53253": "Split", "53254": "Stale Metadata", "53255": "IO Error", "53256": "Unrecognized Metadata",
	"53269": "Removing From Pool", "53270": "In Maintenance Mode", "53271": "Updating Firmware", "53272": "Device Hardware Error",
	"53273": "Not Usable", "53274": "Transient Error", "53276": "Starting Maintenance Mode", "53277": "Stopping Maintenance Mode",
	"53285": "Threshold Exceeded", "53286": "Abnormal Latency",
}

func mapEnum(m map[string]string, v flexVal) string {
	s := strings.TrimSpace(string(v))
	if n, ok := m[s]; ok {
		return n
	}
	return s
}

func mapEnumList(m map[string]string, v flexVal) string {
	var out []string
	for _, p := range strings.Split(string(v), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, mapEnum(m, flexVal(p)))
		}
	}
	return strings.Join(out, ", ")
}

func (w *winDisk) mediaType() string { return w.Media }

func (w *winDisk) temp() *int {
	if w.Rel == nil {
		return nil
	}
	return validTemp(w.Rel.Temperature)
}

func (w *winDisk) poh() *uint64 {
	if w.Rel == nil || w.Rel.PowerOnHours == nil || *w.Rel.PowerOnHours == 0 || *w.Rel.PowerOnHours == 0xffff {
		return nil // UInt16 in the CIM schema: 65535 means saturated
	}
	return w.Rel.PowerOnHours
}

func (w *winDisk) wear() *int {
	if w.Rel == nil || w.Rel.Wear == nil || w.Media == "HDD" {
		return nil
	}
	if *w.Rel.Wear == 0 && w.Media != "SSD" && w.Media != "SCM" {
		return nil
	}
	return w.Rel.Wear
}

func (w *winDisk) counters() string {
	if w.Rel == nil {
		return ""
	}
	var cs []string
	if w.Rel.ReadErrorsUncorrected != nil {
		cs = append(cs, fmt.Sprintf("read uncorrected %d", *w.Rel.ReadErrorsUncorrected))
	}
	if w.Rel.WriteErrorsUncorrected != nil {
		cs = append(cs, fmt.Sprintf("write uncorrected %d", *w.Rel.WriteErrorsUncorrected))
	}
	if u := w.wear(); u != nil {
		cs = append(cs, fmt.Sprintf("used %d%%", *u))
	}
	return strings.Join(cs, ", ")
}

// winSmartIndex maps a smartctl device name on Windows to the disk number:
// /dev/sda = PhysicalDrive0, /dev/sdb = 1, ..., /dev/sdaa = 26
// (smartmontools os_win32.cpp).
func winSmartIndex(dev string) int {
	s, ok := strings.CutPrefix(dev, "/dev/sd")
	if !ok || s == "" || len(s) > 2 {
		if n, ok := strings.CutPrefix(dev, "/dev/pd"); ok {
			if i, err := strconv.Atoi(n); err == nil {
				return i
			}
		}
		return -1
	}
	idx := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 'a' || c > 'z' {
			return -1
		}
		idx = idx*26 + int(c-'a') + 1
	}
	return idx - 1
}

func (c *checker) windowsInventory() {
	phys := c.b.Get("disk.win_physical")
	dd := c.b.Get("disk.win_diskdrive")
	if phys == nil && dd == nil {
		return
	}
	var pds []winPhysical
	var drives []winDiskDrive
	state, reason := model.CovRan, model.Text{}
	if phys.Ran() {
		if err := collect.DecodeJSON(phys.Text(), &pds); err != nil {
			state, reason = model.CovPartial, model.Tf("Get-PhysicalDisk output could not be read: %s", "Không đọc được kết quả Get-PhysicalDisk: %s", err.Error())
		} else if phys.RC != 0 && len(pds) == 0 {
			state, reason = model.CovPartial, model.Tf("Get-PhysicalDisk failed: %s", "Get-PhysicalDisk bị lỗi: %s", firstLine(phys.Err))
		}
	} else if phys != nil {
		state, reason = model.CovPartial, model.T("Get-PhysicalDisk is not available.", "Không có lệnh Get-PhysicalDisk.")
	}
	if dd.Ran() {
		_ = collect.DecodeJSON(dd.Text(), &drives)
	}
	byIndex := map[int]*diskInfo{}
	for i := range pds {
		p := &pds[i]
		idx := -1
		if n, ok := p.DeviceID.uint(); ok {
			idx = int(n)
		}
		w := &winDisk{Index: idx, HealthStatus: mapEnum(winHealth, p.HealthStatus), OpStatus: mapEnumList(winOpStatus, p.OperationalStatus),
			Media: mapEnum(winMedia, p.MediaType), Bus: mapEnum(winBus, p.BusType), Location: clean(string(p.PhysicalLocation))}
		d := &diskInfo{Dev: fmt.Sprintf("PhysicalDisk%d", idx), Model: clean(firstNonEmpty(string(p.Model), string(p.FriendlyName))),
			Serial: strings.TrimRight(clean(string(p.SerialNumber)), "."), Firmware: clean(string(p.FirmwareVersion)),
			Vendor: clean(string(p.Manufacturer)), Win: w, WinIndex: idx, Location: w.Location}
		if idx < 0 {
			d.Dev = "PhysicalDisk?"
		}
		d.Bytes, _ = p.Size.uint()
		d.Iface = w.Bus
		if d.Vendor == "" {
			d.Vendor = vendorFromModel(d.Model)
		}
		if w.Bus == "Virtual" || w.Bus == "File Backed Virtual" || virtualModel(d.Vendor, d.Model) {
			d.Virtual = true
		}
		if w.Bus == "RAID" && raidVolume(d.Vendor, d.Model) {
			d.RAIDVol = true
		}
		c.disks = append(c.disks, d)
		if idx >= 0 {
			byIndex[idx] = d
		}
	}
	for i := range drives {
		dr := &drives[i]
		if dr.Index == nil {
			continue
		}
		d := byIndex[*dr.Index]
		if d == nil {
			// Get-PhysicalDisk missing (old Windows): build from Win32_DiskDrive.
			d = &diskInfo{Dev: fmt.Sprintf("PhysicalDisk%d", *dr.Index), Model: clean(string(dr.Model)),
				Serial: strings.TrimRight(clean(string(dr.SerialNumber)), "."), Firmware: clean(string(dr.FirmwareRevision)),
				WinIndex: *dr.Index, Win: &winDisk{Index: *dr.Index}, Iface: clean(string(dr.InterfaceType))}
			d.Bytes, _ = dr.Size.uint()
			d.Vendor = vendorFromModel(d.Model)
			d.Virtual = virtualModel("", d.Model)
			c.disks = append(c.disks, d)
			byIndex[*dr.Index] = d
		}
		d.Win.Drive = dr
		// Intel RST/VMD presents NVMe disks with BusType RAID; the PNP ID
		// still says VEN_NVME. Such a disk is not a RAID logical volume.
		if strings.Contains(strings.ToUpper(string(dr.PNPDeviceID)), "VEN_NVME") && d.Iface == "RAID" {
			d.Iface = "NVMe (RAID/VMD driver)"
			d.RAIDVol = false
		}
	}
	c.windowsAdminData(byIndex)
	c.cover("inventory", covInventory, state, reason, model.Text{})
}

func (c *checker) windowsAdminData(byIndex map[int]*diskInfo) {
	if rs := c.b.Get("disk.win_reliability"); rs.Ran() {
		var rels []winReliability
		if collect.DecodeJSON(rs.Text(), &rels) == nil {
			for i := range rels {
				r := &rels[i]
				id := firstNonEmpty(string(r.DiskDeviceID), string(r.DeviceID))
				if n, err := strconv.Atoi(strings.TrimSpace(id)); err == nil && byIndex[n] != nil {
					byIndex[n].Win.Rel = r
				}
			}
		}
	}
	if ps := c.b.Get("disk.win_predict"); ps.Ran() {
		var preds []winPredict
		if collect.DecodeJSON(ps.Text(), &preds) == nil {
			for i := range preds {
				p := &preds[i]
				inst := strings.ToUpper(string(p.InstanceName))
				for _, d := range byIndex {
					if d.Win.Drive == nil {
						continue
					}
					pnp := strings.ToUpper(string(d.Win.Drive.PNPDeviceID))
					// InstanceName is the PNP device ID plus "_0".
					if pnp != "" && strings.HasPrefix(inst, pnp) {
						d.Win.Predict = p
					}
				}
			}
		}
	}
}

// windowsRules turns Windows' own health data into findings. When smartctl
// data exists for the disk, temperature and wear come from smartctl (more
// detail) and are not repeated here.
func (c *checker) windowsRules(d *diskInfo) []model.Finding {
	w := d.Win
	var fs []model.Finding
	haveSmart := d.Smart != nil && hasHealth(d.Smart)
	ev := []string{fmt.Sprintf("HealthStatus: %s, OperationalStatus: %s, BusType: %s, MediaType: %s", firstNonEmpty(w.HealthStatus, "?"), firstNonEmpty(w.OpStatus, "?"), firstNonEmpty(w.Bus, "?"), firstNonEmpty(w.Media, "?"))}
	if w.Drive != nil && string(w.Drive.Status) != "" {
		ev = append(ev, "Win32_DiskDrive.Status: "+string(w.Drive.Status))
	}
	op := strings.ToLower(w.OpStatus)
	predictive := strings.Contains(op, "predictive failure") || strings.Contains(op, "failed media") ||
		strings.Contains(op, "device hardware error") || strings.Contains(op, "non-recoverable") ||
		(w.Drive != nil && strings.EqualFold(strings.TrimSpace(string(w.Drive.Status)), "Pred Fail"))
	switch {
	case strings.EqualFold(w.HealthStatus, "Unhealthy") || predictive:
		fs = append(fs, d.finding("win_health", model.Crit,
			model.Tf("Windows reports disk %s as unhealthy", "Windows báo ổ %s không khỏe (Unhealthy)", d.target()),
			model.Tf("Windows reports HealthStatus %s (OperationalStatus: %s). Windows marks a disk Unhealthy when it has failed or predicts its own failure.",
				"Windows báo HealthStatus %s (OperationalStatus: %s). Windows đánh dấu Unhealthy khi ổ đã hỏng hoặc tự báo sắp hỏng.", w.HealthStatus, w.OpStatus),
			d.replaceAction("", ""), ev))
	case strings.EqualFold(w.HealthStatus, "Warning"):
		fs = append(fs, d.finding("win_health", model.Warn,
			model.Tf("Windows reports a warning on disk %s", "Windows báo cảnh báo trên ổ %s", d.target()),
			model.Tf("Windows reports HealthStatus Warning (OperationalStatus: %s).", "Windows báo HealthStatus Warning (OperationalStatus: %s).", w.OpStatus),
			model.Tf("Back up %s, check Event Viewer (System log, disk/storport events) and plan a replacement (%s).",
				"Sao lưu %s, xem Event Viewer (System log, sự kiện disk/storport) và lên kế hoạch thay ổ (%s).", d.target(), d.ident()), ev))
	}
	if p := w.Predict; p != nil && p.PredictFailure != nil && *p.PredictFailure {
		reason := 0
		if p.Reason != nil {
			reason = *p.Reason
		}
		fs = append(fs, d.finding("win_predict_failure", model.Crit,
			model.Tf("Disk %s predicts its own failure (S.M.A.R.T. via Windows)", "Ổ %s tự báo sắp hỏng (S.M.A.R.T. qua Windows)", d.target()),
			model.T("The drive's S.M.A.R.T. failure prediction flag is set (MSStorageDriver_FailurePredictStatus.PredictFailure).",
				"Cờ dự báo hỏng S.M.A.R.T. của ổ đang bật (MSStorageDriver_FailurePredictStatus.PredictFailure)."),
			d.replaceAction("", ""), []string{fmt.Sprintf("PredictFailure: true, Reason: %d, InstanceName: %s", reason, p.InstanceName)}))
	}
	if r := w.Rel; r != nil {
		var unc []string
		if r.ReadErrorsUncorrected != nil && *r.ReadErrorsUncorrected > 0 {
			unc = append(unc, fmt.Sprintf("ReadErrorsUncorrected: %d", *r.ReadErrorsUncorrected))
		}
		if r.WriteErrorsUncorrected != nil && *r.WriteErrorsUncorrected > 0 {
			unc = append(unc, fmt.Sprintf("WriteErrorsUncorrected: %d", *r.WriteErrorsUncorrected))
		}
		if len(unc) > 0 && !haveSmart {
			fs = append(fs, d.finding("win_uncorrected_errors", model.Crit,
				model.Tf("Disk %s has uncorrected read/write errors", "Ổ %s có lỗi đọc/ghi không sửa được", d.target()),
				model.T("The drive's reliability counters record reads or writes it could not recover: data could not be read back or written.",
					"Bộ đếm độ tin cậy của ổ ghi nhận lần đọc/ghi không phục hồi được: dữ liệu không đọc lại hoặc không ghi được."),
				d.replaceAction("", ""), unc))
		}
		var lat []string
		for _, x := range []struct {
			n string
			v *uint64
		}{{"ReadLatencyMax", r.ReadLatencyMax}, {"WriteLatencyMax", r.WriteLatencyMax}, {"FlushLatencyMax", r.FlushLatencyMax}} {
			if x.v != nil && *x.v > winLatencyWarnMs {
				lat = append(lat, fmt.Sprintf("%s: %d ms", x.n, *x.v))
			}
		}
		if len(lat) > 0 {
			fs = append(fs, d.finding("win_latency", model.Warn,
				model.Tf("Disk %s had I/O requests taking over 10 seconds", "Ổ %s có yêu cầu I/O mất hơn 10 giây", d.target()),
				model.T("Microsoft documents a maximum latency above 10 seconds as a possible problem with the disk or the HBA (MSFT_StorageReliabilityCounter).",
					"Theo tài liệu của Microsoft, độ trễ tối đa trên 10 giây có thể là dấu hiệu lỗi ổ hoặc card HBA (MSFT_StorageReliabilityCounter)."),
				model.T("Check Event Viewer for disk/storport timeouts (Event ID 129, 153) and the cabling/controller of this disk; back it up.",
					"Xem Event Viewer có timeout của disk/storport không (Event ID 129, 153), kiểm tra cáp/controller của ổ; sao lưu dữ liệu."), lat))
		}
		if !haveSmart {
			if u := w.wear(); u != nil && *u >= wearWarn {
				fs = append(fs, wearFinding(d, *u, fmt.Sprintf("Wear: %d%% (Get-StorageReliabilityCounter)", *u)))
			}
			if t := validTemp(r.Temperature); t != nil && r.TemperatureMax != nil && *r.TemperatureMax >= 30 && *r.TemperatureMax <= 120 && *t >= *r.TemperatureMax {
				// TemperatureMax is documented as the maximum temperature for
				// normal operation, i.e. the drive's own limit.
				fs = append(fs, d.finding("temperature", model.Warn,
					model.Tf("Disk %s is running hot: %d °C (limit %d °C)", "Ổ %s đang nóng: %d °C (ngưỡng %d °C)", d.target(), *t, *r.TemperatureMax),
					model.T("The temperature is at or above the maximum operating temperature the drive reports.", "Nhiệt độ đã chạm mức tối đa khi hoạt động mà ổ khai báo."),
					model.T("Check fans, airflow and the room temperature.", "Kiểm tra quạt, luồng gió và nhiệt độ phòng máy."),
					[]string{fmt.Sprintf("Temperature: %d, TemperatureMax: %d", *t, *r.TemperatureMax)}))
			}
			if h := w.poh(); h != nil && *h >= oldDiskHours {
				fs = append(fs, d.finding("old_disk", model.Info,
					model.Tf("Disk %s has been powered on for more than five years", "Ổ %s đã chạy hơn 5 năm", d.target()),
					model.T("Beyond the usual warranty and design life; failure rates rise with age.", "Quá thời hạn bảo hành và tuổi thọ thiết kế thông thường; tỉ lệ hỏng tăng theo tuổi."),
					model.T("Plan a replacement in the next hardware refresh.", "Đưa ổ vào kế hoạch thay mới đợt nâng cấp tới."),
					[]string{fmt.Sprintf("PowerOnHours: %d", *h)}))
			}
		}
	}
	return fs
}

func (c *checker) windowsCoverage(raidNames []string) {
	if c.b.Get("disk.win_physical") == nil && c.b.Get("disk.smart_scan") == nil && len(c.b.Prefix("disk.smart:")) == 0 {
		return
	}
	rel, pred, scan := c.b.Get("disk.win_reliability"), c.b.Get("disk.win_predict"), c.b.Get("disk.smart_scan")
	notAdmin := (rel != nil && rel.Skipped == "not-admin") || (scan != nil && scan.Skipped == "not-admin") || !c.env.Root
	smartOK := scan.Ran() && len(c.b.Prefix("disk.smart:")) > 0
	smartMissing := scan != nil && scan.Missing != ""
	physical := 0
	for _, d := range c.disks {
		if !d.Virtual && !d.RAIDVol {
			physical++
		}
	}
	switch {
	case physical == 0 && len(c.disks) > 0 && len(raidNames) == 0:
		c.cover("smart", covSmart, model.CovSkipped, hint.Virtual(c.env), model.Text{})
	case notAdmin:
		c.cover("smart", covSmart, model.CovPartial,
			model.T("Without Administrator rights only the Windows health status was read; S.M.A.R.T. counters, failure prediction and smartctl need Administrator.",
				"Không có quyền Administrator nên chỉ đọc được trạng thái sức khỏe của Windows; bộ đếm S.M.A.R.T., dự báo hỏng và smartctl cần quyền Administrator."),
			hint.RunAsRoot(c.env))
	case smartOK && len(raidNames) > 0:
		c.cover("smart", covSmart, model.CovPartial, raidHiddenText(raidNames), raidHiddenFix(raidNames))
	case smartOK && len(c.standby) > 0:
		c.cover("smart", covSmart, model.CovPartial, standbyText(c.standby), model.Text{})
	case smartOK:
		c.cover("smart", covSmart, model.CovRan, model.Text{}, model.Text{})
	case rel.Ran() || pred.Ran():
		reason := model.T("Windows reliability counters only; install smartmontools for full S.M.A.R.T. detail (attributes, self-tests, error logs).",
			"Chỉ có bộ đếm độ tin cậy của Windows; cài smartmontools để xem đầy đủ S.M.A.R.T. (thuộc tính, self-test, nhật ký lỗi).")
		fix, cmd := model.Text{}, ""
		if smartMissing {
			fix, cmd = hint.InstallFix(c.env, "smartctl")
		}
		c.coverCmd("smart", covSmart, model.CovPartial, reason, fix, cmd)
	default:
		fix, cmd := hint.InstallFix(c.env, "smartctl")
		c.coverCmd("smart", covSmart, model.CovPartial,
			model.T("Only the Windows health status was available.", "Chỉ có trạng thái sức khỏe của Windows."), fix, cmd)
	}
}
