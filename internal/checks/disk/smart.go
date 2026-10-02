package disk

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// smartJSON is the subset of `smartctl -x -j` output (smartctl >= 7.0) that
// the analysis reads. Key names were checked against smartmontools'
// ataprint.cpp, nvmeprint.cpp and scsiprint.cpp (7.0 to 7.5) and against
// real outputs in testdata/. Fields that changed type between versions are
// decoded defensively: json.Unmarshal fills every field it can and reports
// the first type mismatch, which decodeSmartJSON ignores.
type smartJSON struct {
	Smartctl struct {
		Version    []int `json:"version"`
		ExitStatus *int  `json:"exit_status"`
		Messages   []struct {
			String   string `json:"string"`
			Severity string `json:"severity"`
		} `json:"messages"`
	} `json:"smartctl"`
	Device struct {
		Name     string `json:"name"`
		InfoName string `json:"info_name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelFamily     string `json:"model_family"`
	ModelName       string `json:"model_name"`
	Vendor          string `json:"vendor"`
	Product         string `json:"product"`
	ScsiVendor      string `json:"scsi_vendor"`
	ScsiProduct     string `json:"scsi_product"`
	ScsiModelName   string `json:"scsi_model_name"`
	SerialNumber    string `json:"serial_number"`
	FirmwareVersion string `json:"firmware_version"`
	Revision        string `json:"revision"`
	ScsiRevision    string `json:"scsi_revision"`
	WWN             *struct {
		NAA uint64 `json:"naa"`
		OUI uint64 `json:"oui"`
		ID  uint64 `json:"id"`
	} `json:"wwn"`
	LogicalUnitID string `json:"logical_unit_id"`
	UserCapacity  struct {
		Bytes uint64 `json:"bytes"`
	} `json:"user_capacity"`
	NvmeTotalCapacity uint64 `json:"nvme_total_capacity"`
	NvmePCIVendor     struct {
		ID int `json:"id"`
	} `json:"nvme_pci_vendor"`
	RotationRate *int `json:"rotation_rate"`
	SataVersion  struct {
		String string `json:"string"`
	} `json:"sata_version"`
	ScsiTransportProtocol struct {
		Name string `json:"name"`
	} `json:"scsi_transport_protocol"`
	SmartSupport *struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed *bool `json:"passed"`
		Nvme   *struct {
			Value int `json:"value"`
		} `json:"nvme"`
		Scsi *struct {
			Asc      int    `json:"asc"`
			Ascq     int    `json:"ascq"`
			IEString string `json:"ie_string"`
		} `json:"scsi"`
	} `json:"smart_status"`
	PowerMode *struct {
		Name string `json:"name"`
	} `json:"power_mode"`
	AtaSmartAttributes struct {
		Table []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			Value      *int   `json:"value"`
			Worst      *int   `json:"worst"`
			Thresh     *int   `json:"thresh"`
			WhenFailed string `json:"when_failed"`
			Flags      struct {
				Value      int  `json:"value"`
				Prefailure bool `json:"prefailure"`
			} `json:"flags"`
			Raw struct {
				Value  uint64 `json:"value"`
				String string `json:"string"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	PowerOnTime struct {
		Hours *uint64 `json:"hours"`
	} `json:"power_on_time"`
	PowerCycleCount *uint64 `json:"power_cycle_count"`
	Temperature     struct {
		Current          *int `json:"current"`
		DriveTrip        *int `json:"drive_trip"`
		OpLimitMax       *int `json:"op_limit_max"`
		LimitMax         *int `json:"limit_max"`
		CriticalLimitMax *int `json:"critical_limit_max"`
		LifetimeMax      *int `json:"lifetime_max"`
	} `json:"temperature"`
	AtaSctStatus struct {
		Temperature struct {
			Current    *int `json:"current"`
			OpLimitMax *int `json:"op_limit_max"`
			LimitMax   *int `json:"limit_max"`
		} `json:"temperature"`
	} `json:"ata_sct_status"`
	AtaSctTemperatureHistory struct {
		OpLimitMax *int `json:"op_limit_max"`
		LimitMax   *int `json:"limit_max"`
	} `json:"ata_sct_temperature_history"`
	AtaSmartErrorLog struct {
		Summary  *ataErrLogJSON `json:"summary"`
		Extended *ataErrLogJSON `json:"extended"`
	} `json:"ata_smart_error_log"`
	AtaSmartSelfTestLog struct {
		Standard *ataSelfTestLogJSON `json:"standard"`
		Extended *ataSelfTestLogJSON `json:"extended"`
	} `json:"ata_smart_self_test_log"`
	AtaDeviceStatistics struct {
		Pages []struct {
			Number int `json:"number"`
			Table  []struct {
				Offset int    `json:"offset"`
				Name   string `json:"name"`
				Value  *int64 `json:"value"`
				Flags  struct {
					Valid bool `json:"valid"`
				} `json:"flags"`
			} `json:"table"`
		} `json:"pages"`
	} `json:"ata_device_statistics"`
	EnduranceUsed struct {
		CurrentPercent *int `json:"current_percent"`
	} `json:"endurance_used"`
	ScsiPercentUsedEndurance *int     `json:"scsi_percentage_used_endurance_indicator"`
	NvmeHealth               *nvmeLog `json:"nvme_smart_health_information_log"`
	NvmeTempThreshold        struct {
		Warning  *int `json:"warning"`
		Critical *int `json:"critical"`
	} `json:"nvme_composite_temperature_threshold"`
	NvmeSelfTestLog struct {
		Table []struct {
			SelfTestCode struct {
				Value  int    `json:"value"`
				String string `json:"string"`
			} `json:"self_test_code"`
			SelfTestResult struct {
				Value  int    `json:"value"`
				String string `json:"string"`
			} `json:"self_test_result"`
			PowerOnHours uint64 `json:"power_on_hours"`
		} `json:"table"`
	} `json:"nvme_self_test_log"`
	ScsiGrownDefectList *uint64                    `json:"scsi_grown_defect_list"`
	ScsiErrorCounterLog map[string]json.RawMessage `json:"scsi_error_counter_log"`
}

type ataErrLogJSON struct {
	Count       *int `json:"count"`
	LoggedCount int  `json:"logged_count"`
	Table       []struct {
		ErrorNumber      int    `json:"error_number"`
		LifetimeHours    uint64 `json:"lifetime_hours"`
		ErrorDescription string `json:"error_description"`
	} `json:"table"`
}

type ataSelfTestLogJSON struct {
	Count *int `json:"count"`
	Table []struct {
		Type struct {
			Value  int    `json:"value"`
			String string `json:"string"`
		} `json:"type"`
		Status struct {
			Value  int    `json:"value"`
			String string `json:"string"`
			Passed *bool  `json:"passed"`
		} `json:"status"`
		LifetimeHours uint64  `json:"lifetime_hours"`
		LBA           *uint64 `json:"lba"`
	} `json:"table"`
}

type nvmeLog struct {
	CriticalWarning         *int    `json:"critical_warning"`
	Temperature             *int    `json:"temperature"`
	AvailableSpare          *int    `json:"available_spare"`
	AvailableSpareThreshold *int    `json:"available_spare_threshold"`
	PercentageUsed          *int    `json:"percentage_used"`
	PowerCycles             *uint64 `json:"power_cycles"`
	PowerOnHours            *uint64 `json:"power_on_hours"`
	UnsafeShutdowns         *uint64 `json:"unsafe_shutdowns"`
	MediaErrors             *uint64 `json:"media_errors"`
	NumErrLogEntries        *uint64 `json:"num_err_log_entries"`
	WarningTempTime         *uint64 `json:"warning_temp_time"`
	CriticalCompTime        *uint64 `json:"critical_comp_time"`
}

// smartData is one device's S.M.A.R.T. data, normalised from either the
// JSON or the text output of smartctl.
type smartData struct {
	Format   string // "json" or "text"
	Version  string // smartctl version, e.g. "7.3"
	Exit     int    // smartctl exit status, -1 when unknown
	Protocol string // "ATA", "NVMe", "SCSI" or ""
	DevName  string // device.name as smartctl reports it
	DevType  string // device.type
	InfoName string

	Family, Model, Vendor, Product, Serial, Firmware, WWN string
	Bytes                                                 uint64
	RPM                                                   int // -1 unknown, 0 = solid state
	Transport                                             string
	PCIVendor                                             int

	SmartAvailable *bool
	SmartEnabled   *bool
	Passed         *bool
	SCSIHealth     string // the text after "SMART Health Status:" when not OK
	Standby        string // power mode name when smartctl did not wake the disk
	Messages       []string
	ErrorMessages  []string

	Attrs []ataAttr

	POH       *uint64
	Cycles    *uint64
	TempC     *int
	TempWarn  *int // device-reported "maximum operating" limit
	TempCrit  *int // device-reported absolute/critical limit
	TempTrip  *int // SCSI drive trip temperature
	LifeMaxC  *int
	Endurance *int   // percentage used, from a standard log (device statistics, SCSI/NVMe log)
	EndurSrc  string // where Endurance came from

	ErrLogCount   *int
	ErrLogLastPOH *uint64
	ErrLogDescs   []string

	SelfTests []selfTest // most recent first

	NVMe *nvmeLog

	GrownDefects *uint64
	Uncorrected  map[string]uint64 // read/write/verify total uncorrected errors
}

type ataAttr struct {
	ID         int
	Name       string
	Value      *int
	Worst      *int
	Thresh     *int
	WhenFailed string // "now", "past" or ""
	Prefail    bool
	Raw        uint64
	RawStr     string
}

// selfTest is one entry of a self-test log, most recent first.
type selfTest struct {
	Kind     string // "Short offline", "Extended", "Background long"...
	Extended bool
	Status   string
	Result   int // 0 passed, 1 failed (Crit), 2 doubtful (Warn), -1 aborted/in progress/unknown
	Hours    uint64
	LBA      string
}

// decodeSmartJSON parses smartctl JSON output.
func decodeSmartJSON(out string) (*smartData, error) {
	var j smartJSON
	err := json.Unmarshal([]byte(out), &j)
	var te *json.UnmarshalTypeError
	if err != nil && !errors.As(err, &te) {
		return nil, err
	}
	d := &smartData{Format: "json", Exit: -1, RPM: -1}
	if len(j.Smartctl.Version) >= 2 {
		d.Version = fmt.Sprintf("%d.%d", j.Smartctl.Version[0], j.Smartctl.Version[1])
	}
	if j.Smartctl.ExitStatus != nil {
		d.Exit = *j.Smartctl.ExitStatus
	}
	for _, m := range j.Smartctl.Messages {
		s := strings.TrimSpace(m.String)
		if s == "" {
			continue
		}
		d.Messages = append(d.Messages, s)
		if m.Severity == "error" {
			d.ErrorMessages = append(d.ErrorMessages, s)
		}
		if p := standbyFromMessage(s); p != "" {
			d.Standby = p
		}
	}
	d.Protocol = j.Device.Protocol
	d.DevName, d.DevType, d.InfoName = j.Device.Name, j.Device.Type, j.Device.InfoName
	d.Family = clean(j.ModelFamily)
	d.Vendor = clean(firstNonEmpty(j.ScsiVendor, j.Vendor))
	d.Product = clean(firstNonEmpty(j.ScsiProduct, j.Product))
	d.Model = clean(firstNonEmpty(j.ModelName, j.ScsiModelName))
	if d.Model == "" {
		d.Model = strings.TrimSpace(d.Vendor + " " + d.Product)
	}
	d.Serial = clean(j.SerialNumber)
	d.Firmware = clean(firstNonEmpty(j.FirmwareVersion, j.ScsiRevision, j.Revision))
	if j.WWN != nil && (j.WWN.NAA != 0 || j.WWN.OUI != 0 || j.WWN.ID != 0) {
		d.WWN = fmt.Sprintf("%x %06x %09x", j.WWN.NAA, j.WWN.OUI, j.WWN.ID)
	} else if j.LogicalUnitID != "" {
		d.WWN = j.LogicalUnitID
	}
	d.Bytes = j.UserCapacity.Bytes
	if d.Bytes == 0 {
		d.Bytes = j.NvmeTotalCapacity
	}
	d.PCIVendor = j.NvmePCIVendor.ID
	if j.RotationRate != nil {
		d.RPM = *j.RotationRate
	}
	d.Transport = j.ScsiTransportProtocol.Name
	if d.Transport == "" && j.SataVersion.String != "" {
		d.Transport = "SATA"
	}
	if j.SmartSupport != nil {
		a, e := j.SmartSupport.Available, j.SmartSupport.Enabled
		d.SmartAvailable, d.SmartEnabled = &a, &e
	}
	if j.SmartStatus != nil && j.SmartStatus.Passed != nil {
		p := *j.SmartStatus.Passed
		d.Passed = &p
		if !p && j.SmartStatus.Scsi != nil {
			d.SCSIHealth = strings.TrimSpace(j.SmartStatus.Scsi.IEString)
		}
	}
	if j.PowerMode != nil && d.Standby == "" && d.Exit >= 0 && d.Exit&2 != 0 && isLowPower(j.PowerMode.Name) {
		d.Standby = j.PowerMode.Name
	}
	for _, a := range j.AtaSmartAttributes.Table {
		d.Attrs = append(d.Attrs, ataAttr{
			ID: a.ID, Name: a.Name, Value: a.Value, Worst: a.Worst, Thresh: a.Thresh,
			WhenFailed: strings.ToLower(a.WhenFailed), Prefail: a.Flags.Prefailure,
			Raw: a.Raw.Value, RawStr: a.Raw.String,
		})
	}
	d.POH = j.PowerOnTime.Hours
	d.Cycles = j.PowerCycleCount

	t := j.Temperature
	d.TempC = firstInt(t.Current, j.AtaSctStatus.Temperature.Current)
	d.TempWarn = firstInt(j.NvmeTempThreshold.Warning, t.OpLimitMax, j.AtaSctStatus.Temperature.OpLimitMax, j.AtaSctTemperatureHistory.OpLimitMax)
	d.TempCrit = firstInt(j.NvmeTempThreshold.Critical, t.CriticalLimitMax, t.LimitMax, j.AtaSctStatus.Temperature.LimitMax, j.AtaSctTemperatureHistory.LimitMax)
	d.TempTrip = t.DriveTrip
	d.LifeMaxC = t.LifetimeMax

	// Percentage used: ATA device statistics page 7 (ACS-3) or the SCSI
	// "Percentage used endurance indicator" (SBC-4); smartctl >= 7.3 puts
	// both in endurance_used.current_percent, older versions differ.
	if v := j.EnduranceUsed.CurrentPercent; v != nil {
		d.Endurance, d.EndurSrc = v, "endurance_used"
	} else if v := j.ScsiPercentUsedEndurance; v != nil {
		d.Endurance, d.EndurSrc = v, "scsi_percentage_used_endurance_indicator"
	}
	for _, p := range j.AtaDeviceStatistics.Pages {
		for _, e := range p.Table {
			if e.Value == nil || !e.Flags.Valid {
				continue
			}
			if (p.Number == 7 && e.Offset == 8) || strings.EqualFold(e.Name, "Percentage Used Endurance Indicator") {
				if d.Endurance == nil {
					v := int(*e.Value)
					d.Endurance, d.EndurSrc = &v, "ata_device_statistics"
				}
			}
		}
	}

	if el := firstErrLog(j.AtaSmartErrorLog.Extended, j.AtaSmartErrorLog.Summary); el != nil {
		d.ErrLogCount = el.Count
		for i, e := range el.Table {
			if i == 0 || e.LifetimeHours > derefU(d.ErrLogLastPOH) {
				h := e.LifetimeHours
				d.ErrLogLastPOH = &h
			}
			if e.ErrorDescription != "" && len(d.ErrLogDescs) < 5 {
				d.ErrLogDescs = append(d.ErrLogDescs, fmt.Sprintf("Error %d at %d h: %s", e.ErrorNumber, e.LifetimeHours, e.ErrorDescription))
			}
		}
	}
	for _, lg := range []*ataSelfTestLogJSON{j.AtaSmartSelfTestLog.Extended, j.AtaSmartSelfTestLog.Standard} {
		if lg == nil || len(lg.Table) == 0 {
			continue
		}
		for _, e := range lg.Table {
			st := selfTest{Kind: e.Type.String, Status: e.Status.String, Hours: e.LifetimeHours}
			st.Extended = strings.Contains(strings.ToLower(e.Type.String), "extended") || e.Type.Value == 2 || e.Type.Value == 130
			st.Result = ataSelfTestResult(e.Status.Value>>4, e.Status.Passed)
			if e.LBA != nil {
				st.LBA = strconv.FormatUint(*e.LBA, 10)
			}
			d.SelfTests = append(d.SelfTests, st)
		}
		break // the extended (GP) log is a superset of the standard one
	}
	for _, e := range j.NvmeSelfTestLog.Table {
		st := selfTest{Kind: e.SelfTestCode.String, Status: e.SelfTestResult.String, Hours: e.PowerOnHours}
		st.Extended = e.SelfTestCode.Value == 2
		st.Result = nvmeSelfTestResult(e.SelfTestResult.Value)
		d.SelfTests = append(d.SelfTests, st)
	}
	d.NVMe = j.NvmeHealth
	if d.NVMe != nil {
		if d.TempC == nil {
			d.TempC = d.NVMe.Temperature
		}
		if d.POH == nil {
			d.POH = d.NVMe.PowerOnHours
		}
		if d.NVMe.PercentageUsed != nil && d.Endurance == nil {
			d.Endurance, d.EndurSrc = d.NVMe.PercentageUsed, "nvme percentage_used"
		}
	}
	d.GrownDefects = j.ScsiGrownDefectList
	for k, raw := range j.ScsiErrorCounterLog {
		var c struct {
			TotalUncorrectedErrors *uint64 `json:"total_uncorrected_errors"`
		}
		if json.Unmarshal(raw, &c) == nil && c.TotalUncorrectedErrors != nil {
			if d.Uncorrected == nil {
				d.Uncorrected = map[string]uint64{}
			}
			d.Uncorrected[k] = *c.TotalUncorrectedErrors
		}
	}
	d.SelfTests = append(d.SelfTests, scsiSelfTestsJSON(out)...)
	if d.Protocol == "" {
		d.Protocol = guessProtocol(d)
	}
	return d, nil
}

// scsiSelfTestsJSON reads the scsi_self_test_N objects (N = 0 is the most
// recent), which smartctl writes as separate top-level keys.
func scsiSelfTestsJSON(out string) []selfTest {
	var top map[string]json.RawMessage
	if json.Unmarshal([]byte(out), &top) != nil {
		return nil
	}
	type ent struct {
		n  int
		st selfTest
	}
	var es []ent
	for k, raw := range top {
		if !strings.HasPrefix(k, "scsi_self_test_") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(k, "scsi_self_test_"))
		if err != nil {
			continue
		}
		var e struct {
			Code struct {
				Value  int    `json:"value"`
				String string `json:"string"`
			} `json:"code"`
			Result struct {
				Value  int    `json:"value"`
				String string `json:"string"`
			} `json:"result"`
			PowerOnTime struct {
				Hours uint64 `json:"hours"`
			} `json:"power_on_time"`
			FailedLBA struct {
				Value *uint64 `json:"value"`
			} `json:"lba_first_failure"`
		}
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		st := selfTest{Kind: e.Code.String, Status: e.Result.String, Hours: e.PowerOnTime.Hours}
		st.Extended = e.Code.Value == 2 || e.Code.Value == 6
		st.Result = scsiSelfTestResult(e.Result.Value)
		if e.FailedLBA.Value != nil {
			st.LBA = strconv.FormatUint(*e.FailedLBA.Value, 10)
		}
		es = append(es, ent{n, st})
	}
	sort.Slice(es, func(i, k int) bool { return es[i].n < es[k].n })
	out2 := make([]selfTest, 0, len(es))
	for _, e := range es {
		out2 = append(out2, e.st)
	}
	return out2
}

// ataSelfTestResult classifies the high nibble of an ATA self-test status
// (ACS-3 table "Self-test execution status values", as printed by
// smartctl's ataprint.cpp): 0 completed OK; 1 aborted by host; 2 interrupted
// by reset; 3 fatal or unknown error; 4 unknown failure; 5 electrical;
// 6 servo/seek; 7 read failure; 8 handling damage; 15 in progress.
func ataSelfTestResult(nib int, passed *bool) int {
	switch {
	case nib == 0:
		return 0
	case nib >= 4 && nib <= 8:
		return 1
	case nib == 3:
		return 2
	case nib == 1 || nib == 2 || nib == 15:
		return -1
	}
	if passed != nil && !*passed {
		return 1
	}
	return -1
}

// nvmeSelfTestResult classifies an NVMe self-test result (NVMe Base Spec
// 1.4, Figure 203): 0 OK; 1-4, 8, 9 aborted; 5 fatal or unknown error;
// 6 unknown failed segment; 7 failed segments.
func nvmeSelfTestResult(v int) int {
	switch v {
	case 0:
		return 0
	case 6, 7:
		return 1
	case 5:
		return 2
	}
	return -1
}

// scsiSelfTestResult classifies a SCSI self-test result (SPC-3 7.2.10):
// 0 completed; 1, 2 aborted; 3 unknown error, incomplete; 4 completed with
// a failed segment; 5-7 failed in a segment; 15 in progress.
func scsiSelfTestResult(v int) int {
	switch {
	case v == 0:
		return 0
	case v >= 4 && v <= 7:
		return 1
	case v == 3:
		return 2
	}
	return -1
}

func firstErrLog(ls ...*ataErrLogJSON) *ataErrLogJSON {
	for _, l := range ls {
		if l != nil && (l.Count != nil || len(l.Table) > 0) {
			return l
		}
	}
	return nil
}

// standbyFromMessage recognises smartctl's "Device is in STANDBY mode,
// exit(2)" message (ataprint.cpp/scsiprint.cpp), printed when -n standby
// kept it from spinning the disk up.
func standbyFromMessage(s string) string {
	const pfx = "Device is in "
	i := strings.Index(s, pfx)
	if i < 0 {
		return ""
	}
	rest := s[i+len(pfx):]
	j := strings.Index(rest, " mode")
	if j <= 0 {
		return ""
	}
	if m := rest[:j]; isLowPower(m) {
		return m
	}
	return ""
}

func isLowPower(m string) bool {
	m = strings.ToUpper(m)
	return strings.HasPrefix(m, "STANDBY") || strings.HasPrefix(m, "SLEEP") || strings.HasPrefix(m, "IDLE")
}

func guessProtocol(d *smartData) string {
	switch {
	case d.NVMe != nil || strings.Contains(d.DevType, "nvme"):
		return "NVMe"
	case len(d.Attrs) > 0:
		return "ATA"
	case d.GrownDefects != nil || d.Uncorrected != nil || d.Vendor != "":
		return "SCSI"
	}
	return ""
}

// attr returns the attribute with id, or nil.
func (d *smartData) attr(id int) *ataAttr {
	for i := range d.Attrs {
		if d.Attrs[i].ID == id {
			return &d.Attrs[i]
		}
	}
	return nil
}

// count returns the attribute's raw value as a counter. smartctl prints the
// raw value according to its drive database (e.g. "32 (Min/Max 24/38)" or
// "0 0 1"); the leading integer of that string is what users see and what
// vendors document, so it wins over the 48-bit raw number, which for some
// attributes packs several fields.
func (a *ataAttr) count() uint64 {
	if a == nil {
		return 0
	}
	if n, ok := leadingUint(a.RawStr); ok {
		return n
	}
	return a.Raw
}

// leadingUint parses the integer at the start of s ("12", "12 (…)", "0/1").
func leadingUint(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(s[:i], 10, 64)
	return n, err == nil
}
