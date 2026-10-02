package memory

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu/dmi"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

type winDIMM struct {
	BankLabel            string  `json:"BankLabel"`
	DeviceLocator        string  `json:"DeviceLocator"`
	Capacity             float64 `json:"Capacity"` // uint64 bytes; float64 tolerates odd encodings
	Speed                int     `json:"Speed"`
	ConfiguredClockSpeed int     `json:"ConfiguredClockSpeed"`
	Manufacturer         string  `json:"Manufacturer"`
	PartNumber           string  `json:"PartNumber"`
	SerialNumber         string  `json:"SerialNumber"`
	SMBIOSMemoryType     int     `json:"SMBIOSMemoryType"`
	TypeDetail           int     `json:"TypeDetail"` // bit 0x1000 = non-volatile
	FormFactor           int     `json:"FormFactor"`
	DataWidth            int     `json:"DataWidth"`
	TotalWidth           int     `json:"TotalWidth"`
}

type winArray struct {
	MemoryErrorCorrection *int    `json:"MemoryErrorCorrection"`
	MemoryDevices         int     `json:"MemoryDevices"`
	MaxCapacity           float64 `json:"MaxCapacity"`   // KB
	MaxCapacityEx         float64 `json:"MaxCapacityEx"` // KB
	Use                   *int    `json:"Use"`
}

type winOS struct {
	TotalVisibleMemorySize float64  `json:"TotalVisibleMemorySize"` // KB
	FreePhysicalMemory     float64  `json:"FreePhysicalMemory"`     // KB
	AvailableBytes         *float64 `json:"AvailableBytes"`
	CommittedBytes         *float64 `json:"CommittedBytes"`
	CommitLimit            *float64 `json:"CommitLimit"`
	PagesInputPerSec       *float64 `json:"PagesInputPerSec"`
}

type winPagefile struct {
	Name              string  `json:"Name"`
	AllocatedBaseSize float64 `json:"AllocatedBaseSize"` // MB
	CurrentUsage      float64 `json:"CurrentUsage"`      // MB
	PeakUsage         float64 `json:"PeakUsage"`         // MB
}

// MemDiagEvent is one Windows Memory Diagnostic result event.
type MemDiagEvent struct {
	ID      int       `json:"id"`
	Time    time.Time `json:"time,omitzero"`
	Message string    `json:"message,omitempty"`
}

type winMemDiag struct {
	ID          int    `json:"Id"`
	Level       int    `json:"Level"`
	TimeCreated string `json:"TimeCreated"`
	Message     string `json:"Message"`
}

// Win32_PhysicalMemoryArray.MemoryErrorCorrection (Microsoft docs).
var winECC = map[int]string{0: "Reserved", 1: "Other", 2: "Unknown", 3: "None", 4: "Parity", 5: "Single-bit ECC", 6: "Multi-bit ECC", 7: "CRC"}

// SMBIOS memory types (SMBIOS 3.x, type 17 "Memory Type").
var smbiosType = map[int]string{20: "DDR", 21: "DDR2", 24: "DDR3", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2", 29: "LPDDR3", 30: "LPDDR4", 34: "DDR5", 35: "LPDDR5"}

// Win32_PhysicalMemory.FormFactor.
var winFormFactor = map[int]string{8: "DIMM", 12: "SODIMM", 13: "SRIMM", 7: "SIMM"}

func (s *state) windows() {
	b := s.b
	var (
		wd   []winDIMM
		wa   []winArray
		wos  []winOS
		wpf  []winPagefile
		diag []winMemDiag
	)
	ps := b.Get("memory.win_physical")
	physOK := ps.Ran() && collect.DecodeJSON(ps.Out, &wd) == nil
	if ar := b.Get("memory.win_array"); ar.Ran() {
		_ = collect.DecodeJSON(ar.Out, &wa)
	}
	for _, d := range wd {
		dd := DIMM{
			Locator:      firstNonEmpty(strings.TrimSpace(d.DeviceLocator), strings.TrimSpace(d.BankLabel), "?"),
			Bank:         strings.TrimSpace(d.BankLabel),
			Populated:    d.Capacity > 0,
			SizeBytes:    uint64(max(d.Capacity, 0)),
			Type:         smbiosType[d.SMBIOSMemoryType],
			FormFactor:   winFormFactor[d.FormFactor],
			SpeedMT:      d.Speed,
			ConfiguredMT: d.ConfiguredClockSpeed,
			Manufacturer: cleanWin(d.Manufacturer, true),
			PartNumber:   cleanWin(d.PartNumber, false),
			Serial:       cleanWin(d.SerialNumber, false),
			TotalWidth:   d.TotalWidth,
			DataWidth:    d.DataWidth,
			CE:           -1,
			UE:           -1,
		}
		if dd.Bank == dd.Locator {
			dd.Bank = ""
		}
		// Win32_PhysicalMemory.TypeDetail 4096 (0x1000) = "Nonvolatile"
		// (Microsoft docs): persistent memory (NVDIMM, Optane PMem), whose
		// capacity is not RAM the OS counts.
		if d.TypeDetail&0x1000 != 0 {
			dd.PMem, dd.Type = true, "PMem"
		} else {
			dd.VolatileBytes = dd.SizeBytes
		}
		s.dimms = append(s.dimms, dd)
	}
	for _, a := range wa {
		if a.Use != nil && *a.Use != 3 && *a.Use != 0 && *a.Use != 2 {
			continue // not system memory
		}
		ecc := ""
		if a.MemoryErrorCorrection != nil {
			ecc = winECC[*a.MemoryErrorCorrection]
		}
		capKB := a.MaxCapacityEx
		if capKB <= 0 {
			capKB = a.MaxCapacity
		}
		mc := ""
		if capKB > 0 {
			mc = units.IEC(uint64(capKB) * 1024)
		}
		s.arrays = append(s.arrays, Array{ECC: ecc, MaxCapacity: mc, Devices: a.MemoryDevices})
	}
	switch {
	case ps == nil:
	case physOK && len(s.dimms) > 0:
		s.cov("memory.inventory", nameInventory, model.CovRan, model.Text{}, model.Text{})
	case s.virtual:
		s.cov("memory.inventory", nameInventory, model.CovSkipped, model.T("This virtual machine reports no memory modules.", "Máy ảo này không báo thanh RAM nào."), model.Text{})
	default:
		s.cov("memory.inventory", nameInventory, model.CovFailed,
			model.Tf("Win32_PhysicalMemory could not be read: %s", "Không đọc được Win32_PhysicalMemory: %s", firstNonEmpty(oneLine(ps.Err), "no modules reported")), model.Text{})
	}

	var visible uint64
	osec := b.Get("memory.win_os")
	if osec.Ran() && collect.DecodeJSON(osec.Out, &wos) == nil && len(wos) > 0 {
		visible = uint64(max(wos[0].TotalVisibleMemorySize, 0)) * 1024
	}
	s.inventoryFindings(visible, "TotalVisibleMemorySize")

	ecc, eccText, eccShort := s.eccState()
	s.facts.ECC, s.facts.ECCType, s.eccShort = ecc, eccText.EN, eccShort
	if ps != nil {
		if ecc == "none" {
			s.cov("memory.ecc", nameECC, model.CovSkipped,
				model.T("The installed RAM has no ECC, so memory errors cannot be detected.", "RAM đang lắp không có ECC nên không phát hiện được lỗi bộ nhớ."), model.Text{})
			if !s.virtual && len(s.dimms) > 0 {
				s.add(model.Finding{
					ID: "memory.no_ecc", Severity: model.Info,
					Title:  model.T("The RAM has no ECC", "RAM không có ECC"),
					Detail: noECCDetail(eccText),
					Action: model.T("For a production server, use ECC DIMMs on a board/CPU that supports ECC. Until then, run the Windows Memory Diagnostic (mdsched.exe) when you suspect RAM problems.",
						"Với máy chủ chạy thật, dùng RAM ECC trên bo mạch/CPU hỗ trợ ECC. Trong lúc chưa thay, chạy Windows Memory Diagnostic (mdsched.exe) khi nghi ngờ lỗi RAM."),
				})
			}
		} else {
			// Windows reports corrected/uncorrected memory errors as
			// WHEA-Logger events in the System log (logs domain).
			s.cov("memory.ecc", nameECC, model.CovSkipped,
				model.T("Windows has no per-DIMM ECC counters; corrected and uncorrected memory errors are WHEA-Logger events, checked in the System log section. The BMC event log names the slot.",
					"Windows không có bộ đếm lỗi ECC theo từng thanh; lỗi RAM là sự kiện WHEA-Logger, được kiểm tra ở phần System log. Log sự kiện BMC cho biết khe RAM nào."),
				model.T("Check the BMC event log (iDRAC/iLO/IPMI SEL) for memory errors.", "Xem log sự kiện BMC (iDRAC/iLO/IPMI SEL) để biết lỗi RAM."))
		}
	}

	// Usage.
	if osec != nil {
		switch {
		case len(wos) == 0 || wos[0].TotalVisibleMemorySize <= 0:
			s.cov("memory.usage", nameUsage, model.CovFailed,
				model.Tf("Win32_OperatingSystem could not be read: %s", "Không đọc được Win32_OperatingSystem: %s", firstNonEmpty(oneLine(osec.Err), osec.Missing, osec.Skipped, "no data")), model.Text{})
		default:
			o := wos[0]
			u := usage{total: visible, avail: uint64(max(o.FreePhysicalMemory, 0)) * 1024}
			if o.AvailableBytes != nil && *o.AvailableBytes > 0 {
				u.avail = uint64(*o.AvailableBytes)
			}
			if pf := b.Get("memory.win_pagefile"); pf.Ran() && collect.DecodeJSON(pf.Out, &wpf) == nil {
				for _, p := range wpf {
					u.swapTotal += uint64(max(p.AllocatedBaseSize, 0)) << 20
					u.swapUsed += uint64(max(p.CurrentUsage, 0)) << 20
				}
			}
			u.evidence = []string{
				fmt.Sprintf("TotalVisibleMemorySize %s, available %s", units.IEC(u.total), units.IEC(u.avail)),
				fmt.Sprintf("page file %s, in use %s", units.IEC(u.swapTotal), units.IEC(u.swapUsed)),
			}
			if o.CommittedBytes != nil && o.CommitLimit != nil && *o.CommitLimit > 0 {
				u.commitPct = *o.CommittedBytes * 100 / *o.CommitLimit
				u.evidence = append(u.evidence, fmt.Sprintf("committed %s of %s commit limit (%.0f%%)",
					units.IEC(uint64(*o.CommittedBytes)), units.IEC(uint64(*o.CommitLimit)), u.commitPct))
			}
			s.cov("memory.usage", nameUsage, model.CovRan, model.Text{}, model.Text{})
			s.usageFindings(u)
		}
	}

	// Windows Memory Diagnostic results stand in for memtester.
	dsec := b.Get("memory.win_memdiag")
	if dsec.Ran() {
		_ = collect.DecodeJSON(dsec.Out, &diag)
	}
	if dsec != nil || b.Get("memory.memtest") != nil {
		s.memdiag(diag, dsec)
	}
	s.tables(false)
}

// cleanWin drops the placeholders Windows/SMBIOS put in DIMM strings and
// decodes JEDEC manufacturer codes ("8A76", "80AD000080AD").
func cleanWin(v string, vendor bool) string {
	v = strings.TrimSpace(v)
	if vendor {
		return dmi.Vendor(v)
	}
	return dmi.Clean(v)
}

func (s *state) memdiag(diag []winMemDiag, sec *collect.Section) {
	var evs []MemDiagEvent
	for _, d := range diag {
		e := MemDiagEvent{ID: d.ID, Message: d.Message}
		if t, ok := collect.WinTime(d.TimeCreated); ok {
			e.Time = t
		}
		evs = append(evs, e)
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.After(evs[j].Time) })
	s.facts.MemDiag = evs
	var results []MemDiagEvent // 1101/1201 pass, 1102/1202 fail
	for _, e := range evs {
		switch e.ID {
		case 1101, 1201, 1102, 1202:
			results = append(results, e)
		}
	}
	if len(results) == 0 {
		reason := model.T("memtester is Linux-only, and the Windows Memory Diagnostic has no recorded result on this machine.",
			"memtester chỉ có trên Linux, và máy này chưa có kết quả Windows Memory Diagnostic nào.")
		if len(evs) > 0 {
			reason = model.T("The last Windows Memory Diagnostic run was cancelled or could not complete.", "Lần chạy Windows Memory Diagnostic gần nhất bị huỷ hoặc không hoàn tất.")
		}
		if sec != nil && sec.Err != "" && len(diag) == 0 {
			reason = model.Tf("The System log could not be read: %s", "Không đọc được System log: %s", oneLine(sec.Err))
		}
		s.covCmd("memory.memtest", nameMemtest, model.CovSkipped, reason,
			model.T("Run the Windows Memory Diagnostic (mdsched.exe) in a maintenance window and choose \"Restart now and check for problems\" (the server reboots and is offline during the test). Then run Diagward again to read the result.",
				"Chạy Windows Memory Diagnostic (mdsched.exe) trong giờ bảo trì, chọn \"Restart now and check for problems\" (máy sẽ khởi động lại và không phục vụ trong lúc test). Sau đó chạy lại Diagward để đọc kết quả."),
			"mdsched.exe")
		return
	}
	s.cov("memory.memtest", nameMemtest, model.CovRan, model.Text{}, model.Text{})
	last := results[0]
	when := "unknown date"
	if !last.Time.IsZero() {
		when = last.Time.UTC().Format("2006-01-02")
	}
	ev := []string{}
	for i, e := range results {
		if i == 5 {
			break
		}
		ev = append(ev, fmt.Sprintf("%s event %d: %s", e.Time.UTC().Format("2006-01-02 15:04Z"), e.ID, e.Message))
	}
	switch last.ID {
	case 1102, 1202:
		sev := model.Crit
		age := ""
		if !last.Time.IsZero() && !s.env.Now.IsZero() && s.env.Now.Sub(last.Time) > memdiagRecentDays*24*time.Hour {
			sev = model.Warn // may predate a DIMM replacement
			age = " (old result)"
		}
		s.add(model.Finding{
			ID: "memory.memdiag_errors", Severity: sev, Target: "Windows Memory Diagnostic",
			Title: model.Tf("Windows Memory Diagnostic found hardware errors in RAM (%s)%s", "Windows Memory Diagnostic phát hiện lỗi phần cứng RAM (%s)%s", when, age),
			Detail: model.Tf("The last memory test, on %s, reported hardware errors (event %d). This comes from writing and reading RAM directly at boot: a DIMM is faulty. If a DIMM was replaced after that date, run the test again to confirm.",
				"Lần test RAM gần nhất, ngày %s, báo lỗi phần cứng (sự kiện %d). Kết quả này có được khi ghi/đọc RAM trực tiếp lúc khởi động: có thanh RAM bị hỏng. Nếu đã thay RAM sau ngày đó, hãy chạy test lại để xác nhận.", when, last.ID),
			Action: model.T("Back up important data. Find the DIMM with the BMC event log or the vendor's diagnostics (Dell ePSA, HPE Insight Diagnostics, Lenovo XClarity), or test the DIMMs in halves with mdsched.exe. Replace the faulty DIMM and run the test again.",
				"Sao lưu dữ liệu quan trọng. Xác định thanh RAM lỗi qua log sự kiện BMC hoặc công cụ chẩn đoán của hãng (Dell ePSA, HPE Insight Diagnostics, Lenovo XClarity), hoặc test từng nửa số thanh bằng mdsched.exe. Thay thanh RAM lỗi rồi test lại."),
			Evidence: ev,
		})
	default:
		f := okF("memory.memdiag_ok",
			fmt.Sprintf("Windows Memory Diagnostic found no errors (last run %s)", when),
			fmt.Sprintf("Windows Memory Diagnostic không phát hiện lỗi (lần chạy gần nhất %s)", when))
		for _, e := range results[1:] {
			if e.ID == 1102 || e.ID == 1202 {
				f.Severity = model.Info
				f.ID = "memory.memdiag_past_errors"
				f.Title = model.Tf("Latest Windows Memory Diagnostic passed (%s), but an earlier run on %s found errors", "Lần test RAM gần nhất đạt (%s), nhưng lần chạy ngày %s đã phát hiện lỗi", when, e.Time.UTC().Format("2006-01-02"))
				f.Detail = model.T("If the faulty DIMM was replaced in between, this is resolved; otherwise errors can be intermittent: watch the System log for WHEA memory errors.",
					"Nếu đã thay thanh RAM lỗi giữa hai lần test thì vấn đề đã được xử lý; nếu chưa, lỗi có thể chập chờn: theo dõi lỗi WHEA về RAM trong System log.")
				f.Evidence = ev
				break
			}
		}
		s.add(f)
	}
}
