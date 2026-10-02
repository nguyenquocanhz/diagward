package raid

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// Windows Storage Spaces (Get-StoragePool, Get-VirtualDisk, Get-PhysicalDisk,
// Get-StorageJob). The collector converts enums to strings; numbers are
// mapped here in case it ran where the Storage module's type data was
// missing.

// flexStr accepts a JSON string, number or array of them.
type flexStr string

func (f *flexStr) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flexStr(s)
		return nil
	}
	var n float64
	if json.Unmarshal(b, &n) == nil {
		*f = flexStr(strconv.FormatFloat(n, 'f', -1, 64))
		return nil
	}
	var a []flexStr
	if json.Unmarshal(b, &a) == nil {
		var p []string
		for _, x := range a {
			p = append(p, string(x))
		}
		*f = flexStr(strings.Join(p, ","))
		return nil
	}
	*f = ""
	return nil
}

// flexNum accepts a JSON number or numeric string.
type flexNum uint64

func (f *flexNum) UnmarshalJSON(b []byte) error {
	var n float64
	if json.Unmarshal(b, &n) == nil && n >= 0 {
		*f = flexNum(n)
		return nil
	}
	var s string
	if json.Unmarshal(b, &s) == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err == nil {
			*f = flexNum(v)
		}
	}
	return nil
}

// SpacesPool is a Storage Spaces pool.
type SpacesPool struct {
	FriendlyName      string  `json:"FriendlyName"`
	HealthStatus      flexStr `json:"HealthStatus"`
	OperationalStatus flexStr `json:"OperationalStatus"`
	IsPrimordial      bool    `json:"IsPrimordial"`
	IsReadOnly        bool    `json:"IsReadOnly"`
	Size              flexNum `json:"Size"`
	AllocatedSize     flexNum `json:"AllocatedSize"`
}

// SpacesVDisk is a Storage Spaces virtual disk.
type SpacesVDisk struct {
	FriendlyName          string  `json:"FriendlyName"`
	ResiliencySettingName string  `json:"ResiliencySettingName"`
	HealthStatus          flexStr `json:"HealthStatus"`
	OperationalStatus     flexStr `json:"OperationalStatus"`
	DetachedReason        flexStr `json:"DetachedReason"`
	Size                  flexNum `json:"Size"`
	PoolName              string  `json:"PoolName"`
}

// SpacesPDisk is a physical disk in a Storage Spaces pool.
type SpacesPDisk struct {
	FriendlyName      string  `json:"FriendlyName"`
	SerialNumber      string  `json:"SerialNumber"`
	Model             string  `json:"Model"`
	Manufacturer      string  `json:"Manufacturer"`
	FirmwareVersion   string  `json:"FirmwareVersion"`
	MediaType         flexStr `json:"MediaType"`
	BusType           flexStr `json:"BusType"`
	HealthStatus      flexStr `json:"HealthStatus"`
	OperationalStatus flexStr `json:"OperationalStatus"`
	Usage             flexStr `json:"Usage"`
	Size              flexNum `json:"Size"`
	DeviceID          flexStr `json:"DeviceId"`
	PhysicalLocation  string  `json:"PhysicalLocation"`
	SlotNumber        flexStr `json:"SlotNumber"`
	PoolName          string  `json:"PoolName"`
}

// SpacesJob is a running storage job (repair, rebalance, ...).
type SpacesJob struct {
	Name            string  `json:"Name"`
	JobState        flexStr `json:"JobState"`
	PercentComplete flexNum `json:"PercentComplete"`
	IsBackground    bool    `json:"IsBackgroundTask"`
	BytesProcessed  flexNum `json:"BytesProcessed"`
	BytesTotal      flexNum `json:"BytesTotal"`
}

// SpacesFacts groups the Storage Spaces data.
type SpacesFacts struct {
	Pools  []SpacesPool  `json:"pools,omitempty"`
	VDisks []SpacesVDisk `json:"virtualDisks,omitempty"`
	PDisks []SpacesPDisk `json:"physicalDisks,omitempty"`
	Jobs   []SpacesJob   `json:"jobs,omitempty"`
}

// MSFT_StorageObject HealthStatus: 0 Healthy, 1 Warning, 2 Unhealthy, 5 Unknown.
func spHealth(s flexStr) string {
	switch string(s) {
	case "0":
		return "Healthy"
	case "1":
		return "Warning"
	case "2":
		return "Unhealthy"
	case "5":
		return "Unknown"
	}
	return string(s)
}

// MSFT_VirtualDisk / MSFT_PhysicalDisk OperationalStatus values (Windows
// Storage Management API docs, MSFT_VirtualDisk): 0xD002 Detached and
// 0xD003 Incomplete are Storage Spaces specific. MSFT_PhysicalDisk does not
// document its extra values, so only names written by PowerShell are matched.
var spOpNames = map[string]string{
	"0": "Unknown", "1": "Other", "2": "OK", "3": "Degraded", "4": "Stressed", "5": "Predictive Failure",
	"6": "Error", "7": "Non-Recoverable Error", "8": "Starting", "9": "Stopping", "10": "Stopped",
	"11": "In Service", "12": "No Contact", "13": "Lost Communication", "14": "Aborted", "15": "Dormant",
	"16": "Supporting Entity in Error", "17": "Completed", "18": "Power Mode",
	"19": "Relocating", "53250": "Detached", "53251": "Incomplete",
}

func spOp(s flexStr) string {
	var out []string
	for _, p := range strings.Split(string(s), ",") {
		p = strings.TrimSpace(p)
		if n, ok := spOpNames[p]; ok {
			p = n
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

// spNorm folds case and drops blanks and dashes, so the type data's display
// strings ("Lost Communication", "Read-only") and bare enum names
// ("LostCommunication", "ReadOnly") compare equal.
var spNorm = strings.NewReplacer(" ", "", "-", "", "_", "")

func hasOp(op string, names ...string) bool {
	lo := spNorm.Replace(strings.ToLower(op))
	for _, n := range names {
		if strings.Contains(lo, spNorm.Replace(strings.ToLower(n))) {
			return true
		}
	}
	return false
}

var spacesName = model.T("Storage Spaces", "Storage Spaces")

func (c *checker) checkSpaces() {
	ps := c.b.Get("raid.win_pools")
	if ps == nil || !ps.Ran() {
		return
	}
	f := &SpacesFacts{}
	var all []SpacesPool
	if err := collect.DecodeJSON(ps.Out, &all); err != nil {
		if strings.TrimSpace(ps.Out) != "" {
			c.cover("raid.spaces", spacesName, model.CovFailed, model.Tf("Get-StoragePool output unreadable: %v", "Không đọc được kết quả Get-StoragePool: %v", err), model.Text{})
		}
		return
	}
	for _, p := range all {
		if !p.IsPrimordial {
			f.Pools = append(f.Pools, p)
		}
	}
	if len(f.Pools) == 0 {
		return // Storage Spaces not in use (only the primordial pool)
	}
	_ = collect.DecodeJSON(c.sectionText("raid.win_vdisks"), &f.VDisks)
	_ = collect.DecodeJSON(c.sectionText("raid.win_pdisks"), &f.PDisks)
	_ = collect.DecodeJSON(c.sectionText("raid.win_jobs"), &f.Jobs)
	c.facts.Spaces = f

	var ok []string
	for _, p := range f.Pools {
		h, op := spHealth(p.HealthStatus), spOp(p.OperationalStatus)
		s := model.OK
		switch {
		case h == "Unhealthy" || p.IsReadOnly || hasOp(op, "read-only", "readonly"):
			s = model.Crit
		case h == "Warning" || hasOp(op, "degraded", "incomplete"):
			s = model.Warn
		}
		if s > model.OK {
			c.add(model.Finding{
				ID: "raid.spaces_pool", Severity: s, Target: p.FriendlyName,
				Title: model.Tf("Storage pool %s is %s (%s)", "Storage pool %s ở trạng thái %s (%s)", p.FriendlyName, h, op),
				Detail: model.T("The pool reports a health problem: usually a physical disk is missing, failing or retired, or the pool ran out of space for repairs.",
					"Pool báo có vấn đề: thường do một ổ vật lý bị mất, sắp hỏng hoặc đã bị retire, hoặc pool không còn đủ chỗ để tự sửa."),
				Action: model.T("Check the disks below (Get-PhysicalDisk | ? HealthStatus -ne Healthy), replace failed ones, then run Repair-VirtualDisk and watch Get-StorageJob.",
					"Kiểm tra các ổ bên dưới (Get-PhysicalDisk | ? HealthStatus -ne Healthy), thay ổ hỏng rồi chạy Repair-VirtualDisk và theo dõi Get-StorageJob."),
				Evidence: []string{fmt.Sprintf("%s HealthStatus=%s OperationalStatus=%s ReadOnly=%v", p.FriendlyName, h, op, p.IsReadOnly)},
			})
		}
		used := ""
		if p.Size > 0 {
			used = fmt.Sprintf("%.0f%% allocated", float64(p.AllocatedSize)*100/float64(p.Size))
		}
		c.arrayRow(s, p.FriendlyName, "storage pool", units.SI(uint64(p.Size)), strings.TrimSpace(h+" "+op+" "+used), "", "")
		if s == model.OK {
			ok = append(ok, p.FriendlyName)
		}
	}

	repairing := false
	for _, j := range f.Jobs {
		st := strings.ToLower(string(j.JobState))
		if (st == "running" || st == "4") && j.PercentComplete < 100 {
			n := strings.ToLower(j.Name)
			if strings.Contains(n, "repair") || strings.Contains(n, "regenerat") || strings.Contains(n, "resync") {
				repairing = true
			}
		}
	}

	for _, v := range f.VDisks {
		h, op := spHealth(v.HealthStatus), spOp(v.OperationalStatus)
		s := model.OK
		dr := strings.ToLower(strings.ReplaceAll(string(v.DetachedReason), " ", ""))
		detachedByPolicy := hasOp(op, "detached") && (dr == "bypolicy" || dr == "2") // MSFT_VirtualDisk.DetachedReason 2 = By Policy
		switch {
		case hasOp(op, "incomplete") || h == "Unhealthy" || (hasOp(op, "detached") && !detachedByPolicy):
			s = model.Crit
		case hasOp(op, "degraded"):
			s = model.Crit
			if repairing || hasOp(op, "in service") {
				s = model.Warn
			}
		case hasOp(op, "in service"):
			s = model.Warn
		case h == "Warning":
			s = model.Warn
		case detachedByPolicy:
			s = model.Info
		}
		target := v.FriendlyName
		evid := []string{fmt.Sprintf("%s Resiliency=%s HealthStatus=%s OperationalStatus=%s DetachedReason=%s", v.FriendlyName, v.ResiliencySettingName, h, op, v.DetachedReason)}
		switch {
		case s == model.Crit:
			c.add(model.Finding{
				ID: "raid.spaces_vdisk_degraded", Severity: model.Crit, Target: target,
				Title: model.Tf("Storage Spaces virtual disk %s is %s (%s)", "Ổ ảo Storage Spaces %s ở trạng thái %s (%s)", target, h, op),
				Detail: model.Tf("%s virtual disk %s has lost redundancy or is not fully available (Degraded: a copy is missing; Incomplete: too many disks are missing to read all data; Detached: it is offline).",
					"Ổ ảo %s (%s) đã mất dự phòng hoặc không còn đầy đủ (Degraded: thiếu một bản sao; Incomplete: thiếu quá nhiều ổ để đọc hết dữ liệu; Detached: đang offline).", v.ResiliencySettingName, target),
				Action: model.Tf("Back up now. Find the missing/failed disk (Get-PhysicalDisk), reconnect or replace it (Add-PhysicalDisk to the pool, then Retire and Remove the bad one), then run 'Repair-VirtualDisk -FriendlyName \"%s\"' and watch Get-StorageJob.",
					"Sao lưu ngay. Tìm ổ bị mất/hỏng (Get-PhysicalDisk), cắm lại hoặc thay ổ (Add-PhysicalDisk vào pool, rồi Retire và Remove ổ hỏng), sau đó chạy 'Repair-VirtualDisk -FriendlyName \"%s\"' và theo dõi Get-StorageJob.", target),
				Evidence: evid,
			})
		case s == model.Warn:
			c.add(model.Finding{
				ID: "raid.spaces_vdisk_repairing", Severity: model.Warn, Target: target,
				Title:    model.Tf("Storage Spaces virtual disk %s is repairing / not fully healthy (%s, %s)", "Ổ ảo Storage Spaces %s đang sửa chữa / chưa ổn hoàn toàn (%s, %s)", target, h, op),
				Detail:   model.T("Windows is regenerating the missing copies or the disk reports a warning. Redundancy is reduced until it finishes.", "Windows đang tạo lại bản sao bị thiếu hoặc ổ ảo báo cảnh báo. Mức dự phòng bị giảm cho tới khi xong."),
				Action:   model.T("Do not remove disks or restart until Get-StorageJob shows no running repair job; then check Get-VirtualDisk again.", "Không rút ổ hay khởi động lại cho tới khi Get-StorageJob không còn tác vụ sửa chữa; sau đó kiểm tra lại Get-VirtualDisk."),
				Evidence: evid,
			})
		case s == model.Info:
			c.add(model.Finding{
				ID: "raid.spaces_vdisk_detached", Severity: model.Info, Target: target,
				Title:  model.Tf("Storage Spaces virtual disk %s is detached by policy", "Ổ ảo Storage Spaces %s đang tách (detached) theo chính sách", target),
				Detail: model.T("Manual-attach virtual disks (and clustered disks owned by another node) show as detached; this is normal.", "Ổ ảo đặt chế độ gắn thủ công (hoặc ổ cluster do node khác giữ) sẽ hiện detached; điều này bình thường."),
			})
		}
		c.arrayRow(s, target, "storage space "+strings.ToLower(v.ResiliencySettingName), units.SI(uint64(v.Size)), strings.TrimSpace(h+" "+op), v.PoolName, "")
		if s == model.OK {
			ok = append(ok, target)
		}
	}

	for _, j := range f.Jobs {
		st := strings.ToLower(string(j.JobState))
		if !(st == "running" || st == "4") || j.PercentComplete >= 100 {
			continue
		}
		n := strings.ToLower(j.Name)
		s := model.Info
		if strings.Contains(n, "repair") || strings.Contains(n, "regenerat") || strings.Contains(n, "resync") {
			s = model.Warn
		}
		f := model.Finding{
			ID: "raid.spaces_job", Severity: s, Target: j.Name,
			Title:  model.Tf("Storage job %q running: %d%% done", "Tác vụ lưu trữ %q đang chạy: xong %d%%", j.Name, int(j.PercentComplete)),
			Detail: model.T("Repair/regeneration jobs rebuild redundancy; rebalance/optimize jobs only move data.", "Tác vụ Repair/Regeneration đang tạo lại dự phòng; Rebalance/Optimize chỉ di chuyển dữ liệu."),
		}
		if s == model.Warn {
			f.Action = model.T("Do not remove disks or restart until it finishes (Get-StorageJob).", "Không rút ổ hay khởi động lại cho tới khi xong (Get-StorageJob).")
		}
		c.add(f)
	}

	for _, d := range f.PDisks {
		if d.PoolName == "" {
			continue
		}
		h, op, usage := spHealth(d.HealthStatus), spOp(d.OperationalStatus), string(d.Usage)
		if usage == "4" { // MSFT_PhysicalDisk.Usage 4 = Retired
			usage = "Retired"
		}
		part := &model.Part{Kind: "disk", Vendor: strings.TrimSpace(d.Manufacturer), Model: strings.TrimSpace(firstNonEmpty(d.Model, d.FriendlyName)),
			Serial: strings.TrimSpace(d.SerialNumber), Firmware: d.FirmwareVersion, Size: units.SI(uint64(d.Size)),
			Location: strings.TrimSpace(fmt.Sprintf("pool %s, disk %s %s", d.PoolName, d.DeviceID, d.PhysicalLocation))}
		pen, pvi := partText(part)
		s := model.OK
		switch {
		case hasOp(op, "lost communication", "no contact", "failed media", "predictive failure", "io error", "not usable") || h == "Unhealthy":
			s = model.Crit
			c.add(model.Finding{
				ID: "raid.spaces_disk_failed", Severity: model.Crit, Target: firstNonEmpty(d.FriendlyName, string(d.DeviceID)),
				Title: model.Tf("Disk %s in storage pool %s: %s (%s)", "Ổ %s trong storage pool %s: %s (%s)", d.FriendlyName, d.PoolName, h, op),
				Detail: model.T("Lost Communication: the disk disappeared (cable, slot, or dead disk). Predictive Failure / Failed Media / IO Error: the disk itself is failing.",
					"Lost Communication: ổ biến mất (cáp, khe cắm, hoặc ổ chết). Predictive Failure / Failed Media / IO Error: bản thân ổ đang hỏng."),
				Action: model.Text{
					EN: fmt.Sprintf("Replace the disk%s: add the new disk to the pool (Add-PhysicalDisk), set the old one to Retired (Set-PhysicalDisk -Usage Retired), run Repair-VirtualDisk, wait for Get-StorageJob to finish, then Remove-PhysicalDisk. If it only lost communication, reseat it first.", pen),
					VI: fmt.Sprintf("Thay ổ%s: thêm ổ mới vào pool (Add-PhysicalDisk), đặt ổ cũ sang Retired (Set-PhysicalDisk -Usage Retired), chạy Repair-VirtualDisk, chờ Get-StorageJob xong rồi Remove-PhysicalDisk. Nếu chỉ mất kết nối, thử cắm lại trước.", pvi),
				},
				Evidence: []string{fmt.Sprintf("%s serial=%s Health=%s Op=%s Usage=%s", d.FriendlyName, d.SerialNumber, h, op, usage)},
				Part:     part,
			})
		case strings.EqualFold(usage, "Retired"):
			s = model.Warn
			c.add(model.Finding{
				ID: "raid.spaces_disk_retired", Severity: model.Warn, Target: firstNonEmpty(d.FriendlyName, string(d.DeviceID)),
				Title:  model.Tf("Disk %s in storage pool %s is retired", "Ổ %s trong storage pool %s đã bị retire", d.FriendlyName, d.PoolName),
				Detail: model.T("A retired disk is no longer used for new data and is waiting to be removed (usually after failures).", "Ổ đã retire không còn được dùng để ghi dữ liệu mới và đang chờ tháo ra (thường do lỗi)."),
				Action: model.Text{EN: "Run Repair-VirtualDisk, then Remove-PhysicalDisk and replace the disk" + pen + ".", VI: "Chạy Repair-VirtualDisk, sau đó Remove-PhysicalDisk và thay ổ" + pvi + "."},
				Part:   part,
			})
		case h == "Warning":
			s = model.Warn
			c.add(model.Finding{
				ID: "raid.spaces_disk_warning", Severity: model.Warn, Target: firstNonEmpty(d.FriendlyName, string(d.DeviceID)),
				Title:  model.Tf("Disk %s in storage pool %s reports a warning (%s)", "Ổ %s trong storage pool %s báo cảnh báo (%s)", d.FriendlyName, d.PoolName, op),
				Detail: model.T("Windows flags this disk as not fully healthy.", "Windows đánh dấu ổ này chưa hoàn toàn ổn."),
				Action: model.T("Check Get-StorageReliabilityCounter and the disk's S.M.A.R.T.; plan a replacement if errors grow.", "Kiểm tra Get-StorageReliabilityCounter và S.M.A.R.T. của ổ; lên kế hoạch thay nếu lỗi tăng."),
				Part:   part,
			})
		}
		c.drives = append(c.drives, model.Row{Status: s, Cells: []string{"Storage Spaces " + d.PoolName, firstNonEmpty(string(d.SlotNumber), string(d.DeviceID)), part.Model, part.Serial, part.Size, strings.TrimSpace(h + " " + op + " " + usage), "-"}})
	}

	if len(ok) > 0 {
		c.add(model.Finding{
			ID: "raid.spaces_ok", Severity: model.OK, Target: strings.Join(ok, ", "),
			Title: model.Tf("Storage Spaces healthy: %s", "Storage Spaces hoạt động tốt: %s", strings.Join(ok, ", ")),
		})
	}
	c.cover("raid.spaces", spacesName, model.CovRan, model.Text{}, model.Text{})
}
