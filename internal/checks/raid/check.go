// Package raid is the "raid" domain check: Linux software RAID (md), ZFS,
// Btrfs, LVM RAID, hardware RAID controllers (Broadcom/LSI storcli, Dell
// perccli, HPE ssacli, Microchip/Adaptec arcconf, legacy MegaCli) and
// Windows Storage Spaces.
//
// Severity policy (see docs/ARCHITECTURE.md): redundancy lost (degraded,
// missing or failed member, failed array) is Crit; a rebuild in progress is
// Warn (the replacement is already happening, the advice is "do not reboot
// or pull disks"); scheduled checks/scrubs are Info.
package raid

import (
	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "raid"

// Facts is the typed data this domain exposes in Result.Facts.
type Facts struct {
	MD          []*MDArray    `json:"md,omitempty"`
	ZFS         []*ZPool      `json:"zfs,omitempty"`
	Btrfs       []*BtrfsFS    `json:"btrfs,omitempty"`
	LVM         []*LVMRaid    `json:"lvm,omitempty"`
	Controllers []*Controller `json:"controllers,omitempty"`
	Detected    []DetectedHW  `json:"detectedControllers,omitempty"`
	Spaces      *SpacesFacts  `json:"storageSpaces,omitempty"`
}

type checker struct {
	b     *collect.Bundle
	env   model.Env
	res   model.Result
	facts Facts
	ids   byID

	arrays []model.Row // raid.arrays table
	drives []model.Row // raid.hw_drives table
	ctrls  []model.Row // raid.controllers table

	okMD []string
}

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	c := &checker{b: b, env: env, res: model.Result{Domain: domain}}
	c.ids = parseByID(b.Get("raid.byid"))
	c.checkMD()
	c.checkZFS()
	c.checkBtrfs()
	c.checkLVM()
	c.checkHW()
	c.checkSpaces()
	c.finish()
	return c.res
}

func (c *checker) add(f model.Finding) {
	f.Component = model.CompRAID
	c.res.Findings = append(c.res.Findings, f)
}

// cover records a coverage entry; cmd (optional) is the one copy-paste
// command that enables the check (Coverage.Cmd), which fix must not repeat.
func (c *checker) cover(id string, name model.Text, state string, reason, fix model.Text, cmd ...string) {
	cv := model.Coverage{ID: id, Component: model.CompRAID, Name: name, State: state, Reason: reason, Fix: fix}
	if len(cmd) > 0 {
		cv.Cmd = cmd[0]
	}
	c.res.Coverage = append(c.res.Coverage, cv)
}

// arrayRow adds a row to the arrays table. size, state and progress are
// strings (translated with raidWords) or Texts.
func (c *checker) arrayRow(sev model.Severity, name, typ string, size, state any, members string, progress any) {
	c.arrays = append(c.arrays, model.NewRow(sev, name, typ, stateCell(size), stateCell(state), membersCell(members), stateCell(progress)))
}

func (c *checker) finish() {
	if len(c.arrays) > 0 {
		c.res.Tables = append(c.res.Tables, model.Table{
			ID:    "raid.arrays",
			Title: model.T("RAID arrays, pools and volumes", "Mảng RAID, pool và volume"),
			Columns: []model.Text{
				model.T("Name", "Tên"), model.T("Type", "Loại"), model.T("Size", "Dung lượng"),
				model.T("State", "Trạng thái"), model.T("Members", "Thành viên"), model.T("Progress", "Tiến độ"),
			},
			Rows: c.arrays,
		})
	}
	if len(c.ctrls) > 0 {
		c.res.Tables = append(c.res.Tables, model.Table{
			ID:    "raid.controllers",
			Title: model.T("Hardware RAID controllers", "Card RAID phần cứng"),
			Columns: []model.Text{
				model.T("Controller", "Controller"), model.T("Model", "Model"), model.T("Serial", "Serial"),
				model.T("Firmware", "Firmware"), model.T("Status", "Trạng thái"), model.T("Cache / battery", "Cache / pin"),
			},
			Rows: c.ctrls,
		})
	}
	if len(c.drives) > 0 {
		c.res.Tables = append(c.res.Tables, model.Table{
			ID:    "raid.hw_drives",
			Title: model.T("Disks behind RAID controllers / in storage pools", "Ổ cứng sau card RAID / trong storage pool"),
			Columns: []model.Text{
				model.T("Controller", "Controller"), model.T("Location", "Vị trí"), model.T("Model", "Model"),
				model.T("Serial", "Serial"), model.T("Size", "Dung lượng"), model.T("State", "Trạng thái"),
				model.T("Errors", "Lỗi"),
			},
			Rows: c.drives,
		})
	}
	f := c.facts
	if len(f.MD)+len(f.ZFS)+len(f.Btrfs)+len(f.LVM)+len(f.Controllers)+len(f.Detected) > 0 || f.Spaces != nil {
		c.res.Facts = &c.facts
	}
}
