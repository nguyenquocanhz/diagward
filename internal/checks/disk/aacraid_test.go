package disk

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// Disks behind an Adaptec/Microchip controller (aacraid) read by the
// collector's probe as disk.smart:<volume>,aacraid,H,L,ID.
func TestAacraidPassthrough(t *testing.T) {
	b := linux(
		testkit.S("disk.lsblk", `{"blockdevices":[{"name":"sdb","kname":"sdb","path":"/dev/sdb","type":"disk","size":1998998994944,"rota":true,"tran":null,"model":"RAID1","serial":"8D3F1A2B","vendor":"Adaptec","rev":"V1.0","state":"running","hctl":"6:0:0:0","wwn":null,"mountpoint":null,"fstype":null,"pkname":null}]}`),
		scanOf("/dev/sdb -d scsi # /dev/sdb, SCSI device"),
		smartSec(t, "/dev/sdb,aacraid,0,0,0", "ata_hdd_wd_healthy.json", 0),
		smartSec(t, "/dev/sdb,aacraid,0,0,1", "ata_hdd_seagate_realloc304.json", 0),
		smartSec(t, "/dev/sdb,aacraid,0,0,2", "aacraid_open_failed_wsl.json", 2),
		testkit.S("disk.aacraid", "host=6 aac=0 node=present disks=0:0 1:0 2:0"),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.reallocated_sectors", model.Crit, "/dev/sdb [aacraid,0,0,1]")
	if f.Part == nil || !strings.Contains(f.Part.Location, "smartctl -d aacraid,0,0,1") || !strings.Contains(f.Part.Location, "device ID 1") {
		t.Errorf("part: %+v", f.Part)
	}
	if d := fact(t, res, "/dev/sdb [aacraid,0,0,0]"); !d.BehindRAID {
		t.Errorf("passthrough fact: %+v", d)
	}
	// The disk smartctl could not open is named in the coverage, with
	// smartctl's own message.
	c := covState(t, res, "disk.smart", model.CovPartial)
	if !strings.Contains(c.Reason.EN, "aacraid,0,0,2") {
		t.Errorf("coverage: %+v", c)
	}
}

func TestAacraidSectionName(t *testing.T) {
	dev, typ := splitSmartInstance("/dev/sdb,aacraid,0,0,2")
	if dev != "/dev/sdb" || typ != "aacraid,0,0,2" || !passthroughType(typ) || devID(typ) != "2" {
		t.Errorf("split: %q %q", dev, typ)
	}
}
