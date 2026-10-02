package memory

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

const intelCPU = "40\tprocessors\n40\tvendor_id=GenuineIntel\n40\tmodel name=Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz\n"

// withSerials gives the anonymised ("--") DIMM serials of a dmidecode
// fixture unique values, so Part assertions can be made.
func withSerials(s string) string {
	n := 0
	var b strings.Builder
	for _, l := range strings.SplitAfter(s, "\n") {
		if strings.HasPrefix(l, "\tSerial Number: --") {
			n++
			l = fmt.Sprintf("\tSerial Number: 3A2B%04d\n", n)
		}
		b.WriteString(l)
	}
	return b.String()
}

// r740 is a healthy Dell R740 (16 x 16 GiB RDIMM, ECC) running Linux.
func r740(t *testing.T, extra ...*collect.Section) *collect.Bundle {
	secs := []*collect.Section{
		testkit.S("meta.ident", "hostname=srv01\nuid=0\nuptime=864000.00\n"),
		testkit.S("cpu.cpuinfo", intelCPU),
		testkit.S("memory.dmidecode", withSerials(testkit.Read(t, "dmidecode_memory_dell_r740.txt"))),
		testkit.S("memory.meminfo", testkit.Read(t, "meminfo_r740.txt")),
		testkit.S("memory.swaps", "Filename\tType\tSize\tUsed\tPriority\n/dev/dm-1 partition\t4194300\t0\t-2\n"),
		testkit.S("memory.psi", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"),
		testkit.S("memory.vmstat", "pswpin 0\npswpout 0\npgmajfault 1234\noom_kill 0\n"),
		testkit.S("memory.edac", testkit.Read(t, "edac_skx_healthy.txt")),
		testkit.S("memory.edac_modules", "skx_edac\nedac_core\n"),
		testkit.Skipped("memory.memtest", "disabled"),
	}
	return testkit.Bundle(collect.OSLinux, append(secs, extra...)...)
}

func run(t *testing.T, b *collect.Bundle, env model.Env) model.Result {
	t.Helper()
	res := Check(b, env)
	testkit.Validate(t, res)
	if res.Domain != "memory" {
		t.Fatalf("domain %q", res.Domain)
	}
	return res
}

func worst(res model.Result) model.Severity {
	w := model.OK
	for _, f := range res.Findings {
		w = model.Worst(w, f.Severity)
	}
	return w
}

func must(t *testing.T, res model.Result, id string, sev model.Severity) *model.Finding {
	t.Helper()
	f := testkit.Find(res, id)
	if f == nil {
		t.Fatalf("missing finding %s; have %v", id, testkit.IDs(res))
	}
	if f.Severity != sev {
		t.Fatalf("%s: severity %s, want %s (%s)", id, f.Severity, sev, f.Title.EN)
	}
	return f
}

func covState(t *testing.T, res model.Result, id, state string) *model.Coverage {
	t.Helper()
	c := testkit.Cov(res, id)
	if c == nil {
		t.Fatalf("missing coverage %s", id)
	}
	if c.State != state {
		t.Fatalf("coverage %s: %s, want %s (%s)", id, c.State, state, c.Reason.EN)
	}
	return c
}

func table(res model.Result, id string) *model.Table {
	for i := range res.Tables {
		if res.Tables[i].ID == id {
			return &res.Tables[i]
		}
	}
	return nil
}

func TestHealthyServer(t *testing.T) {
	res := run(t, r740(t), testkit.Env(collect.OSLinux))
	if w := worst(res); w > model.Info {
		t.Fatalf("worst %s: %v", w, testkit.IDs(res))
	}
	must(t, res, "memory.ecc_ok", model.OK)
	must(t, res, "memory.usage_ok", model.OK)
	must(t, res, "memory.speed_below_rated", model.Info) // 2933 rated, 2666 configured
	for _, id := range []string{"memory.inventory", "memory.ecc", "memory.usage"} {
		covState(t, res, id, model.CovRan)
	}
	covState(t, res, "memory.memtest", model.CovSkipped)
	f := res.Facts.(*Facts)
	if f.ECC != "ecc" || f.InstalledBytes != 256<<30 || len(f.DIMMs) != 24 || f.DIMMs[0].Manufacturer != "SK Hynix" || f.DIMMs[0].Serial != "3A2B0001" {
		t.Fatalf("facts: ecc=%s installed=%d dimms=%d %+v", f.ECC, f.InstalledBytes, len(f.DIMMs), f.DIMMs[0])
	}
	if tb := table(res, "memory.dimms"); tb == nil || len(tb.Rows) != 24 {
		t.Fatal("dimm table")
	}
	// skx labels do not name the slots: a separate EDAC table.
	if tb := table(res, "memory.edac"); tb == nil || len(tb.Rows) != 4 {
		t.Fatal("edac table")
	}
	if table(res, "memory.summary") == nil {
		t.Fatal("summary table")
	}
}

func TestEDACJoinedToSlot(t *testing.T) {
	res := run(t, r740(t, testkit.S("memory.edac", testkit.Read(t, "edac_ghes_dell_r740.txt"))), testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.ecc_corrected", model.Info) // 5 in 2 days
	if f.Target != "B2" || f.Part == nil || f.Part.Kind != "dimm" || f.Part.Location != "B2" || f.Part.Serial == "" || f.Part.Model != "HMA82GR7DJR4N-WM" || f.Part.Size != "16 GiB" {
		t.Fatalf("target %q part %+v", f.Target, f.Part)
	}
	if table(res, "memory.edac") != nil {
		t.Fatal("joined counters need no separate EDAC table")
	}
	for _, r := range table(res, "memory.dimms").Rows {
		if r.Cells[0] == "B2" && r.Cells[7] != "5" {
			t.Fatalf("B2 row %v", r.Cells)
		}
	}
}

func TestEDACManyCorrected(t *testing.T) {
	res := run(t, r740(t, testkit.S("memory.edac", testkit.Read(t, "edac_skx_ce250.txt"))), testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.ecc_corrected", model.Warn) // 250 in 10 days
	if f.Target != "CPU_SrcID#1_MC#0_Chan#1_DIMM#0" || !strings.Contains(f.Title.EN, "25 per day") {
		t.Fatalf("target %q title %q", f.Target, f.Title.EN)
	}
	if testkit.Find(res, "memory.ecc_ok") != nil {
		t.Fatal("no OK with errors")
	}
	if !strings.Contains(f.Detail.EN, "CPU socket 1 (usually printed as CPU2 on the board), memory controller 0, channel 1") || !strings.Contains(f.Detail.VI, "socket CPU 1") {
		t.Fatalf("label not explained: %q", f.Detail.EN)
	}
}

func TestEDACUncorrected(t *testing.T) {
	res := run(t, r740(t, testkit.S("memory.edac", testkit.Read(t, "edac_skx_ue.txt"))), testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.ecc_uncorrected", model.Crit)
	if !strings.Contains(f.Action.VI, "Thay thanh RAM") || len(f.Evidence) == 0 {
		t.Fatalf("action %q evidence %v", f.Action.VI, f.Evidence)
	}
	must(t, res, "memory.ecc_corrected", model.Info)
}

func TestEDACLegacyCsrow(t *testing.T) {
	// node_exporter's fixture: csrow layout with UE and no-info counters.
	res := run(t, r740(t, testkit.S("memory.edac", testkit.Read(t, "edac_node_exporter.txt"))), testkit.Env(collect.OSLinux))
	n := 0
	for _, f := range res.Findings {
		if f.ID == "memory.ecc_uncorrected" {
			n++
			if f.Severity != model.Crit {
				t.Fatal(f.Severity)
			}
		}
	}
	if n < 3 { // channel UEs on csrow0/1, csrow2 UE, ue_noinfo
		t.Fatalf("uncorrected findings %d: %v", n, testkit.IDs(res))
	}
	mcs := res.Facts.(*Facts).EDAC
	if len(mcs) != 1 || mcs[0].UENoInfo != 6 || mcs[0].CENoInfo != 2 {
		t.Fatalf("%+v", mcs)
	}
}

func TestNoEDACDriver(t *testing.T) {
	res := run(t, r740(t, testkit.S("memory.edac", ""), testkit.S("memory.edac_modules", "")), testkit.Env(collect.OSLinux))
	c := covState(t, res, "memory.ecc", model.CovPartial)
	if !strings.Contains(c.Reason.EN, "skx_edac") || !strings.Contains(c.Reason.EN, "BMC") || !strings.Contains(c.Fix.EN, "modprobe") {
		t.Fatalf("reason %q fix %q", c.Reason.EN, c.Fix.EN)
	}
	b := r740(t, testkit.S("memory.edac", ""), testkit.S("cpu.cpuinfo", "64\tprocessors\n64\tvendor_id=AuthenticAMD\n64\tmodel name=AMD EPYC 7302 16-Core Processor\n"))
	c = covState(t, run(t, b, testkit.Env(collect.OSLinux)), "memory.ecc", model.CovPartial)
	if !strings.Contains(c.Reason.EN, "amd64_edac") || strings.Contains(c.Reason.EN, "skx") || c.Cmd != "modprobe amd64_edac" {
		t.Fatalf("reason %q cmd %q", c.Reason.EN, c.Cmd)
	}
	// Known Xeon model (Cascade Lake, family 6 model 85): one command.
	b = r740(t, testkit.S("memory.edac", ""), testkit.S("cpu.cpuinfo", intelCPU+"40\tcpu family=6\n40\tmodel=85\n"))
	c = covState(t, run(t, b, testkit.Env(collect.OSLinux)), "memory.ecc", model.CovPartial)
	if c.Cmd != "modprobe skx_edac" || !strings.Contains(c.Fix.VI, "skx_edac") || strings.Contains(c.Fix.EN, "modprobe") {
		t.Fatalf("cmd %q fix %q", c.Cmd, c.Fix.EN)
	}
	// lscpu JSON (util-linux 2.38+ nesting) of a Sapphire Rapids CPU.
	lj := `{"lscpu":[{"field":"Vendor ID:","data":"GenuineIntel","children":[{"field":"Model name:","data":"Intel(R) Xeon(R) Gold 6430","children":[{"field":"CPU family:","data":"6"},{"field":"Model:","data":"143"}]}]}]}`
	b = r740(t, testkit.S("memory.edac", ""), testkit.S("cpu.cpuinfo", ""), testkit.S("cpu.lscpu_json", lj))
	if c = covState(t, run(t, b, testkit.Env(collect.OSLinux)), "memory.ecc", model.CovPartial); c.Cmd != "modprobe i10nm_edac" {
		t.Fatalf("cmd %q", c.Cmd)
	}
}

func TestRasdaemonHistoryWithoutEDAC(t *testing.T) {
	ras := testkit.Read(t, "../../cpu/testdata/ras_errors_intel_memory.txt")
	res := run(t, r740(t, testkit.S("memory.edac", ""), testkit.S("cpu.ras_errors", ras)), testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.ras_corrected", model.Warn) // 11 in the last 24 h
	if f.Target != "CPU1_E0" || !strings.Contains(f.Title.EN, "17") {
		t.Fatalf("target %q title %q", f.Target, f.Title.EN)
	}
	if c := testkit.Cov(res, "memory.ecc"); !strings.Contains(c.Reason.EN, "rasdaemon") {
		t.Fatalf("reason %q", c.Reason.EN)
	}
	// EDAC already counts corrected errors: no duplicate.
	res = run(t, r740(t, testkit.S("memory.edac", testkit.Read(t, "edac_skx_ce250.txt")), testkit.S("cpu.ras_errors", ras)), testkit.Env(collect.OSLinux))
	if testkit.Find(res, "memory.ras_corrected") != nil {
		t.Fatal("duplicate of EDAC counters")
	}
}

func TestRasdaemonSummaryUncorrected(t *testing.T) {
	sum := "Memory controller events summary:\n\tUncorrected on DIMM Label(s): 'B2' location: 0:1:1:-1 errors: 2\n\nNo PCIe AER errors.\n"
	res := run(t, r740(t, testkit.S("memory.edac", ""), testkit.S("cpu.ras_summary", sum)), testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.ras_uncorrected", model.Warn) // no dates
	if f.Part == nil || f.Part.Location != "B2" || f.Part.Serial == "" {
		t.Fatalf("part %+v", f.Part)
	}
	// Dated and recent: Crit.
	errs := "Memory controller events:\n1 2026-09-30 10:00:00 +0000 1 Uncorrected error(s): memory read error at B2 location: 0:1:1:-1, addr 1, grain 5, syndrome 0 \n"
	res = run(t, r740(t, testkit.S("memory.edac", ""), testkit.S("cpu.ras_errors", errs)), testkit.Env(collect.OSLinux))
	must(t, res, "memory.ras_uncorrected", model.Crit)
}

func TestMcelogClient(t *testing.T) {
	cl := testkit.Read(t, "../../cpu/testdata/mcelog_client_issue16.txt")
	res := run(t, r740(t, testkit.S("memory.edac", ""), testkit.S("cpu.mcelog_client", cl)), testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.mcelog_corrected", model.Warn)
	if f.Target != "socket 1 channel 3 DIMM 0" {
		t.Fatalf("target %q", f.Target)
	}
	n := 0
	for _, f := range res.Findings {
		if f.ID == "memory.mcelog_corrected" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("aggregates must be skipped: %v", testkit.IDs(res))
	}
}

func TestNonECCDesktop(t *testing.T) {
	b := r740(t, testkit.S("memory.dmidecode", testkit.Read(t, "dmidecode_memory_optiplex7070.txt")),
		testkit.S("memory.meminfo", testkit.Read(t, "meminfo_wsl.txt")), testkit.S("memory.edac", ""))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.no_ecc", model.Info)
	if !strings.Contains(f.Detail.EN, "64-bit") {
		t.Fatalf("detail %q", f.Detail.EN)
	}
	covState(t, res, "memory.ecc", model.CovSkipped)
	if res.Facts.(*Facts).DIMMs[0].Manufacturer != "SK Hynix" {
		t.Fatal("JEDEC 80AD not decoded")
	}
}

func TestCapacityMissing(t *testing.T) {
	res := run(t, r740(t, testkit.S("memory.meminfo", testkit.Read(t, "meminfo_r740_one_dimm_missing.txt"))), testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.capacity_missing", model.Warn)
	if !strings.Contains(f.Title.EN, "256 GiB installed") {
		t.Fatalf("title %q", f.Title.EN)
	}
	// Without EDAC the same gap (one of 16 DIMMs) is still a Warn.
	res = run(t, r740(t, testkit.S("memory.meminfo", testkit.Read(t, "meminfo_r740_one_dimm_missing.txt")), testkit.S("memory.edac", "")), testkit.Env(collect.OSLinux))
	must(t, res, "memory.capacity_missing", model.Warn)
}

// skxDump synthesizes a skx_edac sysfs dump with n healthy 16 GiB DIMMs.
func skxDump(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		mc, d := i/6, i%6
		if d == 0 {
			fmt.Fprintf(&b, "/sys/devices/system/edac/mc/mc%d/mc_name=Skylake Socket#%d IMC#%d\n/sys/devices/system/edac/mc/mc%d/seconds_since_reset=864000\n/sys/devices/system/edac/mc/mc%d/ce_count=0\n/sys/devices/system/edac/mc/mc%d/ue_count=0\n", mc, mc/2, mc%2, mc, mc, mc)
		}
		p := fmt.Sprintf("/sys/devices/system/edac/mc/mc%d/dimm%d/", mc, d)
		fmt.Fprintf(&b, "%sdimm_label=CPU_SrcID#%d_MC#%d_Chan#%d_DIMM#0\n%ssize=16384\n%sdimm_mem_type=Registered-DDR4\n%sdimm_ce_count=0\n%sdimm_ue_count=0\n", p, mc/2, mc%2, d, p, p, p, p)
	}
	return b.String()
}

// meminfoTotal is /proc/meminfo with MemTotal kB and plenty available.
func meminfoTotal(kb uint64) string {
	return fmt.Sprintf("MemTotal:       %d kB\nMemFree:        %d kB\nMemAvailable:   %d kB\nSwapTotal:      4194300 kB\nSwapFree:       4194300 kB\n", kb, kb/2, kb/2)
}

func TestMirroringIsNotAMissingDIMM(t *testing.T) {
	// 16 x 16 GiB in full mirroring mode: the OS sees half, minus the usual
	// firmware/kernel reservations (here 125.7 of 128 GiB).
	half := meminfoTotal(131800000)
	// The memory controller has all 16 DIMMs: certain, nothing to replace.
	res := run(t, r740(t, testkit.S("memory.meminfo", half), testkit.S("memory.edac", skxDump(16))), testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.capacity_reserved", model.Info)
	if !strings.Contains(f.Detail.EN, "all 16 DIMMs") || !strings.Contains(f.Action.VI, "Memory Operating Mode") {
		t.Fatalf("%q / %q", f.Detail.EN, f.Action.VI)
	}
	if testkit.Find(res, "memory.capacity_missing") != nil {
		t.Fatal("no missing-capacity finding with every DIMM in use")
	}
	// No native EDAC driver: ambiguous, Info with the BIOS check first.
	res = run(t, r740(t, testkit.S("memory.meminfo", half), testkit.S("memory.edac", "")), testkit.Env(collect.OSLinux))
	f = must(t, res, "memory.capacity_missing", model.Info)
	if !strings.Contains(f.Detail.EN, "mirroring") {
		t.Fatal(f.Detail.EN)
	}
	// The memory controller sees only 8 of 16: DIMMs are really missing.
	res = run(t, r740(t, testkit.S("memory.meminfo", half), testkit.S("memory.edac", skxDump(8))), testkit.Env(collect.OSLinux))
	f = must(t, res, "memory.capacity_missing", model.Warn)
	if !strings.Contains(f.Detail.EN, "uses only 8") || !strings.Contains(f.Detail.VI, "chỉ dùng 8 thanh") {
		t.Fatal(f.Detail.EN)
	}
}

func TestOptaneAppDirect(t *testing.T) {
	// Real Supermicro SYS-1029U-TRT: 12 x 32 GB DRAM + 8 x 126 GB Optane
	// PMem in App Direct mode ("Volatile Size: None"). The OS sees only the
	// DRAM (synthesized MemTotal ~376.7 GiB of 384 GiB).
	b := r740(t, testkit.S("memory.dmidecode", testkit.Read(t, "dmidecode_memory_supermicro_1029u_optane.txt")),
		testkit.S("memory.meminfo", meminfoTotal(395000000)), testkit.S("memory.edac", ""))
	res := run(t, b, testkit.Env(collect.OSLinux))
	for _, id := range []string{"memory.capacity_missing", "memory.mixed_dimms"} {
		if f := testkit.Find(res, id); f != nil {
			t.Errorf("PMem is not missing or mismatched RAM: %s %q", id, f.Detail.EN)
		}
	}
	f := res.Facts.(*Facts)
	pm := 0
	for _, d := range f.DIMMs {
		if d.PMem {
			pm++
			if d.Type != "Optane PMem" || d.VolatileBytes != 0 || d.SizeBytes != 129408<<20 {
				t.Fatalf("%+v", d)
			}
		}
	}
	if pm != 8 || f.ECC != "ecc" {
		t.Fatalf("pmem %d ecc %s", pm, f.ECC)
	}
	// A real missing DRAM DIMM is still found next to PMem.
	b = r740(t, testkit.S("memory.dmidecode", testkit.Read(t, "dmidecode_memory_supermicro_1029u_optane.txt")),
		testkit.S("memory.meminfo", meminfoTotal(360000000)), testkit.S("memory.edac", ""))
	must(t, run(t, b, testkit.Env(collect.OSLinux)), "memory.capacity_missing", model.Warn)
}

func TestNonSystemArrayIgnored(t *testing.T) {
	// A flash array's device (Use: Flash Memory) is not a DIMM.
	flash := "Handle 0x0100, DMI type 16, 23 bytes\nPhysical Memory Array\n\tLocation: System Board Or Motherboard\n\tUse: Flash Memory\n\tError Correction Type: None\n\tMaximum Capacity: 16 MB\n\tNumber Of Devices: 1\n\n" +
		"Handle 0x0101, DMI type 17, 40 bytes\nMemory Device\n\tArray Handle: 0x0100\n\tTotal Width: 8 bits\n\tData Width: 8 bits\n\tSize: 16 MB\n\tForm Factor: Chip\n\tLocator: SPI\n\tType: Flash\n\n"
	b := r740(t, testkit.S("memory.dmidecode", withSerials(testkit.Read(t, "dmidecode_memory_dell_r740.txt"))+"\n"+flash))
	res := run(t, b, testkit.Env(collect.OSLinux))
	if f := res.Facts.(*Facts); len(f.DIMMs) != 24 || f.ECC != "ecc" {
		t.Fatalf("dimms %d ecc %s", len(f.DIMMs), f.ECC)
	}
	if testkit.Find(res, "memory.mixed_dimms") != nil {
		t.Fatal("flash chip counted as a DIMM")
	}
}

func TestOtherServers(t *testing.T) {
	cases := map[string]string{
		"dmidecode_memory_hpe_dl380g10.txt":     "",
		"dmidecode_memory_supermicro_6029p.txt": "memory.speed_below_rated",
		"dmidecode_memory_hp_dl360g8.txt":       "",
	}
	for fx, want := range cases {
		b := r740(t, testkit.S("memory.dmidecode", testkit.Read(t, fx)), testkit.S("memory.meminfo", ""), testkit.S("memory.edac", testkit.Read(t, "edac_skx_healthy.txt")))
		res := run(t, b, testkit.Env(collect.OSLinux))
		if w := worst(res); w > model.Info {
			t.Errorf("%s: worst %s %v", fx, w, testkit.IDs(res))
		}
		if res.Facts.(*Facts).ECC != "ecc" {
			t.Errorf("%s: ECC %q", fx, res.Facts.(*Facts).ECC)
		}
		if want != "" && testkit.Find(res, want) == nil {
			t.Errorf("%s: missing %s: %v", fx, want, testkit.IDs(res))
		}
	}
	// Old dmidecode format (8192 MB, "Configured Clock Speed").
	_, d := dmiMemory(testkit.Read(t, "dmidecode_memory_hp_dl360g8.txt"))
	pop := 0
	for _, x := range d {
		if x.Populated {
			pop++
			if x.SizeBytes != 8<<30 || x.SpeedMT != 1333 || x.ConfiguredMT != 1333 || x.PartNumber != "647650-071" {
				t.Fatalf("%+v", x)
			}
		}
	}
	if pop != 8 {
		t.Fatal(pop)
	}
}

func TestVirtualMachines(t *testing.T) {
	for fx, virt := range map[string]string{"dmidecode_memory_vmware.txt": "vmware", "dmidecode_memory_qemu.txt": "kvm"} {
		env := testkit.Env(collect.OSLinux)
		env.Virtual = virt
		b := r740(t, testkit.S("memory.dmidecode", testkit.Read(t, fx)), testkit.S("memory.edac", ""), testkit.S("memory.meminfo", testkit.Read(t, "meminfo_wsl.txt")))
		res := run(t, b, env)
		if w := worst(res); w > model.OK {
			t.Errorf("%s: %v", fx, testkit.IDs(res))
		}
		covState(t, res, "memory.ecc", model.CovSkipped)
		if tb := table(res, "memory.dimms"); tb != nil {
			for _, r := range tb.Rows {
				if r.Cells[9] == "empty" {
					t.Fatalf("%s: empty VM slots shown", fx)
				}
			}
		}
	}
}

func TestPressure(t *testing.T) {
	b := r740(t, testkit.S("memory.meminfo", testkit.Read(t, "meminfo_pressure.txt")),
		testkit.S("memory.psi", testkit.Read(t, "psi_memory_high.txt")),
		testkit.S("memory.vmstat", "pswpin 812345\npswpout 1534567\noom_kill 3\n"),
		testkit.S("memory.dmidecode", ""))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "memory.pressure", model.Warn)
	if !strings.Contains(f.Detail.EN, "not a hardware fault") || !strings.Contains(f.Detail.VI, "không phải lỗi phần cứng") || !strings.Contains(f.Detail.EN, "OOM killer ran 3") {
		t.Fatalf("detail %q", f.Detail.EN)
	}
	// PSI alone, with plenty of free RAM: a cgroup limit.
	b = r740(t, testkit.S("memory.psi", testkit.Read(t, "psi_memory_high.txt")))
	f = must(t, run(t, b, testkit.Env(collect.OSLinux)), "memory.pressure", model.Warn)
	if !strings.Contains(f.Title.EN, "although") || !strings.Contains(f.Detail.EN, "cgroup") {
		t.Fatalf("title %q", f.Title.EN)
	}
	// Low but no swapping and no stalls: Info.
	low := "MemTotal: 32779464 kB\nMemAvailable: 1903456 kB\nSwapTotal: 8388604 kB\nSwapFree: 8388604 kB\n"
	must(t, run(t, r740(t, testkit.S("memory.meminfo", low)), testkit.Env(collect.OSLinux)), "memory.low_available", model.Info)
	// OOM since boot only.
	must(t, run(t, r740(t, testkit.S("memory.vmstat", "oom_kill 2\n")), testkit.Env(collect.OSLinux)), "memory.oom_kills", model.Info)
	// Kernel without MemAvailable (CentOS 6): estimated, still fine.
	old := "MemTotal: 8000000 kB\nMemFree: 4000000 kB\nBuffers: 100000 kB\nCached: 2000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
	must(t, run(t, r740(t, testkit.S("memory.meminfo", old), testkit.S("memory.dmidecode", "")), testkit.Env(collect.OSLinux)), "memory.usage_ok", model.OK)
}

func TestHardwareCorrupted(t *testing.T) {
	mi := strings.Replace(testkit.Read(t, "meminfo_r740.txt"), "HardwareCorrupted:     0 kB", "HardwareCorrupted:     8 kB", 1)
	f := must(t, run(t, r740(t, testkit.S("memory.meminfo", mi)), testkit.Env(collect.OSLinux)), "memory.pages_retired", model.Warn)
	if !strings.Contains(f.Title.EN, "8 KiB") {
		t.Fatalf("title %q", f.Title.EN)
	}
}

func TestMemtest(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	res := run(t, r740(t, testkit.S("memory.memtest", testkit.Read(t, "memtest_ok_ubuntu.txt"))), env)
	f := must(t, res, "memory.memtest_ok", model.OK)
	if !strings.Contains(f.Title.EN, "16 MiB tested, 18 tests") || strings.Contains(f.Title.EN, "not locked") {
		t.Fatalf("title %q", f.Title.EN)
	}
	covState(t, res, "memory.memtest", model.CovRan)

	sec := testkit.S("memory.memtest", testkit.Read(t, "memtest_unlocked_nonroot.txt"))
	sec.Err = testkit.Read(t, "memtest_unlocked_nonroot.err")
	f = must(t, run(t, r740(t, sec), env), "memory.memtest_ok", model.OK)
	if !strings.Contains(f.Title.EN, "not locked") || !strings.Contains(f.Title.VI, "không khoá") {
		t.Fatalf("title %q", f.Title.EN)
	}

	sec = testkit.RC("memory.memtest", 4, testkit.Read(t, "memtest_failure.txt"), testkit.Read(t, "memtest_failure.err"))
	res = run(t, r740(t, sec), env)
	f = must(t, res, "memory.memtest_failed", model.Crit)
	if !strings.Contains(f.Title.EN, "Compare XOR, Bit Flip failed") || len(f.Evidence) != 4 || !strings.Contains(f.Target, "8 GiB") {
		t.Fatalf("title %q target %q evidence %v", f.Title.EN, f.Target, f.Evidence)
	}
	m := res.Facts.(*Facts).Memtest
	if len(m.Passed) != 16 || len(m.Failed) != 2 {
		t.Fatalf("%+v", m)
	}

	sec = testkit.RC("memory.memtest", 124, testkit.Read(t, "memtest_timeout.txt"), "")
	sec.Timeout = true
	res = run(t, r740(t, sec), env)
	must(t, res, "memory.memtest_incomplete", model.Info)
	covState(t, res, "memory.memtest", model.CovPartial)
	if testkit.Find(res, "memory.memtest_failed") != nil {
		t.Fatal("a timeout is not a failure")
	}
	// Killed by a signal after 40 s of a 900 s limit: the OOM killer, not
	// the time limit.
	sec = testkit.RC("memory.memtest", 137, strings.Replace(testkit.Read(t, "memtest_timeout.txt"), "diagward: rc=124", "diagward: rc=137", 1), "")
	sec.MS = 40000
	res = run(t, r740(t, sec), env)
	if f := must(t, res, "memory.memtest_incomplete", model.Info); !strings.Contains(f.Detail.EN, "OOM killer") || !strings.Contains(f.Title.VI, "40 giây") {
		t.Fatalf("%q / %q", f.Title.VI, f.Detail.EN)
	}

	for reason, state := range map[string]string{"disabled": model.CovSkipped, "low-memory": model.CovSkipped, "not-root": model.CovSkipped, "container": model.CovSkipped} {
		c := covState(t, run(t, r740(t, testkit.Skipped("memory.memtest", reason)), env), "memory.memtest", state)
		if c.Reason.EN == "" || c.Reason.VI == "" {
			t.Fatal(reason)
		}
	}
	c := covState(t, run(t, r740(t, testkit.Missing("memory.memtest", "memtester")), env), "memory.memtest", model.CovSkipped)
	if !strings.Contains(c.Fix.EN, "EPEL") || c.Cmd != "dnf install -y epel-release && dnf install -y memtester" {
		t.Fatalf("fix %q cmd %q", c.Fix.EN, c.Cmd)
	}
	// Not requested: the coverage names the real CLI flag.
	c = covState(t, run(t, r740(t, testkit.Skipped("memory.memtest", "disabled")), env), "memory.memtest", model.CovSkipped)
	if c.Cmd != "diagward check --memtest 2G" || strings.Contains(c.Fix.EN, "diagward check") {
		t.Fatalf("cmd %q fix %q", c.Cmd, c.Fix.EN)
	}
	user := env
	user.Root = false
	c = covState(t, run(t, r740(t, testkit.Skipped("memory.memtest", "disabled")), user), "memory.memtest", model.CovSkipped)
	if c.Cmd != "sudo diagward check --memtest 2G" {
		t.Fatalf("cmd %q", c.Cmd)
	}
	// Too little free RAM: a size that fits (a quarter of MemAvailable).
	c = covState(t, run(t, r740(t, testkit.Skipped("memory.memtest", "low-memory"), testkit.S("memory.meminfo", meminfoTotal(8388608))), env), "memory.memtest", model.CovSkipped)
	if c.Cmd != "diagward check --memtest 1024M" {
		t.Fatalf("cmd %q", c.Cmd)
	}
	sec = testkit.RC("memory.memtest", 1, "diagward: size=1G\nmemtester version 4.5.1 (64-bit)\nwant 1024MB (1073741824 bytes)\ndiagward: rc=1\n", "failed to allocate memory")
	covState(t, run(t, r740(t, sec), env), "memory.memtest", model.CovFailed)
}

func TestNotRootAndContainer(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	res := run(t, r740(t, testkit.Skipped("memory.dmidecode", "not-root")), env)
	c := covState(t, res, "memory.inventory", model.CovSkipped)
	if !strings.Contains(c.Fix.EN, "sudo") {
		t.Fatal(c.Fix.EN)
	}
	env = testkit.Env(collect.OSLinux)
	env.Virtual, env.Container = "lxc", true
	b := testkit.Bundle(collect.OSLinux, testkit.Skipped("memory.dmidecode", "container"), testkit.Skipped("memory.edac", "container"),
		testkit.S("memory.meminfo", testkit.Read(t, "meminfo_wsl.txt")), testkit.Skipped("memory.memtest", "disabled"))
	res = run(t, b, env)
	covState(t, res, "memory.inventory", model.CovSkipped)
	covState(t, res, "memory.ecc", model.CovSkipped)
	covState(t, res, "memory.usage", model.CovRan)
	if w := worst(res); w > model.OK {
		t.Fatalf("%v", testkit.IDs(res))
	}
	// dmidecode missing.
	c = covState(t, run(t, r740(t, testkit.Missing("memory.dmidecode", "dmidecode")), testkit.Env(collect.OSLinux)), "memory.inventory", model.CovSkipped)
	if !strings.Contains(c.Fix.EN, "dmidecode") {
		t.Fatal(c.Fix.EN)
	}
}

func win(t *testing.T, extra ...*collect.Section) *collect.Bundle {
	secs := []*collect.Section{
		testkit.S("memory.win_physical", testkit.Read(t, "win_physical_server_r740.json")),
		testkit.S("memory.win_array", testkit.Read(t, "win_array_server_r740.json")),
		testkit.S("memory.win_os", testkit.Read(t, "win_os_server_r740.json")),
		testkit.S("memory.win_pagefile", `[{"Name":"C:\\pagefile.sys","AllocatedBaseSize":17408,"CurrentUsage":120,"PeakUsage":300}]`),
		testkit.S("memory.win_memdiag", "[]"),
	}
	return testkit.Bundle(collect.OSWindows, append(secs, extra...)...)
}

func TestWindowsServer(t *testing.T) {
	env := testkit.Env(collect.OSWindows)
	res := run(t, win(t), env)
	if w := worst(res); w > model.Info {
		t.Fatalf("%v", testkit.IDs(res))
	}
	must(t, res, "memory.usage_ok", model.OK)
	covState(t, res, "memory.inventory", model.CovRan)
	c := covState(t, res, "memory.ecc", model.CovSkipped)
	if !strings.Contains(c.Reason.EN, "WHEA") {
		t.Fatal(c.Reason.EN)
	}
	m := covState(t, res, "memory.memtest", model.CovSkipped)
	if !strings.Contains(m.Fix.EN, "mdsched.exe") {
		t.Fatal(m.Fix.EN)
	}
	f := res.Facts.(*Facts)
	if f.ECC != "ecc" || f.InstalledBytes != 256<<30 || f.DIMMs[0].Manufacturer != "SK Hynix" || f.DIMMs[0].Type != "DDR4" || f.DIMMs[0].FormFactor != "DIMM" {
		t.Fatalf("%+v", f.DIMMs[0])
	}

	res = run(t, win(t, testkit.S("memory.win_os", testkit.Read(t, "win_os_server_r740_missing.json"))), env)
	must(t, res, "memory.capacity_missing", model.Warn)

	res = run(t, win(t, testkit.S("memory.win_os", testkit.Read(t, "win_os_pressure.json")),
		testkit.S("memory.win_pagefile", testkit.Read(t, "win_pagefile_pressure.json")),
		testkit.S("memory.win_physical", "[]")), env)
	f2 := must(t, res, "memory.pressure", model.Warn)
	if !strings.Contains(f2.Detail.EN, "commit limit") {
		t.Fatal(f2.Detail.EN)
	}
}

func TestWindowsLaptopRealData(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows,
		testkit.S("memory.win_physical", testkit.Read(t, "win_physical_laptop.json")),
		testkit.S("memory.win_array", testkit.Read(t, "win_array_laptop.json")),
		testkit.S("memory.win_os", testkit.Read(t, "win_os_laptop.json")),
		testkit.S("memory.win_pagefile", testkit.Read(t, "win_pagefile_laptop.json")),
		testkit.S("memory.win_memdiag", "[]"))
	res := run(t, b, testkit.Env(collect.OSWindows))
	ne := must(t, res, "memory.no_ecc", model.Info)
	mx := must(t, res, "memory.mixed_dimms", model.Info)
	// Vietnamese texts must not fall back to English sentences.
	for _, vi := range []string{ne.Detail.VI, mx.Detail.VI} {
		for _, en := range []string{"Error correction type", "modules are", "without ECC bits", "part numbers ", "sizes ", "speeds "} {
			if strings.Contains(vi, en) {
				t.Errorf("English %q in VI text: %q", en, vi)
			}
		}
	}
	if !strings.Contains(ne.Detail.VI, "không có bit ECC") || !strings.Contains(mx.Detail.VI, "mã linh kiện") {
		t.Fatalf("%q / %q", ne.Detail.VI, mx.Detail.VI)
	}
	if c := covState(t, res, "memory.memtest", model.CovSkipped); c.Cmd != "mdsched.exe" {
		t.Fatalf("cmd %q", c.Cmd)
	}
	must(t, res, "memory.speed_below_rated", model.Info)
	must(t, res, "memory.usage_ok", model.OK)
	if d := res.Facts.(*Facts).DIMMs; d[1].Manufacturer != "Lexar" || d[0].PartNumber != "HMA81GS6DJR8N-XN" || d[0].FormFactor != "SODIMM" {
		t.Fatalf("%+v", d)
	}
}

func TestWindowsMemDiag(t *testing.T) {
	env := testkit.Env(collect.OSWindows)
	res := run(t, win(t, testkit.S("memory.win_memdiag", testkit.Read(t, "win_memdiag_errors.json"))), env)
	f := must(t, res, "memory.memdiag_errors", model.Crit)
	if !strings.Contains(f.Title.EN, "2026-09-25") {
		t.Fatal(f.Title.EN)
	}
	covState(t, res, "memory.memtest", model.CovRan)

	old := env
	old.Now = time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	must(t, run(t, win(t, testkit.S("memory.win_memdiag", testkit.Read(t, "win_memdiag_errors.json"))), old), "memory.memdiag_errors", model.Warn)

	must(t, run(t, win(t, testkit.S("memory.win_memdiag", testkit.Read(t, "win_memdiag_fixed.json"))), env), "memory.memdiag_past_errors", model.Info)

	c := covState(t, run(t, win(t, testkit.S("memory.win_memdiag", testkit.Read(t, "win_memdiag_cancelled.json"))), env), "memory.memtest", model.CovSkipped)
	if !strings.Contains(c.Reason.EN, "cancelled") {
		t.Fatal(c.Reason.EN)
	}
	ok := `[{"Id":1101,"Level":4,"TimeCreated":"2026-09-01T00:00:00Z","Message":"no errors"}]`
	must(t, run(t, win(t, testkit.S("memory.win_memdiag", ok)), env), "memory.memdiag_ok", model.OK)
}

func TestEmptyAndForeign(t *testing.T) {
	res := run(t, testkit.Bundle(collect.OSLinux), testkit.Env(collect.OSLinux))
	if len(res.Findings)+len(res.Coverage)+len(res.Tables) != 0 {
		t.Fatalf("%+v", res)
	}
	res = run(t, testkit.Bundle(collect.OSBMC, testkit.S("redfish.memory", "{}")), testkit.Env(collect.OSBMC))
	if len(res.Coverage) != 0 {
		t.Fatal("bmc")
	}
}

func TestGarbage(t *testing.T) {
	names := []string{"memory.dmidecode", "memory.meminfo", "memory.swaps", "memory.psi", "memory.vmstat", "memory.edac",
		"memory.edac_modules", "memory.memtest", "cpu.ras_errors", "cpu.ras_summary", "cpu.mcelog_client", "cpu.cpuinfo"}
	winNames := []string{"memory.win_physical", "memory.win_array", "memory.win_os", "memory.win_pagefile", "memory.win_memdiag"}
	fixtures := []string{"dmidecode_memory_dell_r740.txt", "edac_node_exporter.txt", "memtest_failure.txt", "meminfo_pressure.txt",
		"win_physical_server_r740.json", "win_memdiag_errors.json", "edac_ghes_dell_r740.txt"}
	rng := rand.New(rand.NewSource(7))
	for _, fx := range fixtures {
		data := testkit.Read(t, fx)
		for i := 0; i < 30; i++ {
			cut := data[:rng.Intn(len(data)+1)]
			var secs, wsecs []*collect.Section
			for _, n := range names {
				secs = append(secs, testkit.S(n, cut))
			}
			for _, n := range winNames {
				wsecs = append(wsecs, testkit.S(n, cut))
			}
			run(t, testkit.Bundle(collect.OSLinux, secs...), testkit.Env(collect.OSLinux))
			run(t, testkit.Bundle(collect.OSWindows, wsecs...), testkit.Env(collect.OSWindows))
		}
	}
	junk := make([]byte, 4096)
	for i := 0; i < 50; i++ {
		rng.Read(junk)
		var secs []*collect.Section
		for _, n := range append(names, winNames...) {
			secs = append(secs, testkit.S(n, string(junk[:rng.Intn(len(junk))])))
		}
		run(t, testkit.Bundle(collect.OSLinux, secs...), testkit.Env(collect.OSLinux))
		run(t, testkit.Bundle(collect.OSWindows, secs...), testkit.Env(collect.OSWindows))
	}
	run(t, testkit.Bundle(collect.OSLinux,
		testkit.S("memory.meminfo", "MemTotal: 18446744073709551615 kB\nSwapTotal: 1 kB\nSwapFree: 99 kB\n"),
		testkit.S("memory.edac", "/sys/devices/system/edac/mc/mc0/dimm0/dimm_ce_count=-5\n/sys/devices/system/edac/mc/mc0/seconds_since_reset=99999999999999999999\n"),
		testkit.S("memory.psi", "some avg10=NaN avg60=1e309 avg300=-1\n")), testkit.Env(collect.OSLinux))
	run(t, testkit.Bundle(collect.OSWindows,
		testkit.S("memory.win_physical", `[{"Capacity":-1,"Speed":-5},{"Capacity":1e30}]`),
		testkit.S("memory.win_os", `[{"TotalVisibleMemorySize":-1,"CommitLimit":0,"CommittedBytes":5}]`)), testkit.Env(collect.OSWindows))
}
