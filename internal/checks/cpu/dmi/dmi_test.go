package dmi

import "testing"

func TestHelpers(t *testing.T) {
	for in, want := range map[string]uint64{"16 GB": 16 << 30, "8192 MB": 8192 << 20, "512 kB": 512 << 10, "2 TB": 2 << 40,
		"No Module Installed": 0, "Unknown": 0, "0 MB": 0, "x GB": 0} {
		if got, _ := Size(in); got != want {
			t.Errorf("Size(%q) = %d", in, got)
		}
	}
	if Speed("2933 MT/s") != 2933 || Speed("1333 MHz") != 1333 || Speed("Unknown") != 0 || Speed("") != 0 {
		t.Error("Speed")
	}
	for _, p := range []string{"Not Specified", "--", "NO DIMM", "0000000000", "FFFFFFFF", "  ", "To Be Filled By O.E.M."} {
		if Clean(p) != "" {
			t.Errorf("Clean(%q) not empty", p)
		}
	}
	if Clean(" HMA82GR7DJR4N-WM    ") != "HMA82GR7DJR4N-WM" {
		t.Error("Clean trim")
	}
	for in, want := range map[string]string{"00AD00B300AD": "SK Hynix", "80AD000080AD": "SK Hynix", "8A76": "Lexar", "Samsung": "Samsung",
		"CE00000000000000": "Samsung", "UNKNOWN": "", "HPE": "HPE"} {
		if got := Vendor(in); got != want {
			t.Errorf("Vendor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	in := "# dmidecode 3.4\nGetting SMBIOS data from sysfs.\n\nHandle 0x1100, DMI type 17, 84 bytes\nMemory Device\n\tSize: 16 GB\n\tLocator: A1\n\n" +
		"Handle 0x0400, DMI type 4, 48 bytes\nProcessor Information\n\tFlags:\n\t\tFPU (Floating-point unit on-chip)\n\t\tVME (Virtual mode extension)\n\tStatus: Populated, Enabled\n" +
		"Handle 0x0401, DMI type 4"
	r := Parse(in)
	if len(r) != 3 || r[0].Type != 17 || r[0].Get("Locator") != "A1" || r[1].Title != "Processor Information" ||
		len(r[1].Lists["Flags"]) != 2 || r[1].Get("Status") != "Populated, Enabled" || r[2].Type != 4 {
		t.Fatalf("%+v", r)
	}
	if len(OfType(r, 4)) != 2 || !NoTable("# No SMBIOS nor DMI entry point found, sorry.") {
		t.Fatal("OfType/NoTable")
	}
	Parse("Handle")
	Parse("Handle 0x, DMI type x\n\tk")
}
