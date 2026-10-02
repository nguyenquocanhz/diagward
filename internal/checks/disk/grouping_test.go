package disk

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
)

// smartctl formats capacities and the NVMe counters with the locale's
// thousands separator (format_with_thousands_sep in utility.cpp). glibc
// locales use U+00A0 (fr_FR before glibc 2.28, ru_RU, cs_CZ...), U+202F
// (fr_FR since 2.28), U+2009, "'" or U+2019 (de_CH), "." (de_DE), "," (C/en).
// text64_sat_hdd.txt is a real output with U+00A0: the disk was shown as 2 B.

// The separators, spelled as code points so this file stays ASCII.
var (
	nbsp   = string(rune(0x00A0)) // no-break space
	nnbsp  = string(rune(0x202F)) // narrow no-break space
	thin   = string(rune(0x2009)) // thin space
	figure = string(rune(0x2007)) // figure space
	rquote = string(rune(0x2019)) // right single quotation mark (de_CH)
	arabic = string(rune(0x066C)) // Arabic thousands separator
)

// grp joins digit groups with sep: grp(nbsp, "2", "000") = "2<U+00A0>000".
func grp(sep string, groups ...string) string { return strings.Join(groups, sep) }

var twoTB = []string{"2", "000", "398", "934", "016"}

func TestTextCapacityNoBreakSpace(t *testing.T) {
	txt := testkit.Read(t, "text64_sat_hdd.txt")
	if !strings.Contains(txt, "User Capacity:    "+grp(nbsp, twoTB...)+" bytes") {
		t.Fatal("fixture no longer has U+00A0 separators")
	}
	d, ok := parseSmartText(txt)
	if !ok || d.Bytes != 2000398934016 {
		t.Fatalf("Bytes = %d, want 2000398934016", d.Bytes)
	}
	res := check(t, linux(scanOf("/dev/sg2 -d sat"), testkit.S("disk.smart:/dev/sg2", txt)), testkit.Env(collect.OSLinux))
	if f := fact(t, res, "/dev/sg2"); f.SizeBytes != 2000398934016 {
		t.Errorf("fact SizeBytes = %d", f.SizeBytes)
	}

	// The same output from other locales.
	for _, sep := range []string{nnbsp, thin, figure, " ", ",", ".", "'", rquote, arabic} {
		alt := strings.ReplaceAll(txt, nbsp, sep)
		if d, _ := parseSmartText(alt); d.Bytes != 2000398934016 {
			t.Errorf("separator %q: Bytes = %d", sep, d.Bytes)
		}
	}
}

func TestTextNVMeGroupedCounters(t *testing.T) {
	// text72 groups with "." (256.060.514.304, 5.809); a French build of
	// smartctl prints the same values with U+202F / U+00A0.
	txt := strings.NewReplacer(
		"256.060.514.304", grp(nnbsp, "256", "060", "514", "304"),
		"5.809", grp(nnbsp, "5", "809"),
		"1.356", grp(nbsp, "1", "356"),
	).Replace(testkit.Read(t, "text72_nvme_toshiba.txt"))
	if !strings.Contains(txt, grp(nnbsp, "5", "809")) || !strings.Contains(txt, grp(nbsp, "1", "356")) {
		t.Fatal("fixture edit failed")
	}
	d, _ := parseSmartText(txt)
	if d.Bytes != 256060514304 {
		t.Errorf("Bytes = %d", d.Bytes)
	}
	if d.NVMe == nil || d.NVMe.PowerOnHours == nil || *d.NVMe.PowerOnHours != 5809 ||
		d.NVMe.NumErrLogEntries == nil || *d.NVMe.NumErrLogEntries != 1356 {
		t.Errorf("nvme: %+v", d.NVMe)
	}
	res := check(t, linux(scanOf("/dev/nvme0 -d nvme"), testkit.S("disk.smart:/dev/nvme0", txt)), testkit.Env(collect.OSLinux))
	if f := fact(t, res, "/dev/nvme0"); f.SizeBytes != 256060514304 || f.PowerOnHours == nil || *f.PowerOnHours != 5809 {
		t.Errorf("fact: %+v", f)
	}
}

func TestTextAccumulatedHoursGrouped(t *testing.T) {
	// strings.Fields splits on U+00A0: the hours must not be read from the
	// last field only.
	for _, hours := range []string{"43549", grp(nbsp, "43", "549"), grp(",", "43", "549"), grp(nnbsp, "43", "549")} {
		line := "Accumulated power on time, hours:minutes " + hours + ":33"
		d, _ := parseSmartText("Vendor: HGST\nProduct: HUH721212AL5200\n" + line + "\n")
		if d.POH == nil || *d.POH != 43549 {
			t.Errorf("%q: POH = %v", line, d.POH)
		}
	}
}

func TestDigitsUintGrouping(t *testing.T) {
	cases := map[string]uint64{
		grp(nbsp, twoTB...) + " bytes":            2000398934016,
		grp(nnbsp, twoTB...):                      2000398934016,
		grp(thin, twoTB...):                       2000398934016,
		grp(figure, twoTB...):                     2000398934016,
		grp("'", twoTB...):                        2000398934016,
		grp(rquote, twoTB...):                     2000398934016,
		grp(arabic, twoTB...):                     2000398934016,
		grp(",", twoTB...):                        2000398934016,
		grp(".", twoTB...):                        2000398934016,
		grp(" ", twoTB...):                        2000398934016,
		"2 000" + nbsp + "398 934" + nbsp + "016": 2000398934016, // separators half normalised by copy/paste
		"20,00,39,89,34,016":                      2000398934016, // en_IN grouping (3;2)
		"2000398934016":                           2000398934016,
		nbsp + " 5" + nbsp + "809" + nbsp:         5809,
		"+1,234":                                  1234,
		"1.234":                                   1234, // three digits after the dot: grouping
		"1234.567":                                1234, // four digits before the dot: a decimal point
		"6311,396":                                6311, // decimal comma
		"2.5":                                     2,
		"1,234.5":                                 1234,
		"1.234,56":                                1234,
		"12 34":                                   12, // two numbers, not grouping
		"1,2345":                                  1,
		"5,809 [3 TB]":                            5809,
		"29.426.647 [15,0 TB]":                    29426647,
		"7 [x]":                                   7,
		"0":                                       0,
		"18446744073709551615":                    18446744073709551615,
	}
	for in, want := range cases {
		if got, ok := digitsUint(in); !ok || got != want {
			t.Errorf("digitsUint(%q) = %d %v, want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "abc", nbsp, ",123", "18446744073709551616", grp(nbsp, "99", "999", "999", "999", "999", "999", "999")} {
		if n, ok := digitsUint(in); ok {
			t.Errorf("digitsUint(%q) = %d, want failure", in, n)
		}
	}
	for in, want := range map[string]uint64{
		grp(nbsp, twoTB...) + " bytes [2,00 TB]":             2000398934016,
		grp(nnbsp, "256", "060", "514", "304") + " [256 GB]": 256060514304,
		"500,107,862,016 bytes":                              500107862016,
	} {
		if got, ok := capacityBytes(in); !ok || got != want {
			t.Errorf("capacityBytes(%q) = %d %v", in, got, ok)
		}
	}
}

func TestTextCapacityNarrowNoBreakSpaceSAS(t *testing.T) {
	// text71_sas_hgst.txt (real, smartctl 7.1, SAS) groups with U+202F.
	txt := testkit.Read(t, "text71_sas_hgst.txt")
	if !strings.Contains(txt, "User Capacity: "+grp(nnbsp, "12", "000", "138", "625", "024")+" bytes") {
		t.Fatal("fixture no longer has U+202F separators")
	}
	res := check(t, linux(scanOf("/dev/sdc -d scsi"), testkit.S("disk.smart:/dev/sdc", txt)), testkit.Env(collect.OSLinux))
	if f := fact(t, res, "/dev/sdc"); f.SizeBytes != 12000138625024 {
		t.Errorf("fact SizeBytes = %d, want 12000138625024", f.SizeBytes)
	}
}
