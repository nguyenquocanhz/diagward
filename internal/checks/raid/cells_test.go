package raid

import "testing"

// membersCell translates the states a member list adds after a device
// name, and keeps everything it does not translate exactly as written:
// md's one-letter flags (F = faulty, S = spare, W = write-mostly) stay in
// upper case.
func TestMembersCell(t *testing.T) {
	for in, want := range map[string]string{
		"sda1 sdb1(F) sdc1(S)":          "sda1 sdb1(F) sdc1(S)",
		"sdd1(W) sde1(R)":               "sdd1(W) sde1(R)",
		"sda sdb(FAULTED) sdc(UNAVAIL)": "sda sdb(lỗi) sdc(không truy cập được)",
		"/dev/sda1 devid 3(MISSING)":    "/dev/sda1 devid 3(bị thiếu)",
		"32:0 32:1":                     "32:0 32:1",
		"lv_rimage_0(0),lv_rimage_1(0)": "lv_rimage_0(0),lv_rimage_1(0)",
		"/dev/loop2 [unknown]":          "/dev/loop2 [không rõ]",
		"spare-0 sdf(AVAIL)":            "spare-0 sdf(sẵn sàng)",
	} {
		if got := membersCell(in); got.EN != in || got.VI != want {
			t.Errorf("membersCell(%q) = %q, want %q", in, got.VI, want)
		}
	}
}
