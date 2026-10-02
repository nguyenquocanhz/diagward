package logs

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/model"
)

var (
	reWord = regexp.MustCompile(`[\p{L}\p{N}]+`)
	// English words that must not appear in Vietnamese text (commands and
	// established terms such as RAID, firmware, rebuild are fine).
	reENinVI = regexp.MustCompile(`(?i)\b(the|is|are|was|were|and|of|with|this|that|usually|times?|seen|between)\b`)
)

// dupWord returns the first word repeated right after itself ("do do",
// "the the", "thường do thường do"), or "".
func dupWord(s string) string {
	for _, part := range regexp.MustCompile(`[.;:!?,()/]`).Split(strings.ToLower(s), -1) {
		ws := reWord.FindAllString(part, -1)
		for i := 1; i < len(ws); i++ {
			if ws[i] == ws[i-1] && len([]rune(ws[i])) > 1 {
				return ws[i] + " " + ws[i]
			}
			if i >= 3 && ws[i] == ws[i-2] && ws[i-1] == ws[i-3] {
				return ws[i-1] + " " + ws[i] + " " + ws[i-1] + " " + ws[i]
			}
		}
	}
	return ""
}

// stripCode drops commands and paths from a text before the language checks.
var reCode = regexp.MustCompile(`\b(?:journalctl|smartctl|mdadm|lspci|ethtool|edac-util|ras-mc-ctl|mcelog|ipmitool|dmidecode|fsck|xfs_repair|btrfs|chkdsk|Repair-Volume|Get-\w+|storcli|perccli|ssacli|sas3ircu|iostat|free|ps|cat|sort|uniq|head|diagward)\b[^.;,)]*|"[^"]*"|\([^)]*\)|\S+\.(?:txt|DMP|dwb)|/\S+|[A-Z]:\\S*`)

func checkText(t *testing.T, where string, x model.Text) {
	t.Helper()
	for _, s := range []string{x.EN, x.VI} {
		if strings.Contains(s, "%!") || strings.Contains(s, "(s)") || strings.Contains(s, "{t}") || strings.Contains(s, "{n}") {
			t.Errorf("%s: formatting leftover in %q", where, s)
		}
		if d := dupWord(s); d != "" {
			t.Errorf("%s: duplicated words %q in %q", where, d, s)
		}
		if strings.Contains(s, "..") && !strings.Contains(s, "...") {
			t.Errorf("%s: double full stop in %q", where, s)
		}
	}
	if m := reENinVI.FindString(reCode.ReplaceAllString(x.VI, "")); m != "" {
		t.Errorf("%s: English word %q left in Vietnamese: %q", where, m, x.VI)
	}
}

func checkTexts(t *testing.T, res model.Result) {
	t.Helper()
	for _, f := range res.Findings {
		w := f.ID + "@" + f.Target
		checkText(t, w+" title", f.Title)
		checkText(t, w+" detail", f.Detail)
		checkText(t, w+" action", f.Action)
	}
	for _, c := range res.Coverage {
		checkText(t, c.ID+" name", c.Name)
		if !strings.Contains(c.Reason.EN, ": ") { // reasons may quote raw stderr
			checkText(t, c.ID+" reason", c.Reason)
		}
		checkText(t, c.ID+" fix", c.Fix)
	}
}

// Every static text of the domain, not only those the fixtures reach.
func TestStaticTexts(t *testing.T) {
	var specs []*spec
	for _, r := range rules {
		specs = append(specs, r.sp)
	}
	specs = append(specs, wsBadBlock, wsSmart, wsHWFail, wsPaging, wsCtrlErr, wsRetried, wsNotReady, wsReset,
		wsNtfsCorrupt, wsNtfsChkdsk, wsNtfsWarn, wsDump, wsThrottle, wsLowMem, wsWHEAFatal, wsWHEACorr, wsWHEAPCIe, wsNICDown, wsNICReset)
	for _, sp := range specs {
		g := &group{spec: sp, target: "sdx"}
		checkText(t, sp.ID+" title", fill(sp.Title, g))
		checkText(t, sp.ID+" detail", fill(sp.Detail, g))
		checkText(t, sp.ID+" action", fill(sp.Action, g))
	}
	for code, sc := range stopCodes {
		checkText(t, sc.name, sc.hint)
		if !strings.HasSuffix(sc.hint.EN, ".") || !strings.HasSuffix(sc.hint.VI, ".") {
			t.Errorf("0x%X: hint must be a full sentence: %+v", code, sc.hint)
		}
	}
	checkText(t, "vfioNote", vfioNote)
	checkText(t, "persistFix", persistFix)
	checkText(t, "actUnclean", actUnclean)
}

func TestDupWord(t *testing.T) {
	for s, want := range map[string]string{
		"Mã này thường do thường do driver.": "thường do thường do",
		"the the disk":              "the the",
		"Ghi nhận 2 lần lúc 10:00.": "",
		"từng thiết bị":             "",
	} {
		if got := dupWord(s); got != want {
			t.Errorf("dupWord(%q) = %q, want %q", s, got, want)
		}
	}
}
