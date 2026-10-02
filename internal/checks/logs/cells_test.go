package logs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every log rule needs a short name for the event table; otherwise the
// table shows its snake_case ID in both languages.
func TestEveryRuleHasATableName(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	re := regexp.MustCompile(`&spec\{ID: "([a-z0-9_]+)"`)
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			n++
			name, ok := ruleNames[m[1]]
			if !ok || name.EN == "" || name.VI == "" {
				t.Errorf("rule %s has no table name in ruleNames (cells.go)", m[1])
			}
		}
	}
	if n < 50 {
		t.Errorf("found only %d rules; did the spec syntax change?", n)
	}
}
