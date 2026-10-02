package report

import "testing"

func TestMarkdownEscapesLineStartAndLinks(t *testing.T) {
	cases := map[string]string{
		"# Urgent: login at https://phish.example/reset": `\# Urgent: login at https\://phish.example/reset`,
		"> quoted":               `\> quoted`,
		"- item":                 `\- item`,
		"1. first":               `1\. first`,
		"12) x":                  `12\) x`,
		"Dell Inc.":              "Dell Inc.",
		"PowerEdge R740":         "PowerEdge R740",
		"a-b c#d":                "a-b c#d",
		"2.5 TB":                 "2.5 TB",
		"Current_Pending_Sector": "Current_Pending_Sector",
	}
	for in, want := range cases {
		if got := mdEsc(in); got != want {
			t.Errorf("mdEsc(%q) = %q, want %q", in, got, want)
		}
	}
}
