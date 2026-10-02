package redfish

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
)

// mockup is a Redfish mockup tree (DMTF DSP2043 layout): key "/redfish/v1/..."
// (with "?query" for paged collections) → JSON object.
type mockup map[string]map[string]any

// loadMockup reads testdata/mockups/<name>. A file "index@<query>.json"
// holds the page served for "<dir>?<query>".
func loadMockup(t testing.TB, name string) mockup {
	t.Helper()
	root := filepath.Join("testdata", "mockups", name)
	m := mockup{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		key := "/redfish/v1"
		if rel != "." {
			key += "/" + filepath.ToSlash(rel)
		}
		base := filepath.Base(p)
		if q, ok := strings.CutPrefix(strings.TrimSuffix(base, ".json"), "index@"); ok {
			key += "?" + q
		} else if base != "index.json" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var o map[string]any
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		m[key] = o
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) == 0 {
		t.Fatalf("mockup %s is empty", name)
	}
	return m
}

// set changes a value at a JSON path ("Status.Health", "PowerSupplies.0.LineInputVoltage").
func (m mockup) set(t testing.TB, key, path string, v any) {
	t.Helper()
	o := m[key]
	if o == nil {
		t.Fatalf("no resource %s", key)
	}
	parts := strings.Split(path, ".")
	var cur any = o
	for i, p := range parts {
		last := i == len(parts)-1
		switch c := cur.(type) {
		case map[string]any:
			if last {
				if v == nil {
					delete(c, p)
				} else {
					c[p] = v
				}
				return
			}
			if c[p] == nil {
				c[p] = map[string]any{}
			}
			cur = c[p]
		case []any:
			n := 0
			for _, ch := range p {
				n = n*10 + int(ch-'0')
			}
			if n >= len(c) {
				t.Fatalf("%s %s: index %d out of range", key, path, n)
			}
			if last {
				c[n] = v
				return
			}
			cur = c[n]
		default:
			t.Fatalf("%s %s: cannot descend into %T", key, path, cur)
		}
	}
}

// bundle emulates the collector: starting at the root it follows every
// @odata.id and nextLink inside /redfish/v1 and stores each resource (404
// for links the mockup does not have).
func (m mockup) bundle(extra ...*collect.Section) *collect.Bundle {
	b := testkit.Bundle(collect.OSBMC)
	b.Options.SinceDays = 30
	seen := map[string]bool{}
	queue := []string{"/redfish/v1"}
	for len(queue) > 0 && len(seen) < 5000 {
		k := queue[0]
		queue = queue[1:]
		if seen[k] {
			continue
		}
		seen[k] = true
		o, ok := m[k]
		if !ok {
			b.Add(&collect.Section{Name: SectionPrefix + k, RC: 404, Out: `{"error":{"code":"Base.1.0.ResourceMissingAtURI"}}`})
			continue
		}
		body, _ := json.Marshal(o)
		b.Add(&collect.Section{Name: SectionPrefix + k, RC: 200, Out: string(body)})
		follow := func(ref string) {
			if nk := normKey(ref); nk != "" && strings.HasPrefix(nk, "/redfish/v1") && !seen[nk] {
				queue = append(queue, nk)
			}
		}
		walkLinks(o, follow)
		follow(nextLink(o)) // also iLO 4's links.NextPage

	}
	for _, s := range extra {
		b.Add(s)
	}
	return b
}

func walkLinks(v any, fn func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if s, ok := c.(string); ok && (k == "@odata.id" || k == "href" || strings.HasSuffix(k, "nextLink")) {
				if !strings.Contains(s, "#") {
					fn(s)
				}
				continue
			}
			walkLinks(c, fn)
		}
	case []any:
		for _, c := range x {
			walkLinks(c, fn)
		}
	}
}
