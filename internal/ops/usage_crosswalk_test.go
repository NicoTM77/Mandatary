package ops_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestUsageCrosswalkNamesResolve keeps docs/usage-accounting.md honest: every test its
// requirement map cites must be a real declaration in one of the packages the accounting
// acceptance spans, so a renamed or deleted test cannot leave a claim pointing at nothing.
func TestUsageCrosswalkNamesResolve(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "usage-accounting.md"))
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	declared := map[string]bool{}
	for _, dir := range []string{".", filepath.Join("..", "store"), filepath.Join("..", "authz"), filepath.Join("..", "..", "tests", "adapters")} {
		files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range decl.FindAllSubmatch(b, -1) {
				declared[string(m[1])] = true
			}
		}
	}
	cited := map[string]bool{}
	for _, m := range regexp.MustCompile("`(Test[A-Z][A-Za-z0-9_]+)`").FindAllStringSubmatch(string(doc), -1) {
		cited[m[1]] = true
	}
	if len(cited) < 30 {
		t.Fatalf("the usage crosswalk cites only %d tests", len(cited))
	}
	for name := range cited {
		if !declared[name] {
			t.Errorf("docs/usage-accounting.md cites %s, which is not a declared test", name)
		}
	}
	// And the other direction for this row's own tests: every usage test declared in
	// internal/ops must be cited.
	own := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*(Usage|Accounting|Counted|Counts|Attribution|Ledger)[A-Za-z0-9_]*)\(`)
	for _, f := range []string{"usage_test.go", "usage_fixture_test.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range own.FindAllSubmatch(b, -1) {
			if name := string(m[1]); name != "TestUsageCrosswalkNamesResolve" && !cited[name] {
				t.Errorf("%s declares %s, which docs/usage-accounting.md does not cite", f, name)
			}
		}
	}
}
