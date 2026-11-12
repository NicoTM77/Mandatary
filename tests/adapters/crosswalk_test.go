package adapters_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAdapterCrosswalkNamesResolve keeps docs/api-mcp.md honest: every test it cites must
// be a real declaration, and every test of this package must be cited, so a renamed or
// deleted test cannot leave an acceptance claim pointing at nothing.
func TestAdapterCrosswalkNamesResolve(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "api-mcp.md"))
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	declared, own := map[string]bool{}, map[string]bool{}
	for _, dir := range []string{".", filepath.Join("..", "..", "internal", "api"), filepath.Join("..", "..", "internal", "authz"), filepath.Join("..", "..", "cmd", "mandatary")} {
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
				if dir == "." && string(m[1]) != "TestMain" {
					own[string(m[1])] = true
				}
			}
		}
	}
	cited := map[string]bool{}
	text := string(doc)
	if i := strings.Index(text, "## Requirement-to-executable-test map"); i >= 0 {
		text = text[i:]
	}
	for _, m := range regexp.MustCompile("`(Test[A-Z][A-Za-z0-9_]+)`").FindAllStringSubmatch(text, -1) {
		cited[m[1]] = true
	}
	if len(cited) < 30 {
		t.Fatalf("crosswalk cites only %d tests", len(cited))
	}
	for name := range cited {
		if !declared[name] {
			t.Errorf("docs/api-mcp.md cites %s, which is not a declared test", name)
		}
	}
	for name := range own {
		if !cited[name] {
			t.Errorf("tests/adapters declares %s, which docs/api-mcp.md does not cite", name)
		}
	}
}
