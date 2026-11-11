package auth

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The crosswalk in docs/sessions-browser-security.md is only useful if every test
// name it cites is a real declaration. A renamed or deleted test must fail here
// rather than leave an acceptance claim pointing at nothing.
func TestSessionCrosswalkNamesResolve(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "sessions-browser-security.md"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	for _, dir := range []string{".", filepath.Join("..", "..", "tests", "security")} {
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
	for _, m := range regexp.MustCompile("`?(Test[A-Z][A-Za-z0-9_]+)`?").FindAllStringSubmatch(string(doc), -1) {
		cited[m[1]] = true
	}
	if len(cited) < 40 {
		t.Fatalf("crosswalk cites only %d tests", len(cited))
	}
	for name := range cited {
		if !declared[name] {
			t.Errorf("crosswalk cites %s, which is not a declared test", name)
		}
	}
	// And the reverse for this card's own tests: every P1.08 session test that
	// exists is cited, so a new test cannot silently escape the evidence map.
	for name := range declared {
		if (strings.HasPrefix(name, "TestSession") || strings.HasPrefix(name, "TestStepUp") || strings.HasPrefix(name, "TestSensitive")) && !cited[name] {
			t.Errorf("%s is not cited in docs/sessions-browser-security.md", name)
		}
	}
}
