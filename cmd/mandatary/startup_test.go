package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupRequiresKeyBeforeOpeningStorage(t *testing.T) {
	for _, value := range []string{"", "synthetic-invalid-key"} {
		path := filepath.Join(t.TempDir(), "must-not-create")
		values := map[string]string{"MANDATARY_MASTER_KEY": value, "MANDATARY_DATA_DIR": path}
		r, err := openRepository(t.Context(), func(name string) string { return values[name] })
		if err == nil {
			_ = r.Close()
			t.Fatal("startup accepted missing/invalid master key")
		}
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatal("startup key error leaks input")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("invalid key touched storage")
		}
	}
	path := filepath.Join(t.TempDir(), "data")
	values := map[string]string{"MANDATARY_MASTER_KEY": strings.Repeat("42", 32), "MANDATARY_DATA_DIR": path}
	r, err := openRepository(t.Context(), func(name string) string { return values[name] })
	if err != nil {
		t.Fatal("valid startup rejected", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	values["MANDATARY_MASTER_KEY"] = strings.Repeat("43", 32)
	if r, err := openRepository(t.Context(), func(name string) string { return values[name] }); err == nil {
		_ = r.Close()
		t.Fatal("wrong key startup accepted")
	}
}
