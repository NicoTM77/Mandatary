package store

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(t *testing.T) *MasterKey {
	t.Helper()
	key, err := LoadMasterKey(strings.Repeat("42", 32), "")
	if err != nil {
		t.Fatal("synthetic key rejected")
	}
	return key
}

func TestAuthenticatedRecordEncryption(t *testing.T) {
	cipher, err := newRecordCipher(testKey(t), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("synthetic-secret-not-for-logs")
	first, err := cipher.Seal("smtp", "relay", secret)
	if err != nil {
		t.Fatal("encryption refused")
	}
	second, err := cipher.Seal("smtp", "relay", secret)
	if err != nil || bytes.Equal(first, second) || bytes.Equal(first[1:1+saltSize], second[1:1+saltSize]) || bytes.Equal(first[1+saltSize:1+saltSize+12], second[1+saltSize:1+saltSize+12]) {
		t.Fatal("nonce/salt reused")
	}
	plain, err := cipher.Open("smtp", "relay", first)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatal("roundtrip failed")
	}
	other, _ := newRecordCipher(testKey(t), bytes.Repeat([]byte{2}, 32))
	wrongKey, _ := LoadMasterKey(strings.Repeat("43", 32), "")
	wrong, _ := newRecordCipher(wrongKey, bytes.Repeat([]byte{1}, 32))
	for _, c := range []*recordCipher{wrong, other} {
		if plain, err := c.Open("smtp", "relay", first); err == nil || plain != nil {
			t.Fatal("wrong key/installation accepted")
		}
	}
	for i := range first {
		changed := bytes.Clone(first)
		changed[i] ^= 1
		if plain, err := cipher.Open("smtp", "relay", changed); err == nil || plain != nil || strings.Contains(err.Error(), string(secret)) {
			t.Fatal("tamper accepted or leaked")
		}
	}
	for n := 0; n < len(first); n++ {
		if plain, err := cipher.Open("smtp", "relay", first[:n]); err == nil || plain != nil {
			t.Fatal("truncation accepted")
		}
	}
	for _, pair := range [][2]string{{"totp", "relay"}, {"smtp", "other"}, {"future", "relay"}, {"smtp", ""}} {
		if plain, err := cipher.Open(pair[0], pair[1], first); err == nil || plain != nil {
			t.Fatal("record substitution accepted")
		}
	}
	cipher.random = failRandom{}
	if sealed, err := cipher.Seal("smtp", "relay", secret); err == nil || sealed != nil {
		t.Fatal("entropy failure accepted")
	}
}

type failRandom struct{}

func (failRandom) Read([]byte) (int, error) { return 0, fmt.Errorf("entropy-canary-must-not-escape") }

func TestKeyFileRejectsAliasesLinksAndOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte(strings.Repeat("42", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if key, err := LoadMasterKey("", link); err == nil || key != nil {
		t.Fatal("key symlink accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if key, err := LoadMasterKey("", path); err == nil || key != nil {
		t.Fatal("key hard link accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	alias := dir + "-alias"
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	if key, err := LoadMasterKey("", filepath.Join(alias, "key")); err == nil || key != nil {
		t.Fatal("key directory alias accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 257)), 0600); err != nil {
		t.Fatal(err)
	}
	if key, err := LoadMasterKey("", path); err == nil || key != nil {
		t.Fatal("oversized key file accepted")
	}
}

func TestStorageErrorsDoNotLeakCanaries(t *testing.T) {
	r, _ := openFixture(t)
	for _, format := range []string{"json", "text"} {
		for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
			var out bytes.Buffer
			options := &slog.HandlerOptions{Level: slog.LevelDebug}
			var handler slog.Handler = slog.NewJSONHandler(&out, options)
			if format == "text" {
				handler = slog.NewTextHandler(&out, options)
			}
			logger := slog.New(handler)
			canary := "synthetic-secret-error-canary"
			err := r.Write(t.Context(), func(*Queries) error { return fmt.Errorf("%s", canary) })
			logger.Log(t.Context(), level, "storage failed", "err", err, "key", testKey(t))
			if err == nil || strings.Contains(out.String(), canary) || strings.Contains(out.String(), strings.Repeat("42", 32)) {
				t.Fatal("secret error/key logged")
			}
		}
	}
}

func TestMasterKeyBoundary(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, 32)
	for _, value := range []string{hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw)} {
		key, err := LoadMasterKey(value, "")
		if err != nil || key == nil {
			t.Fatal("valid key refused")
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("key", "key", key)
		fmt.Fprintf(&output, "%v %+v %#v %v %#v", key, key, key, *key, *key)
		if strings.Contains(output.String(), value) || strings.Contains(output.String(), "0x42") || strings.Contains(output.String(), "[66") {
			t.Fatal("key exposed in formatting/logs")
		}
	}
	for _, value := range []string{"", "canary-invalid-master-key", strings.Repeat("a", 63), strings.Repeat("0", 64), base64.StdEncoding.EncodeToString(raw[:31])} {
		key, err := LoadMasterKey(value, "")
		if key != nil || err == nil {
			t.Fatal("invalid/missing key accepted")
		}
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatal("key value leaked")
		}
	}
	path := filepath.Join(t.TempDir(), "master-key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKey("", path); err != nil {
		t.Fatal("key file rejected")
	}
	if _, err := LoadMasterKey(hex.EncodeToString(raw), path); err == nil {
		t.Fatal("ambiguous sources accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKey("", path); err == nil {
		t.Fatal("world-readable key accepted")
	}
	if _, err := LoadMasterKey("", path+"-missing"); err == nil || strings.Contains(err.Error(), path) {
		t.Fatal("missing path accepted or disclosed")
	}
}
