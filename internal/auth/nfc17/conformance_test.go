package nfc17

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func corpus(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".gz")
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = z.Close() }()
	b, err = io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]struct {
		SHA256 string `json:"sha256"`
		Bytes  int    `json:"bytes"`
	}
	manifest, err := os.ReadFile("data-sha256.json")
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(manifest, &m) != nil {
		t.Fatal("manifest")
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != m[name].SHA256 || len(b) != m[name].Bytes {
		t.Fatal("corpus integrity")
	}
	return b
}
func TestOfficialNormalization17(t *testing.T) {
	scanner := bufio.NewScanner(bytes.NewReader(corpus(t, "NormalizationTest.txt")))
	count := 0
	parts := map[string]bool{}
	singleton := map[rune]bool{}
	for scanner.Scan() {
		line := strings.TrimSpace(strings.Split(scanner.Text(), "#")[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@") {
			parts[line] = true
			continue
		}
		fields := strings.Split(line, ";")
		if len(fields) < 5 {
			t.Fatal("corpus schema")
		}
		var c [5]string
		for i := range c {
			var b strings.Builder
			for _, v := range strings.Fields(fields[i]) {
				x, err := strconv.ParseInt(v, 16, 32)
				if err != nil {
					t.Fatal(err)
				}
				b.WriteRune(rune(x))
			}
			c[i] = b.String()
		}
		if utf8.RuneCountInString(c[0]) == 1 {
			r, _ := utf8.DecodeRuneInString(c[0])
			singleton[r] = true
		}
		for i := range c {
			want := c[1]
			if i >= 3 {
				want = c[3]
			}
			if got := string(mustNFC(t, c[i])); got != want {
				t.Fatalf("NFC equality row %d column %d", count, i)
			}
		}
		count++
	}
	if scanner.Err() != nil || count != 20034 || len(parts) != 6 {
		t.Fatalf("corpus coverage rows=%d parts=%d", count, len(parts))
	}
	tested := 0
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF || singleton[r] {
			continue
		}
		s := string(r)
		if string(mustNFC(t, s)) != s {
			t.Fatalf("singleton U+%04X", r)
		}
		tested++
	}
	t.Logf("official rows=%d parts=%d additional singletons=%d", count, len(parts), tested)
}
func TestBounds(t *testing.T) {
	for _, s := range []string{string([]byte{0xff}), strings.Repeat("a", 513), strings.Repeat("a", 4095), strings.Repeat("a", 4096), strings.Repeat("a", 4097)} {
		if b, e := Bytes([]byte(s)); e == nil || b != nil {
			t.Fatal("invalid input succeeded/partial return")
		}
	}
	if _, e := Bytes([]byte(strings.Repeat("a", 512))); e != nil {
		t.Fatal(e)
	}
	s := []byte("q\u0301\u0323")
	for _, limits := range [][4]int{{1, maxByteBufferSize, MaxOutput, maxNonStarters}, {maxBufferSize, 4, MaxOutput, maxNonStarters}, {maxBufferSize, maxByteBufferSize, 1, maxNonStarters}, {maxBufferSize, maxByteBufferSize, MaxOutput, 0}} {
		if b, e := bounded(s, limits[0], limits[1], limits[2], limits[3]); e == nil || b != nil {
			t.Fatal("capacity mutation succeeded")
		}
	}
}
func TestFrozenRepertoireData(t *testing.T) {
	scanner := bufio.NewScanner(bytes.NewReader(corpus(t, "DerivedGeneralCategory.txt")))
	checked := 0
	for scanner.Scan() {
		line := strings.TrimSpace(strings.Split(scanner.Text(), "#")[0])
		if line == "" {
			continue
		}
		f := strings.Split(line, ";")
		span := strings.Split(strings.TrimSpace(f[0]), "..")
		lo, e := strconv.ParseInt(span[0], 16, 32)
		if e != nil {
			t.Fatal(e)
		}
		hi, e := strconv.ParseInt(span[len(span)-1], 16, 32)
		if e != nil {
			t.Fatal(e)
		}
		cat := strings.TrimSpace(f[1])
		want := cat != "Cn" && cat != "Cs"
		for r := rune(lo); r <= rune(hi); r++ {
			if Assigned(r) != want {
				t.Fatalf("frozen GC mismatch U+%04X", r)
			}
			checked++
		}
	}
	if scanner.Err() != nil || checked != 0x110000 {
		t.Fatal("incomplete repertoire audit")
	}
}
func TestParallelCanonical(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				s := "q" + strings.Repeat("\u0301", 127)
				if string(mustNFC(t, s)) != s {
					t.Error("parallel normalization changed bytes")
				}
			}
		})
	}
	wg.Wait()
}
func FuzzNFC(f *testing.F) {
	for _, s := range []string{strings.Repeat("\u0344", 257), "q\u0301\u0323", "\U000105D2\u0307", "\ufffd", string([]byte{0xff}), strings.Repeat("\u0301", 256)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		out, e := Bytes(b)
		if e != nil {
			if out != nil {
				t.Fatal("partial output")
			}
			return
		}
		// Admission is not closed under canonical expansion (e.g. 257 U+0344
		// produces 514 scalars). Only re-enter the raw-input API in its domain.
		if len(out) <= MaxBytes && utf8.RuneCount(out) <= MaxScalars {
			again, e := Bytes(out)
			if e != nil || !bytes.Equal(out, again) {
				t.Fatal("idempotence")
			}
		}
		if strings.Count(string(out), "\u034f") > strings.Count(string(b), "\u034f") {
			t.Fatal("synthesized CGJ")
		}
	})
}
