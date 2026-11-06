package nfc17

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Independently audit the resource proof against the actual pinned UCD, not
// compiler Unicode tables or the stream-safe API as a normalization oracle.
func TestFrozenCanonicalResourceProof(t *testing.T) {
	mappings := map[rune][]rune{}
	scan := bufio.NewScanner(bytes.NewReader(corpus(t, "UnicodeData.txt")))
	for scan.Scan() {
		fields := strings.Split(scan.Text(), ";")
		if len(fields) != 15 {
			t.Fatal("UCD schema")
		}
		r, e := strconv.ParseInt(fields[0], 16, 32)
		if e != nil {
			t.Fatal(e)
		}
		d := fields[5]
		if d == "" || strings.HasPrefix(d, "<") {
			continue
		}
		for _, field := range strings.Fields(d) {
			v, e := strconv.ParseInt(field, 16, 32)
			if e != nil || !Assigned(rune(v)) {
				t.Fatal("invalid canonical decomposition")
			}
			mappings[rune(r)] = append(mappings[rune(r)], rune(v))
		}
	}
	if scan.Err() != nil {
		t.Fatal(scan.Err())
	}
	visiting := map[rune]bool{}
	cache := map[rune]int{}
	var count func(rune) int
	count = func(r rune) int {
		if v, ok := cache[r]; ok {
			return v
		}
		if visiting[r] {
			t.Fatal("cyclic decomposition")
		}
		visiting[r] = true
		n := 1
		if r >= hangulBase && r < hangulEnd {
			n = 2
			if (r-hangulBase)%jamoTCount != 0 {
				n = 3
			}
		} else if d, ok := mappings[r]; ok {
			n = 0
			for _, v := range d {
				n += count(v)
			}
		}
		if n < 1 || n > 4 {
			t.Fatal("canonical expansion bound changed")
		}
		visiting[r] = false
		cache[r] = n
		return n
	}
	maximum := 0
	packedMaximum := 0
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		n := count(r)
		if n > maximum {
			maximum = n
		}
		in := inputBytes([]byte(string(r)))
		info := lookupInfoNFC(in, 0)
		for _, v := range []uint8{info.nLeadingNonStarters(), info.nTrailingNonStarters()} {
			if int(v) > packedMaximum {
				packedMaximum = int(v)
			}
			if v > 3 {
				t.Fatal("packed compatibility accounting bound changed")
			}
		}
	}
	if maximum != 4 || packedMaximum != 3 || MaxScalars*maximum > maxBufferSize || MaxScalars*maximum*utf8.UTFMax > maxByteBufferSize || MaxScalars*3 >= maxNonStarters {
		t.Fatal("admission proof no longer fits buffers/counters")
	}
	t.Logf("recursive canonical/Hangul M=%d; packed metadata max=%d; raw=%d D<=%d slot-bytes<=%d", maximum, packedMaximum, MaxScalars, MaxScalars*maximum, MaxScalars*maximum*4)
}
func TestExpansionOutsideRawDomain(t *testing.T) {
	raw := []byte(strings.Repeat("\u0344", 257))
	out, e := Bytes(raw)
	if e != nil || string(out) != strings.Repeat("\u0308\u0301", 257) || utf8.RuneCount(out) != 514 {
		t.Fatal("canonical expansion changed")
	}
	if b, e := Bytes(out); e == nil || b != nil {
		t.Fatal("raw-domain guard disappeared")
	}
}
func TestOrdinaryNFCAdversarialSequences(t *testing.T) {
	for _, n := range []int{29, 30, 31, 32, 63, 64, 65, 127, 254, 255, 256, 510} {
		a := "q" + strings.Repeat("\u0301", n) + "\u0323"
		b := "q\u0323" + strings.Repeat("\u0301", n)
		got, e := Bytes([]byte(a))
		if e != nil || string(got) != b {
			t.Fatalf("ordering/offset boundary n=%d", n)
		}
	}
	for _, s := range []string{"\u1100\u1161\u11a8", "\uac01", "\u1f82", "\u0344", "\u0301\u0323", "q\u034f\u0301"} {
		out, e := Bytes([]byte(s))
		if e != nil {
			t.Fatal(e)
		}
		again, e := Bytes(out)
		if e != nil || !bytes.Equal(out, again) {
			t.Fatal("ordinary NFC idempotence")
		}
	}
}
func BenchmarkBoundedNFC(b *testing.B) {
	raw := []byte("q" + strings.Repeat("\u0301\u0323", 255))
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		if _, e := Bytes(raw); e != nil {
			b.Fatal(e)
		}
	}
}
