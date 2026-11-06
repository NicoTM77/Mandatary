// Command blocklistgen builds exact full-password membership digests from a
// reviewed public corpus. It never handles subscriber credentials.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"github.com/NicoTM77/Mandatary/internal/auth/nfc17"
	"io"
	"os"
	"sort"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: blocklistgen SOURCE.gz OUTPUT")
	}
	if e := run(os.Args[1], os.Args[2]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(source, target string) error {
	f, e := os.Open(source) // #nosec G304 G703 -- offline developer tool; explicit operator-selected public corpus path, not server input.
	if e != nil {
		return e
	}
	defer func() { _ = f.Close() }()
	z, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer func() { _ = z.Close() }()
	raw, e := io.ReadAll(io.LimitReader(z, 2000001))
	if e != nil {
		return e
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != "1472aafa2561df5e3293aee252aee3ca660c12b399a283cf808bb01b39be388b" {
		return fmt.Errorf("public corpus checksum differs")
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 100000 {
		return fmt.Errorf("public corpus count differs")
	}
	unique := map[[32]byte]bool{}
	for _, line := range lines {
		canonical, e := nfc17.Canonical(line)
		if e != nil {
			return fmt.Errorf("public corpus incompatible with profile")
		}
		unique[sha256.Sum256(canonical)] = true
	}
	keys := make([][32]byte, 0, len(unique))
	for k := range unique {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	var out bytes.Buffer
	for _, k := range keys {
		out.Write(k[:])
	}
	fmt.Printf("source=100000 unique=%d digest=%x\n", len(keys), sha256.Sum256(out.Bytes()))
	return os.WriteFile(target, out.Bytes(), 0600) // #nosec G703 -- offline developer tool; explicit operator-selected output path, not server input.
}
