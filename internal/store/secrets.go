package store

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrKey = errors.New("master key unavailable or invalid")

// MasterKey deliberately has no exported bytes or serialization methods.
// Formatting, including Go-syntax formatting and structured logging, is redacted.
// Go does not guarantee erasure of copies held by its runtime/crypto libraries.
type MasterKey struct{ value [32]byte }

func (k *MasterKey) valid() bool {
	if k == nil {
		return false
	}
	var nonzero byte
	for _, b := range k.value {
		nonzero |= b
	}
	return nonzero != 0
}
func (MasterKey) String() string       { return "[REDACTED]" }
func (MasterKey) GoString() string     { return "[REDACTED]" }
func (MasterKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// LoadMasterKey requires exactly one hex/base64 source. No default, generation,
// source precedence, raw-string key or fallback is permitted. Key-file mounts
// must be regular, single-linked, owned by this UID or root and owner-only.
func LoadMasterKey(value, path string) (*MasterKey, error) {
	if (value == "") == (path == "") {
		return nil, ErrKey
	}
	if path != "" {
		dir, err := walkDirectory(filepath.Dir(path), os.Geteuid(), os.Getegid(), false, false)
		if err != nil {
			return nil, ErrKey
		}
		defer func() { _ = dir.Close() }() // read-only directory descriptor
		root, err := os.OpenRoot(dir.Name())
		if err != nil {
			return nil, ErrKey
		}
		defer func() { _ = root.Close() }() // read-only directory descriptor
		anchor, err := dir.Stat()
		if err != nil {
			return nil, ErrKey
		}
		current, err := root.Stat(".")
		if err != nil || !os.SameFile(anchor, current) {
			return nil, ErrKey
		}
		f, err := root.OpenFile(filepath.Base(path), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, ErrKey
		}
		defer func() { _ = f.Close() }() // no data is written
		st, err := f.Stat()
		if err != nil {
			return nil, ErrKey
		}
		var stat unix.Stat_t
		if unix.Fstat(int(f.Fd()), &stat) != nil || !st.Mode().IsRegular() || stat.Nlink != 1 || (int64(stat.Uid) != int64(os.Geteuid()) && stat.Uid != 0) || st.Mode().Perm()&0077 != 0 {
			return nil, ErrKey
		}
		data, err := io.ReadAll(io.LimitReader(f, 257))
		if err != nil || len(data) > 256 {
			return nil, ErrKey
		}
		value = strings.TrimSuffix(string(data), "\n")
		clear(data)
	}
	data, err := hex.DecodeString(value)
	if err != nil || len(data) != 32 {
		data, err = base64.StdEncoding.Strict().DecodeString(value)
	}
	if err != nil || len(data) != 32 {
		return nil, ErrKey
	}
	defer clear(data)
	var nonzero byte
	for _, b := range data {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, ErrKey
	}
	key := &MasterKey{}
	copy(key.value[:], data)
	return key, nil
}
