package store

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

// The setup/recovery reveal file is the deliberate short-lived plaintext copy of
// a one-use token (security-contracts.md S3). These primitives implement only the
// descriptor-relative, no-follow filesystem part. They are NOT the protocol:
// ordering, state, expiry and terminal output belong to the auth setup service.
//
// All methods assume the caller is inside a Repository.Control/ControlThen
// callback: the shared advisory lock, a healthy handle and an open data-directory
// descriptor are then guaranteed. They deliberately do not re-enter the
// repository lifecycle lock, so calling them anywhere else is unsupported.

const revealDirName = "reveal"

var revealName = regexp.MustCompile(`^(initial_setup|mfa_reset|restore_recovery)-[1-9][0-9]{0,17}\.token$`)

// maxRevealBytes bounds every read; the protocol's records are a few hundred bytes.
const maxRevealBytes = 1024

// revealDirectory opens (optionally creating) the 0700 reveal directory below the
// verified data directory. The directory must have exactly the configured numeric
// owner/group and mode 0700; links, wrong owners and widened access are refused,
// never repaired. A created directory and its parent entry are synced.
func (r *Repository) revealDirectory(create bool) (int, error) {
	parent := int(r.dir.Fd())
	fd, err := unix.Openat(parent, revealDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if err = unix.Mkdirat(parent, revealDirName, 0700); err != nil {
			return -1, ErrStorage
		}
		fd, err = unix.Openat(parent, revealDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == nil {
			// Mkdirat is subject to the process umask; refuse rather than chmod-repair.
			if err = unix.Fsync(parent); err != nil {
				_ = unix.Close(fd)
				return -1, ErrStorage
			}
		}
	}
	if err != nil {
		return -1, ErrStorage
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0777 != 0700 || int64(st.Uid) != int64(r.uid) || int64(st.Gid) != int64(r.gid) {
		_ = unix.Close(fd)
		return -1, ErrStorage
	}
	return fd, nil
}

// RevealFileWrite creates name exclusively (mode 0600, owner = configured IDs),
// writes content, syncs the file and the directory. An existing name fails.
func (r *Repository) RevealFileWrite(name string, content []byte) error {
	if !revealName.MatchString(name) || len(content) == 0 || len(content) > maxRevealBytes {
		return ErrStorage
	}
	dfd, err := r.revealDirectory(true)
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = unix.Close(dfd) }() // read-only directory descriptor
	fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrStorage
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&0777 != 0600 || int64(st.Uid) != int64(r.uid) || int64(st.Gid) != int64(r.gid) || st.Nlink != 1 {
		_ = f.Close()
		_ = unix.Unlinkat(dfd, name, 0)
		return ErrStorage
	}
	if _, err = f.Write(content); err == nil {
		err = r.syncFile(f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, name, 0)
		return ErrStorage
	}
	if r.syncDirectory(dfd) != nil {
		return ErrStorage
	}
	return nil
}

// syncDirectory syncs through a duplicate descriptor so the hookable sync path is
// used without os.File taking ownership of (and later closing) the caller's fd.
func (r *Repository) syncDirectory(fd int) error {
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return ErrStorage
	}
	f := os.NewFile(uintptr(duplicate), revealDirName)
	err = r.syncFile(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return ErrStorage
	}
	return nil
}

// RevealFileCheck verifies, WITHOUT reading any content, that name is a safe
// single-linked regular 0600 file with the configured owner inside a safe 0700
// directory. A reveal checks this before it claims, so an unsafe layout emits
// nothing and does not consume the generation.
func (r *Repository) RevealFileCheck(name string) error {
	if !revealName.MatchString(name) {
		return ErrStorage
	}
	dfd, err := r.revealDirectory(false)
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = unix.Close(dfd) }() // read-only directory descriptor
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = unix.Close(fd) }() // read-only descriptor, nothing is read
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || int64(st.Uid) != int64(r.uid) || int64(st.Gid) != int64(r.gid) || st.Size <= 0 || st.Size > maxRevealBytes {
		return ErrStorage
	}
	return nil
}

// RevealFileRead returns the file only when it is a single-linked regular 0600
// file owned by the configured IDs. The caller must clear the returned bytes.
func (r *Repository) RevealFileRead(name string) ([]byte, error) {
	if !revealName.MatchString(name) {
		return nil, ErrStorage
	}
	dfd, err := r.revealDirectory(false)
	if err != nil {
		return nil, ErrStorage
	}
	defer func() { _ = unix.Close(dfd) }() // read-only directory descriptor
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrStorage
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }() // read-only
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || int64(st.Uid) != int64(r.uid) || int64(st.Gid) != int64(r.gid) || st.Size <= 0 || st.Size > maxRevealBytes {
		return nil, ErrStorage
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRevealBytes+1))
	if err != nil || len(data) > maxRevealBytes {
		clear(data)
		return nil, ErrStorage
	}
	return data, nil
}

// RevealFileRemove unlinks name and syncs the directory. A missing file or
// directory is success (nothing remains); anything else that prevents removal,
// including an unsafe directory or a non-regular entry, is an error.
func (r *Repository) RevealFileRemove(name string) error {
	if !revealName.MatchString(name) {
		return ErrStorage
	}
	dfd, err := r.revealDirectory(false)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(r.path, revealDirName)); os.IsNotExist(statErr) {
			return nil
		}
		return ErrStorage
	}
	defer func() { _ = unix.Close(dfd) }() // read-only directory descriptor
	if err = unix.Unlinkat(dfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return ErrStorage
	}
	if r.syncDirectory(dfd) != nil {
		return ErrStorage
	}
	return nil
}

// RevealFileNames lists regular entries in the reveal directory. An absent
// directory is an empty list. Any entry that is not a valid reveal name is an
// error: unexpected content is never silently ignored or deleted.
func (r *Repository) RevealFileNames() ([]string, error) {
	dfd, err := r.revealDirectory(false)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(r.path, revealDirName)); os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, ErrStorage
	}
	// os.NewFile takes ownership of dfd; Close below releases it.
	dir := os.NewFile(uintptr(dfd), revealDirName)
	defer func() { _ = dir.Close() }() // read-only directory descriptor
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, ErrStorage
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !revealName.MatchString(entry.Name()) || !entry.Type().IsRegular() {
			return nil, ErrStorage
		}
		names = append(names, entry.Name())
	}
	return names, nil
}
