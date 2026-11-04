package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Open every directory component without following links. Ancestors must be
// owned by root or the configured UID, and not group/world writable. The data
// directory must have the configured numeric owner/group and mode 0700.
func openDataDir(path string, uid, gid int, create bool) (*os.File, error) {
	return walkDirectory(path, uid, gid, create, true)
}

func walkDirectory(path string, uid, gid int, create, privateLeaf bool) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" || absolute == "/" {
		return nil, ErrStorage
	}
	parts := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrStorage
	}
	for i, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && i == len(parts)-1 && create {
			if e = unix.Mkdirat(fd, part, 0700); e == nil {
				e = unix.Fsync(fd)
			}
			if e == nil {
				next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		_ = unix.Close(fd)
		if e != nil {
			return nil, ErrStorage
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && int64(st.Uid) != int64(uid)) || st.Mode&0022 != 0 || (privateLeaf && i == len(parts)-1 && (int64(st.Uid) != int64(uid) || int64(st.Gid) != int64(gid) || st.Mode&0777 != 0700)) {
			_ = unix.Close(fd)
			return nil, ErrStorage
		}
	}
	return os.NewFile(uintptr(fd), absolute), nil
}

func (r *Repository) privateFile(name string, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(int(r.dir.Fd()), name, flags, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || int64(st.Uid) != int64(r.uid) || int64(st.Gid) != int64(r.gid) {
		_ = unix.Close(fd)
		return nil, ErrStorage
	}
	return os.NewFile(uintptr(fd), name), nil
}

// Each acquisition opens the SAME persistent inode with a new description:
// flock on one shared description would not serialize goroutines. Never unlink
// this lock. All service/helper writers take it before any SQLite transaction.
func (r *Repository) lock(ctx context.Context) (*os.File, error) {
	f, err := r.privateFile("control.lock", false)
	if err != nil {
		return nil, ErrStorage
	}
	stat, err := f.Stat()
	if err != nil || !os.SameFile(stat, r.lockIdentity) {
		_ = f.Close()
		return nil, ErrStorage
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, ErrStorage
		}
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = f.Close()
			return nil, ErrStorage
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = f.Close()
			return nil, ErrStorage
		case <-timer.C:
		}
	}
}

func (r *Repository) verifyFiles() error {
	current, err := openDataDir(r.path, r.uid, r.gid, false)
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = current.Close() }() // read-only directory descriptor
	a, err := current.Stat()
	if err != nil {
		return ErrStorage
	}
	b, err := r.dir.Stat()
	if err != nil || !os.SameFile(a, b) {
		return ErrStorage
	}
	for _, name := range []string{"mandatary.db", "control.lock", "mandatary.db-wal", "mandatary.db-shm", "mandatary.db-journal"} {
		f, err := r.privateFile(name, false)
		if err != nil {
			if _, e := os.Lstat(filepath.Join(r.path, name)); os.IsNotExist(e) && r.sidecarIdentities[name] == nil && name != "mandatary.db" && name != "control.lock" {
				continue
			}
			return ErrStorage
		}
		st, e := f.Stat()
		_ = f.Close()
		if e != nil || (r.sidecarIdentities[name] != nil && !os.SameFile(st, r.sidecarIdentities[name])) || (name == "mandatary.db" && !os.SameFile(st, r.dbIdentity)) || (name == "control.lock" && !os.SameFile(st, r.lockIdentity)) {
			return ErrStorage
		}
	}
	return nil
}

func (r *Repository) syncFiles() error {
	for _, name := range []string{"mandatary.db", "mandatary.db-wal", "control.lock"} {
		f, err := r.privateFile(name, false)
		if err != nil {
			return ErrStorage
		}
		err = r.syncFile(f)
		_ = f.Close()
		if err != nil {
			return ErrStorage
		}
	}
	if err := r.syncFile(r.dir); err != nil {
		return ErrStorage
	}
	return nil
}
