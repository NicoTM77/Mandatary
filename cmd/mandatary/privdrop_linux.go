//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
)

// dropPrivileges makes this process the configured service identity BEFORE any
// data, key or reveal file is opened: supplementary groups are cleared, then gid
// and uid are set (Go applies them to every thread on Linux) and the result is
// verified, including that root cannot be regained. The helper must neither run
// as UID 0 nor keep the Docker-socket (or any other) supplementary group.
func dropPrivileges(uid, gid int) error {
	if uid <= 0 || gid <= 0 {
		return errors.New("refusing to run as a privileged identity")
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	return verifyIdentity(uid, gid)
}

// verifyIdentity checks the effective state and that no path back to root exists.
func verifyIdentity(uid, gid int) error {
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid || len(groups) != 0 {
		return errors.New("identity verification failed")
	}
	if os.Geteuid() != 0 && syscall.Setuid(0) == nil {
		return errors.New("privileges could be regained")
	}
	return nil
}
