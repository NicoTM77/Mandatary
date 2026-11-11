//go:build !linux

package main

import "errors"

func dropPrivileges(int, int) error { return errors.New("unsupported platform") }

func verifyIdentity(int, int) error { return errors.New("unsupported platform") }
