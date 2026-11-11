//go:build !linux

package main

import (
	"context"
	"errors"
)

// The host helper's actual-terminal proof and privilege handling are implemented
// and tested for Linux only (the supported Compose/Unraid host). Elsewhere the
// reveal fails closed rather than emitting a secret without that proof.
type hostTerminal struct{}

func newHostTerminal() *hostTerminal { return &hostTerminal{} }

var errNotTerminal = errors.New("not a controlling terminal")

func (*hostTerminal) Verify() error { return errNotTerminal }
func (*hostTerminal) WriteSecret(context.Context, []byte) error {
	return errNotTerminal
}
