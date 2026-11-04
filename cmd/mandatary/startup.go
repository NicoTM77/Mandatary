package main

import (
	"context"
	"os"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// This is only P1.03's mandatory startup boundary, not the P1.04 structured
// configuration/logging service. No key value/path is included in diagnostics.
func openRepository(ctx context.Context, getenv func(string) string) (*store.Repository, error) {
	key, err := store.LoadMasterKey(getenv("MANDATARY_MASTER_KEY"), getenv("MANDATARY_MASTER_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	path := getenv("MANDATARY_DATA_DIR")
	if path == "" {
		path = "/data"
	}
	return store.Open(ctx, store.Options{DataDir: path, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
}
