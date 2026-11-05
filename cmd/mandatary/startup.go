package main

import (
	"context"
	"os"

	"github.com/NicoTM77/Mandatary/internal/config"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// Keep key decoding/file ownership and missing/wrong-key refusal in the reviewed
// storage boundary. Configuration validation runs before any storage side effect.
func openRepository(ctx context.Context, getenv func(string) string) (*store.Repository, error) {
	c, err := config.Load(getenv)
	if err != nil {
		return nil, err
	}
	return openConfiguredRepository(ctx, getenv, c)
}

func openConfiguredRepository(ctx context.Context, getenv func(string) string, c config.Config) (*store.Repository, error) {
	key, err := store.LoadMasterKey(getenv("MANDATARY_MASTER_KEY"), getenv("MANDATARY_MASTER_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	return store.Open(ctx, store.Options{DataDir: c.DataDir, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
}
