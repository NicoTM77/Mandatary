package store_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestGeneratedModelsAndBoundParameters(t *testing.T) {
	db, _ := fixture(t)
	q := store.New(db)
	local, err := q.GetLocalEndpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := q.GetInstallationControl(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if local.State != "quarantined" || control.RestoreQuarantined != 1 || control.CredentialGeneration != 0 {
		t.Fatal("inactive defaults lost")
	}
	const name = "alice'); DROP TABLE users;--"
	if err = q.CreateUser(t.Context(), store.CreateUserParams{ID: "u1", Username: name}); err != nil {
		t.Fatal(err)
	}
	user, err := q.GetUser(t.Context(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != name || user.State != "quarantined" {
		t.Fatal("bound parameter not preserved")
	}
	if err = q.CreateAgent(t.Context(), store.CreateAgentParams{ID: "a1", Name: "agent", OwnerUserID: sql.NullString{String: "u1", Valid: true}}); err != nil {
		t.Fatal(err)
	}
	agent, err := q.GetAgent(t.Context(), "a1")
	if err != nil {
		t.Fatal(err)
	}
	if agent.OwnerUserID.String != "u1" || agent.OwnerGroupID.Valid {
		t.Fatal("owner XOR lost")
	}
	if err = q.CreateAgent(t.Context(), store.CreateAgentParams{ID: "a2", Name: "unowned"}); err == nil {
		t.Fatal("generated query bypasses XOR")
	}
	if err = q.CreateSelector(t.Context(), store.CreateSelectorParams{ID: "s1", EndpointID: local.ID, ContainerName: "db"}); err != nil {
		t.Fatal(err)
	}
	rows, err := q.ListSelectorsByEndpoint(t.Context(), local.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].EndpointID != local.ID {
		t.Fatal("endpoint qualification lost")
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	tq := q.WithTx(tx)
	if err = tq.CreateUser(t.Context(), store.CreateUserParams{ID: "rollback", Username: "rollback"}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = q.GetUser(t.Context(), "rollback"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("generated transaction escaped rollback")
	}
}
