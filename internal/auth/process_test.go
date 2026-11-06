package auth

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func passwordProcessProof(t *testing.T, path string) {
	t.Helper()
	key, e := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if e != nil {
		t.Fatal(e)
	}
	r, e := store.Open(t.Context(), store.Options{DataDir: path, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	s, e := NewService(r, DefaultPolicy(), "synthetic-host.example.invalid")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Prove(t.Context(), "synthetic-user", []byte("wrong synthetic public phrase"), "192.0.2.1"); e != ErrDenied {
		t.Fatal("child accepted wrong proof")
	}
}
func TestPasswordSeparateProcessesShareCeiling(t *testing.T) {
	if path := os.Getenv("MANDATARY_AUTH_PROCESS_FIXTURE"); path != "" {
		passwordProcessProof(t, path)
		return
	}
	_, _, db := serviceFixture(t)
	execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id='pwd'`)
	var file string
	if e := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&file); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	var commands []*exec.Cmd
	var outputs []*bytes.Buffer
	for range 2 {
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestPasswordSeparateProcessesShareCeiling$", "-test.v") // #nosec G204 -- exact current test executable, constant selector; no user command.
		command.Env = append(os.Environ(), "MANDATARY_AUTH_PROCESS_FIXTURE="+filepath.Dir(file))
		output := new(bytes.Buffer)
		command.Stdout = output
		command.Stderr = output
		if e := command.Start(); e != nil {
			t.Fatal(e)
		}
		commands = append(commands, command)
		outputs = append(outputs, output)
	}
	for i, command := range commands {
		if e := command.Wait(); e != nil {
			t.Fatalf("child failed: %v %s", e, outputs[i].String())
		}
	}
	if scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`) != 100 || scalarFixture(t, db, `SELECT count(*) FROM authenticators WHERE id='pwd' AND state='disabled'`) != 1 {
		t.Fatal("processes exceeded/reset durable ceiling")
	}
}
