package auth

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestRecoverySeparateProcessesConsumeOnce(t *testing.T) {
	if path := os.Getenv("MANDATARY_RECOVERY_PROCESS_FIXTURE"); path != "" {
		code, e := io.ReadAll(io.LimitReader(os.Stdin, 129))
		if e != nil || len(code) != 97 {
			t.Fatal("invalid synthetic process input")
		}
		key, e := store.LoadMasterKey(strings.Repeat("11", 32), "")
		if e != nil {
			t.Fatal(e)
		}
		r, e := store.Open(t.Context(), store.Options{DataDir: path, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
		if e != nil {
			t.Fatal(e)
		}
		defer func() { _ = r.Close() }()
		l, e := NewLifecycle(r, NoticeSettings{Origin: "https://synthetic.example.invalid", Contact: "security@example.invalid", Sender: "notices@example.invalid", Relay: "localhost:465", Mode: "implicit"})
		if e != nil {
			t.Fatal(e)
		}
		l.now = func() time.Time { return time.Unix(2000000010, 0) }
		_, e = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), string(code), "192.0.2.2")
		if e != nil && e != ErrDenied {
			t.Fatal("unexpected child failure")
		}
		if e == nil {
			if os.Getenv("MANDATARY_RECOVERY_CRASH") == "1" {
				os.Exit(23)
			}
			_, _ = fmt.Fprintln(os.Stdout, "RECOVERY-CONSUMED")
		}
		return
	}
	l, db, session := lifecycleFixture(t)
	factor := queueBindingNotice(t, l, session)
	if _, e := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, factor.ID); e != nil {
		t.Fatal(e)
	}
	batch, e := l.IssueRecoveryCodes(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	codes := batch.ExportOnce()
	var file string
	if e = db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&file); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	commands := []*exec.Cmd{}
	outputs := []*bytes.Buffer{}
	for i := 0; i < 2; i++ {
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestRecoverySeparateProcessesConsumeOnce$") // #nosec G204 -- exact current test executable and constant test selector.
		command.Env = append(os.Environ(), "MANDATARY_RECOVERY_PROCESS_FIXTURE="+filepath.Dir(file))
		command.Stdin = strings.NewReader(codes[0])
		output := new(bytes.Buffer)
		command.Stdout = output
		command.Stderr = output
		if e = command.Start(); e != nil {
			t.Fatal(e)
		}
		commands = append(commands, command)
		outputs = append(outputs, output)
	}
	consumed := 0
	for i, command := range commands {
		if e = command.Wait(); e != nil {
			t.Fatal("synthetic worker failed")
		}
		consumed += strings.Count(outputs[i].String(), "RECOVERY-CONSUMED")
	}
	if consumed != 1 {
		t.Fatal("separate processes did not consume exactly once", consumed)
	}
	if scalarFixture(t, db, `SELECT count(*) FROM recovery_capabilities`) != 1 {
		t.Fatal("multiple recovery capabilities created")
	}
}
