package auth

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Abrupt child-process termination after durable consumption, before secret
// response delivery or repository cleanup. No production crash/fault switch.
func TestRecoveryCrashBeforeResponseCannotRedisplayOrReuse(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	codes := batch.ExportOnce()
	var file string
	if err = db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&file); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), executable, "-test.run=^TestRecoverySeparateProcessesConsumeOnce$") // #nosec G204 -- current test executable with constant selector, no shell/input command.
	command.Env = append(os.Environ(), "MANDATARY_RECOVERY_PROCESS_FIXTURE="+filepath.Dir(file), "MANDATARY_RECOVERY_CRASH=1")
	command.Stdin = strings.NewReader(codes[0])
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 || len(output) != 0 {
		t.Fatal("synthetic worker did not crash at pre-response boundary")
	}
	l = reopenLifecycle(t, l, db)
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.2"); err != ErrDenied {
		t.Fatal("crash revived consumed saved code")
	}
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[1], "192.0.2.3"); err != nil {
		t.Fatal("independent saved code unavailable after lost response")
	}
}
