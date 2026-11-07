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

func TestTOTPSeparateProcessesAcceptOnce(t *testing.T) {
	if path := os.Getenv("MANDATARY_TOTP_PROCESS_FIXTURE"); path != "" {
		code, e := io.ReadAll(io.LimitReader(os.Stdin, 7))
		if e != nil || len(code) != 6 {
			t.Fatal("invalid synthetic proof input")
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
		l.now = func() time.Time { return time.Unix(2000000040, 0) }
		_, e = l.VerifyTOTP(t.Context(), "u", os.Getenv("MANDATARY_TOTP_BINDING"), string(code), "192.0.2.2")
		if e != nil && e != ErrDenied {
			t.Fatal("unexpected child failure")
		}
		if e == nil {
			_, _ = fmt.Fprintln(os.Stdout, "TOTP-ACCEPTED")
		}
		return
	}
	l, db, session := lifecycleFixture(t)
	factor := queueBindingNotice(t, l, session)
	var file string
	if e := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&file); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	code := enrollmentCode(t, factor, time.Unix(2000000040, 0))
	commands := []*exec.Cmd{}
	outputs := []*bytes.Buffer{}
	for i := 0; i < 2; i++ {
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestTOTPSeparateProcessesAcceptOnce$") // #nosec G204 -- exact current test executable and constant test selector.
		command.Env = append(os.Environ(), "MANDATARY_TOTP_PROCESS_FIXTURE="+filepath.Dir(file), "MANDATARY_TOTP_BINDING="+factor.ID)
		command.Stdin = strings.NewReader(code)
		output := new(bytes.Buffer)
		command.Stdout = output
		command.Stderr = output
		if e = command.Start(); e != nil {
			t.Fatal(e)
		}
		commands = append(commands, command)
		outputs = append(outputs, output)
	}
	accepted := 0
	for i, command := range commands {
		if e = command.Wait(); e != nil {
			t.Fatal("synthetic worker failed")
		}
		accepted += strings.Count(outputs[i].String(), "TOTP-ACCEPTED")
	}
	if accepted != 1 {
		t.Fatal("separate processes did not accept exactly once", accepted)
	}
	if scalarFixture(t, db, `SELECT count(*) FROM totp_acceptances WHERE verifier_period=2000000040/30`) != 1 {
		t.Fatal("replay period state not durable")
	}
}
