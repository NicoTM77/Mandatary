//go:build linux

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const helperEnv = "MANDATARY_TEST_TERMINAL_HELPER"
const helperSecret = "SYNTHETIC-TERMINAL-SECRET-0001"

// TestMain doubles as the child process for the real-terminal tests: the child is
// started with a pseudo-terminal as its CONTROLLING terminal (or deliberately not),
// and runs the production hostTerminal against its real fds 0/1/2.
func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		term := newHostTerminal()
		if err := term.Verify(); err != nil {
			_, _ = os.Stderr.WriteString("VERIFY-REFUSED\n")
			os.Exit(3)
		}
		if err := term.WriteSecret(context.Background(), []byte(helperSecret+"\n")); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err = os.OpenFile("/dev/pts/"+itoaPTY(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func itoaPTY(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func runHelper(t *testing.T, configure func(cmd *exec.Cmd, master *os.File, slave *os.File)) (exit int, ptyOutput string) {
	t.Helper()
	master, slave := openPTY(t)
	cmd := exec.Command(os.Args[0], "-test.run=NONE")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	configure(cmd, master, slave)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var captured bytes.Buffer
	read := make(chan struct{})
	go func() {
		defer close(read)
		buf := make([]byte, 4096)
		for {
			_ = master.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := master.Read(buf)
			captured.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	select {
	case waitErr := <-done:
		_ = waitErr // the exit status is asserted from ProcessState below
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("helper timed out")
	}
	_ = slave.Close()
	<-read
	exit = cmd.ProcessState.ExitCode()
	return exit, captured.String()
}

// S3.1a: the secret is written ONLY when stdin, stdout and stderr are all the
// process's real controlling terminal.
func TestHostTerminalAcceptsOnlyTheControllingTerminal(t *testing.T) {
	t.Run("controlling terminal on all three fds", func(t *testing.T) {
		exit, out := runHelper(t, func(cmd *exec.Cmd, _, slave *os.File) {
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		})
		if exit != 0 || !strings.Contains(out, helperSecret) {
			t.Fatalf("exit %d output %q", exit, out)
		}
	})
	for name, wire := range map[string]func(t *testing.T, cmd *exec.Cmd, slave *os.File, dir string){
		"stdout piped": func(_ *testing.T, cmd *exec.Cmd, slave *os.File, _ string) {
			cmd.Stdin, cmd.Stderr = slave, slave
			cmd.Stdout = io.Discard // an os/exec pipe
		},
		"stdout redirected to a file": func(t *testing.T, cmd *exec.Cmd, slave *os.File, dir string) {
			f, err := os.Create(dir + "/out")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, f, slave
		},
		"stdin from /dev/null": func(_ *testing.T, cmd *exec.Cmd, slave *os.File, _ string) {
			cmd.Stdout, cmd.Stderr = slave, slave // Stdin nil = /dev/null
		},
		"stderr piped": func(_ *testing.T, cmd *exec.Cmd, slave *os.File, _ string) {
			cmd.Stdin, cmd.Stdout = slave, slave
			cmd.Stderr = io.Discard
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			exit, out := runHelper(t, func(cmd *exec.Cmd, _, slave *os.File) {
				wire(t, cmd, slave, dir)
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
				if cmd.Stdin == nil {
					cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
				}
			})
			if exit != 3 {
				t.Fatalf("exit %d, want 3 (refused); out %q", exit, out)
			}
			if strings.Contains(out, helperSecret) {
				t.Fatal("the secret reached a non-verified channel")
			}
			if b, _ := os.ReadFile(dir + "/out"); strings.Contains(string(b), helperSecret) {
				t.Fatal("the secret reached a redirected file")
			}
		})
	}
	t.Run("a terminal that is not this session's controlling terminal", func(t *testing.T) {
		exit, out := runHelper(t, func(cmd *exec.Cmd, _, slave *os.File) {
			// A new session WITHOUT adopting the pty as controlling terminal: the
			// fds are real ttys, but not this process's controlling terminal.
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		})
		if exit != 3 || strings.Contains(out, helperSecret) {
			t.Fatalf("exit %d output %q", exit, out)
		}
	})
}
