package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// The host-local helper (security-contracts.md S3.1b): short-lived subcommands of
// the SAME static binary, run by a trusted host administrator on the host. They
// never start the server, discover Docker, open a Docker socket, create or
// migrate a store, edit policy or accept any secret through argv/env/stdin. The
// token is written only to the verified controlling terminal.

const cliUsage = `usage:
  mandatary setup status|rotate|reveal [flags]
  mandatary recovery reset-mfa --user NAME --acknowledge-all-factors-lost-risk [--replace-password] [flags]
  mandatary recovery reveal --user NAME [flags]
  mandatary recovery restore-admin            (unavailable until the restore service exists)
flags:
  --data-dir PATH         existing data directory (default $MANDATARY_DATA_DIR, then /data)
  --uid N --gid N         numeric service identity; REQUIRED when launched as root
  --master-key-file PATH  key file readable by that identity (default $MANDATARY_MASTER_KEY_FILE)
`

// cliEnv carries every external dependency so the protocol is testable without
// real privileges or a real terminal. Production wiring is in main().
type cliEnv struct {
	args           []string
	getenv         func(string) string
	stdout, stderr io.Writer
	euid, egid     int
	drop           func(uid, gid int) error
	terminal       auth.Terminal
}

func productionCLI(args []string) cliEnv {
	return cliEnv{args: args, getenv: os.Getenv, stdout: os.Stdout, stderr: os.Stderr, euid: os.Geteuid(), egid: os.Getegid(), drop: dropPrivileges, terminal: newHostTerminal()}
}

// buildIdentity ties a host helper to the binary that issued a token. A helper
// built from a different revision refuses to reveal. An unstamped build (no VCS
// information, e.g. a test binary) is its own identity and is never "equal" to a
// stamped one.
func buildIdentity() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unstamped"
	}
	revision, modified := "", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" || len(revision) > 64 {
		return "unstamped"
	}
	if modified == "true" {
		return "rev:" + revision + "+dirty"
	}
	return "rev:" + revision
}

// cliFailure prints a FIXED message. No error, path, argument or storage detail
// is ever echoed, so a failing command cannot disclose a secret or a layout.
func (e cliEnv) fail(message string) int {
	_, _ = fmt.Fprintln(e.stderr, "mandatary: "+message)
	return 1
}

type cliFlags struct {
	dataDir, keyFile string
	uid, gid         int
	uidSet, gidSet   bool
	user             string
	replacePassword  bool
	acknowledge      bool
}

type optionalInt struct {
	value *int
	set   *bool
}

func (o optionalInt) String() string { return "" }
func (o optionalInt) Set(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 1<<31-2 {
		return errors.New("invalid numeric identity")
	}
	*o.value, *o.set = n, true
	return nil
}

func parseCLIFlags(e cliEnv, args []string) (cliFlags, bool) {
	f := cliFlags{dataDir: e.getenv("MANDATARY_DATA_DIR"), keyFile: e.getenv("MANDATARY_MASTER_KEY_FILE")}
	if f.dataDir == "" {
		f.dataDir = "/data"
	}
	fs := flag.NewFlagSet("mandatary", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.dataDir, "data-dir", f.dataDir, "")
	fs.StringVar(&f.keyFile, "master-key-file", f.keyFile, "")
	fs.Var(optionalInt{&f.uid, &f.uidSet}, "uid", "")
	fs.Var(optionalInt{&f.gid, &f.gidSet}, "gid", "")
	fs.StringVar(&f.user, "user", "", "")
	fs.BoolVar(&f.replacePassword, "replace-password", false, "")
	fs.BoolVar(&f.acknowledge, "acknowledge-all-factors-lost-risk", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return cliFlags{}, false
	}
	return f, true
}

// resolveIdentity applies S3.1b step 2: a root launch must name the numeric
// service identity explicitly and is dropped to it; a non-root launch may only
// name its own identity. UID/GID 0 are never accepted.
func resolveIdentity(e cliEnv, f cliFlags) (uid, gid int, drop bool, ok bool) {
	if e.euid == 0 {
		if !f.uidSet || !f.gidSet || f.uid <= 0 || f.gid <= 0 {
			return 0, 0, false, false
		}
		return f.uid, f.gid, true, true
	}
	if e.euid <= 0 || e.egid <= 0 || (f.uidSet && f.uid != e.euid) || (f.gidSet && f.gid != e.egid) {
		return 0, 0, false, false
	}
	return e.euid, e.egid, false, true
}

// runCLI returns 0 on success, 1 on any refusal/failure and 2 on usage errors.
func runCLI(e cliEnv) int {
	if len(e.args) == 0 {
		_, _ = fmt.Fprint(e.stderr, cliUsage)
		return 2
	}
	group, rest := e.args[0], e.args[1:]
	if (group != "setup" && group != "recovery") || len(rest) == 0 {
		_, _ = fmt.Fprint(e.stderr, cliUsage)
		return 2
	}
	command, rest := rest[0], rest[1:]
	switch group + " " + command {
	case "setup status", "setup rotate", "setup reveal", "recovery reset-mfa", "recovery reveal":
	case "recovery restore-admin":
		return e.fail("restore-administrator recovery is not available until the restore service is delivered")
	default:
		_, _ = fmt.Fprint(e.stderr, cliUsage)
		return 2
	}
	flags, ok := parseCLIFlags(e, rest)
	if !ok {
		_, _ = fmt.Fprint(e.stderr, cliUsage)
		return 2
	}
	if group == "recovery" && flags.user == "" {
		_, _ = fmt.Fprint(e.stderr, cliUsage)
		return 2
	}
	uid, gid, drop, ok := resolveIdentity(e, flags)
	if !ok {
		return e.fail("service identity unsupported: launch as the mapped non-root service UID/GID, or as root with explicit --uid/--gid")
	}
	// Privileges are dropped (and verified) BEFORE any key, data or reveal file is
	// opened. Failure to drop is fatal; nothing is retried at a higher privilege.
	if drop {
		if err := e.drop(uid, gid); err != nil {
			return e.fail("cannot drop to the configured service identity")
		}
	}
	if flags.keyFile == "" {
		return e.fail("a master key FILE is required (the key is never read from argv or the environment by this helper)")
	}
	key, err := store.LoadMasterKey("", flags.keyFile)
	if err != nil {
		return e.fail("master key unavailable or unsafe")
	}
	ctx := context.Background()
	repo, err := store.Open(ctx, store.Options{DataDir: flags.dataDir, MasterKey: key, OwnerUID: uid, OwnerGID: gid, ExistingOnly: true})
	if err != nil {
		return e.fail("existing store unavailable or unsafe; this helper never creates or migrates one")
	}
	defer func() { _ = repo.Close() }()
	setup, err := auth.NewSetup(repo, nil, auth.SetupSettings{Build: buildIdentity()})
	if err != nil {
		return e.fail("setup service unavailable")
	}
	switch group + " " + command {
	case "setup status":
		return e.status(ctx, setup)
	case "setup rotate":
		return e.issue(ctx, setup, auth.IssueRequest{Purpose: auth.PurposeInitialSetup}, "initial-setup", "")
	case "setup reveal":
		return e.reveal(ctx, setup, auth.PurposeInitialSetup, "")
	case "recovery reset-mfa":
		if !flags.acknowledge {
			return e.fail("--acknowledge-all-factors-lost-risk is required: this trusted-host ceremony is not NIST AAL2 account recovery")
		}
		return e.issue(ctx, setup, auth.IssueRequest{Purpose: auth.PurposeMFAReset, Username: flags.user, ReplacePassword: flags.replacePassword, RiskAcknowledged: true}, "MFA-reset", flags.user)
	default: // recovery reveal
		return e.reveal(ctx, setup, auth.PurposeMFAReset, flags.user)
	}
}

func (e cliEnv) status(ctx context.Context, s *auth.Setup) int {
	if _, err := s.Reconcile(ctx); err != nil {
		return e.fail("status unavailable")
	}
	status, err := s.Status(ctx)
	if err != nil {
		return e.fail("status unavailable")
	}
	_, _ = fmt.Fprintf(e.stdout, "setup eligible: %t\nsetup completed: %t\n", status.Eligible, status.Completed)
	for _, t := range status.Tokens {
		_, _ = fmt.Fprintf(e.stdout, "generation %d purpose %s state %s expires %s expired %t\n", t.Generation, t.Purpose, t.State, t.ExpiresAt.Format(time.RFC3339), t.Expired)
	}
	return 0
}

func (e cliEnv) issue(ctx context.Context, s *auth.Setup, req auth.IssueRequest, label, user string) int {
	if _, err := s.Reconcile(ctx); err != nil {
		return e.fail("cannot reconcile existing state; resolve it before issuing")
	}
	t, err := s.Issue(ctx, req)
	if err != nil {
		return e.fail("issuance refused (not eligible, unsafe state or clock uncertainty)")
	}
	_, _ = fmt.Fprintf(e.stdout, "%s generation %d issued, absolute expiry %s. No secret was printed; run the matching reveal command on this host terminal.\n", label, t.Generation, t.ExpiresAt.Format(time.RFC3339))
	return 0
}

func (e cliEnv) reveal(ctx context.Context, s *auth.Setup, purpose auth.SetupPurpose, user string) int {
	if _, err := s.Reconcile(ctx); err != nil {
		return e.fail("cannot reconcile existing state; resolve it before revealing")
	}
	result, err := s.Reveal(ctx, purpose, user, e.terminal)
	if err != nil {
		return e.fail("reveal refused: no revealable generation, expired, unsafe layout, build mismatch or not on a real controlling terminal; rotate or re-issue if it was already shown")
	}
	_, _ = fmt.Fprintf(e.stdout, "generation %d shown once; absolute expiry %s.\n", result.Generation, result.ExpiresAt.Format(time.RFC3339))
	return 0
}
