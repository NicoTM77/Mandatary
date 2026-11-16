#!/usr/bin/env python3
"""Mutation run for the bounded continuity cache (P1.20 R2). Applies one mutant at a time to a scratch COPY of the
tree, runs the internal/docker suite, and records which tests fail. Never touches the worktree."""
import json, os, re, shutil, subprocess, sys

WT = "/workspaces/Mandatary/.worktrees/t_836268ff"
SCR = "/opt/data/scratch/p1203/mut"
TREE = SCR + "/tree"
ENV = open("/opt/data/scratch/p1203/env.sh").read()

MUTANTS = [
    ("M01 publish without the epoch check", "internal/docker/continuity.go",
     "if m.closed || m.state != StateVerified || fl.epoch != m.epoch {", "if m.closed || m.state != StateVerified {"),
    ("M02 refresh outcome ignores the epoch (publishes a late refresh of an older epoch)", "internal/docker/continuity.go",
     "still := !m.closed && m.state == StateVerified && m.epoch == fl.epoch", "still := !m.closed && m.state == StateVerified"),
    ("M03 <= instead of < at the TTL", "internal/docker/continuity.go",
     "return age >= 0 && age < m.ttl", "return age >= 0 && age <= m.ttl"),
    ("M04 start time taken after the reads", "internal/docker/continuity.go",
     "\terr := a.refreshContinuity(lctx, kind)\n\tcancel()\n", "\terr := a.refreshContinuity(lctx, kind)\n\tcancel()\n\tfl.start = m.clock()\n"),
    ("M05 an older snapshot serves a read regardless of age", "internal/docker/continuity.go",
     "return age >= 0 && age < m.ttl", "_ = age\n\treturn true"),
    ("M06 mutations may use the TTL path", "internal/docker/continuity.go",
     "\tif mode != modeRead {\n\t\treturn false\n\t}\n", ""),
    ("M07 waiter's internal deadline treated as local", "internal/docker/continuity.go",
     "if errors.Is(context.Cause(ctx), ErrSafetyCheckDeadline) {", "if errors.Is(context.Cause(ctx), ErrSafetyCheckDeadline) && false {"),
    ("M08 leader fault-with-cancel classified as local", "internal/docker/sdk.go",
     "if isStreamConsumerAbort(ctx, err) {", "if ctx.Err() != nil {"),
    ("M09 invalidation does not clear the snapshot", "internal/docker/safety.go",
     "\tm.contValid = false // no snapshot outlives a revocation\n", ""),
    ("M10 VerifyInventory skipped on the resolve list", "internal/docker/sdk.go",
     "\tif err := a.safety.VerifyInventory(candidates); err != nil {\n\t\treturn nil, err\n\t}\n\treturn items, nil", "\t_ = candidates\n\treturn items, nil"),
    ("M11 TTL validation accepts 2 s", "internal/docker/sdk.go",
     "opts.ContinuityTTL > MaxContinuityTTL", "opts.ContinuityTTL > 2*MaxContinuityTTL"),
    ("M12 a snapshot published before the caller arrived covers a mutation", "internal/docker/continuity.go",
     "if m.contSeq > arrivalSeq {", "if m.contSeq >= arrivalSeq {"),
    ("M13 a leader's pure abort fails its waiters", "internal/docker/continuity.go",
     "fl.outcome = outcomeLocalAbort", "fl.outcome = outcomeFault"),
    ("M14 no refresh ceiling", "internal/docker/continuity.go",
     "lctx, cancel := context.WithTimeoutCause(ctx, continuityRefreshCeiling, ErrSafetyCheckDeadline)", "lctx, cancel := context.WithCancel(ctx)"),
    ("M15 snapshot may move backwards", "internal/docker/continuity.go",
     "(fl.seq <= m.contSeq || fl.start.Before(m.contStart))", "false"),
    ("M16 waiters never share (every caller leads)", "internal/docker/continuity.go",
     "if fl := m.flight; fl != nil && fl.epoch == m.epoch {", "if fl := m.flight; false && fl != nil && fl.epoch == m.epoch {"),
    ("M17 waiter cancel treated as a fault", "internal/docker/continuity.go",
     "\t\treturn SanitizeError(ctx.Err())\n\t}\n}", "\t\tm.drop(Drop{Reason: DropOperationFault, Step: StepContinuity, Cause: CauseCanceled})\n\t\treturn ErrUnverified\n\t}\n}"),
]

def sh(cmd, **kw):
    return subprocess.run(["bash", "-c", ENV + "\n" + cmd], capture_output=True, text=True, **kw)

def prep():
    shutil.rmtree(TREE, ignore_errors=True)
    os.makedirs(TREE)
    files = subprocess.run(["git", "-C", WT, "ls-files", "-co", "--exclude-standard"], capture_output=True, text=True).stdout.split("\n")
    for f in files:
        if not f or f.startswith("web/node_modules") or not os.path.isfile(os.path.join(WT, f)):
            continue
        d = os.path.join(TREE, os.path.dirname(f))
        os.makedirs(d, exist_ok=True)
        shutil.copy2(os.path.join(WT, f), os.path.join(TREE, f))
    if os.path.isdir(WT + "/web/dist"):
        shutil.copytree(WT + "/web/dist", TREE + "/web/dist", dirs_exist_ok=True)

def main():
    only = sys.argv[1:] 
    prep()
    results = []
    for name, rel, old, new in MUTANTS:
        if only and not any(name.startswith(o) for o in only):
            continue
        orig = open(os.path.join(WT, rel)).read()
        if orig.count(old) != 1:
            results.append({"mutant": name, "status": "PATTERN-NOT-UNIQUE", "count": orig.count(old)})
            print(name, "PATTERN NOT UNIQUE", orig.count(old), flush=True)
            continue
        open(os.path.join(TREE, rel), "w").write(orig.replace(old, new))
        r = sh("cd " + TREE + " && go test -count=1 -timeout 240s ./internal/docker/ 2>&1", timeout=600)
        out = r.stdout
        fails = sorted(set(re.findall(r"--- FAIL: (\S+)", out)))
        built = "build failed" not in out and "[build failed]" not in out
        status = "KILLED" if fails and built else ("BUILD-FAILED" if not built else "SURVIVED")
        timed_out = "panic: test timed out" in out
        results.append({"mutant": name, "status": status, "failing": fails[:12], "n_failing": len(fails), "timed_out": timed_out})
        print(name, status, len(fails), "TIMEOUT" if timed_out else "", fails[:6], flush=True)
        open(os.path.join(TREE, rel), "w").write(orig)
        open(SCR + "/log-" + name.split()[0] + ".txt", "w").write(out[-6000:])
    json.dump(results, open(SCR + "/mutation-results.json", "w"), indent=1)
    print("DONE", sum(1 for x in results if x["status"] == "KILLED"), "killed of", len(results))

main()
