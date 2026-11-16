#!/usr/bin/env python3
"""Release acceptance harness (P1.20). Standard library only; drives the `docker` CLI and the real MCP client.

It extends the P1.19 image harness (tests/image/acceptance.py, run separately) with what the Phase 1 exit
criteria need on a packaged release candidate: a clean Compose deployment with containers A and B on a real
Docker daemon, the complete positive/negative authorization matrix over REST and over a real MCP client (the
official go-sdk client, tests/release/mcpclient), credential/policy lifecycle, exact usage counts, restart and
SIGKILL durability, backup restore into fresh instances with explicit reapproval, forward migration of existing
data, and the measured footprint against the technical-decisions.md §10.2 budgets.

It runs ONLY against an isolated, disposable Docker host (the approved test VM, or a hosted CI runner), under the
same guard as the image harness: an explicit --docker-host unix:///absolute/path plus the declared daemon identity
(--expect-daemon-id and/or --expect-daemon-name), verified before the first file, container or network is created
and again before cleanup. Nothing ambient (DOCKER_HOST, the CLI context) is consulted. Every resource carries a
unique run prefix and is removed at the end; it never prunes and never touches resources it did not create.

    python3 tests/release/release.py --image mandatary:local --platform linux/amd64 --repo . \
        --docker-host unix:///var/run/docker.sock --expect-daemon-id <ID> --work /srv/mandatary/tests/<task>/work \
        --host-binary ./out/mandatary --mcp-client ./out/mcpclient --sha <40 hex> --results results.json

Every result line is PASS, FAIL or BLOCKED with a stable id. Nothing is skipped silently. Secrets (key, passwords,
tokens, cookies, TOTP seeds) exist only in memory and ephemeral 0600 files under --work and are never printed.
"""
import argparse
import json
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "image"))  # also under `python3 -I`, which drops the script directory
sys.path.insert(0, HERE)
import isolation  # noqa: E402
from acceptance import Env, Fail  # noqa: E402

import core  # noqa: E402
import footprint  # noqa: E402
import ops  # noqa: E402
import recovery  # noqa: E402
from ctx import Ctx  # noqa: E402


def _terminate(signum, frame):
    raise KeyboardInterrupt("terminated by signal %d" % signum)


def stage(c, name, fn):
    t0 = time.time()
    if name in (c.a.skip or "").split(","):  # diagnostics only: a skipped stage yields no result, so no criterion can link to it (never a pass)
        c.ev.setdefault("stage_seconds", {})[name] = "skipped"
        return True
    try:
        fn(c)
        c.ev.setdefault("stage_seconds", {})[name] = round(time.time() - t0, 1)
        return True
    except Fail as e:
        c.check(name + "-ERROR", name + " aborted", False, str(e))
    except Exception as e:  # noqa: BLE001 - report, never crash silently
        c.check(name + "-ERROR", name + " crashed", False, type(e).__name__ + ": " + str(e)[:300])
    return False


def environment(c):
    e = c.e
    c.ev["environment"].update(describe_environment(e.docker("version", "--format", "{{json .}}", check=False).stdout, e.docker("info", "--format", "{{json .}}", check=False).stdout,
                                                    e.docker("compose", "version", "--short", check=False).stdout.strip()))
    c.ev["environment"]["fsync_4k_work_filesystem"] = footprint.fsync_latency(c.e.work)
    c.ev["environment"]["host_cpus"] = os.cpu_count()


def describe_environment(version_json, info_json, compose):
    """The facts a reader needs to judge a measurement. A missing field is recorded as null and named in `missing`; it is never silently dropped."""
    try:
        srv = json.loads(version_json).get("Server") or {}
        info = json.loads(info_json)
    except ValueError:
        return {"error": "docker version/info unreadable", "missing": ["all"]}
    out = {"docker_server": srv.get("Version"), "api": srv.get("ApiVersion"), "os_arch": "%s/%s" % (srv.get("Os"), srv.get("Arch")), "kernel": info.get("KernelVersion"),
           "os": info.get("OperatingSystem"), "cpus": info.get("NCPU"), "memory_bytes": info.get("MemTotal"), "storage_driver": info.get("Driver"),
           "cgroup": "%s v%s" % (info.get("CgroupDriver"), info.get("CgroupVersion")), "compose": compose or None, "daemon_id": info.get("ID")}
    missing = [k for k, v in out.items() if v in (None, "", "None/None", "None vNone")]
    if missing:
        out["missing"] = missing
    return out


def run(c):
    stage(c, "IMG", core.image_facts)
    environment(c)
    core.start_fixtures(c)
    if not stage(c, "DEPLOY", core.deploy_main):
        return
    stage(c, "IDLE-FRESH", lambda c: core.measure_idle(c, "fresh"))
    if not stage(c, "SETUP", core.bootstrap_main):
        return
    if not stage(c, "IDENTITIES", core.create_identities):
        return
    core.make_executors(c)
    stage(c, "MATRIX", core.run_matrix)
    stage(c, "LIFECYCLE", core.lifecycle)
    stage(c, "LATENCY", ops.latency_probe)
    stage(c, "IDLE-CONFIGURED", lambda c: core.measure_idle(c, "configured"))
    stage(c, "LOAD", lambda c: ops.load(c, c.a.load_seconds))
    stage(c, "PERSISTENCE", ops.persistence)
    stage(c, "RESTORE", recovery.restore_scenarios)
    stage(c, "MIGRATION", recovery.migration)
    stage(c, "DEVFLOW", core.devflow)
    stage(c, "DOCS", core.docs_check)
    stage(c, "LOGLEVEL", core.log_levels)
    stage(c, "LOGS", core.log_scan)




def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--platform", required=True, choices=["linux/amd64", "linux/arm64"])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--host-binary", required=True)
    ap.add_argument("--mcp-client", required=True, help="the tests/release/mcpclient binary for this platform")
    ap.add_argument("--mig-tool", help="the tests/release/migfixture binary for this platform (migration scenario)")
    ap.add_argument("--sha", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--oci-archive", help="a precomputed OCI archive of the image under test (otherwise built with buildx)")
    ap.add_argument("--load-seconds", type=int, default=60)
    ap.add_argument("--count-requests", action="store_true", help="diagnostics only (R2 measurement): stop the service gracefully after the load window to read its daemon request counters, then start it again")
    ap.add_argument("--idle-window", type=int, default=300, help="seconds of RSS curve per idle measurement")
    ap.add_argument("--docker-host", required=True)
    ap.add_argument("--skip", default="", help="comma list of stage names to skip (diagnostics only; the final evidence run never skips)")
    ap.add_argument("--expect-daemon-id")
    ap.add_argument("--expect-daemon-name")
    a = ap.parse_args()
    if not (a.expect_daemon_id or a.expect_daemon_name):
        ap.error("--expect-daemon-id and/or --expect-daemon-name is mandatory (the isolation identity of the fixture daemon)")
    started = time.time()
    os.environ.pop("DOCKER_CONTEXT", None)
    os.environ["DOCKER_HOST"] = a.docker_host

    def write(doc):
        with open(a.results, "w") as fh:
            json.dump(doc, fh, indent=1, default=str)
        print("SUMMARY pass=%d not_pass=%d" % (doc["pass"], doc["not_pass"]))
        return 1 if doc["not_pass"] else 0

    head = {"task": "t_836268ff", "source_sha": a.sha, "image": a.image, "platform": a.platform}
    try:
        isolation.verify(a.docker_host, a.expect_daemon_id, a.expect_daemon_name)
    except isolation.Refused as ex:
        print("FAIL ISO-00 the Docker endpoint is not an approved isolated fixture daemon -- " + str(ex), flush=True)
        item = {"id": "ISO-00", "name": "the Docker endpoint is not an approved isolated fixture daemon", "status": "FAIL", "detail": str(ex)}
        return write(dict(head, seconds=round(time.time() - started), **{"pass": 0, "not_pass": 1, "results": [item]}))
    unsafe = isolation.unsafe_ancestors(a.work)
    if unsafe:
        why = "; ".join("%s %s" % kv for kv in unsafe)
        print("FAIL WORK-00 the --work path is not under owner-only directories -- " + why, flush=True)
        item = {"id": "WORK-00", "name": "the --work path is not under owner-only directories (product storage rule)", "status": "FAIL", "detail": why}
        return write(dict(head, seconds=round(time.time() - started), **{"pass": 0, "not_pass": 1, "results": [item]}))
    signal.signal(signal.SIGTERM, _terminate)  # a background job inherits SIGINT=ignored; SIGTERM must still run the cleanup
    env = Env(a)
    env.pfx = "p120" + env.pfx[4:]  # resources of this card carry the card's own prefix (the harness base class says p119)
    env.res.check("ISO-00", "the Docker endpoint is the declared isolated fixture daemon (explicit endpoint, identity verified, not Unraid)", True)
    c = Ctx(env, a)
    try:
        run(c)
    finally:
        try:
            isolation.verify(a.docker_host, a.expect_daemon_id, a.expect_daemon_name)
            same = True
        except isolation.Refused as ex:
            same = False
            env.res.check("ISO-01", "the daemon is still the declared fixture daemon before cleanup", False, "cleanup refused: " + str(ex))
        if same:
            env.res.check("ISO-01", "the daemon is still the declared fixture daemon before cleanup", True)
            env.cleanup()
    fails = [i for i in env.res.items if i["status"] != "PASS"]
    doc = dict(head, prefix=env.pfx, seconds=round(time.time() - started), evidence=c.ev, **{"pass": sum(1 for i in env.res.items if i["status"] == "PASS"), "not_pass": len(fails), "results": env.res.items})
    return write(doc)


if __name__ == "__main__":
    sys.exit(main())
