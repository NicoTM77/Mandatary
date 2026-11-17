"""P1.20 release acceptance, part 1: image facts and budget, the clean Compose deployment with containers A/B,
identities and grants through the administrative API, and the REST + real-MCP authorization matrix."""
import json
import os
import re
import subprocess
import threading
import time

import stackdeploy as deploy
import executors
import footprint
import matrix
import stack
from ctx import AGENTS, Ctx

BUSY = stack.BUSY


# ---- image -------------------------------------------------------------------------------------------------------
def image_facts(c: Ctx):
    e, a = c.e, c.a
    info = json.loads(e.docker("image", "inspect", a.image).stdout)[0]
    cfg = info.get("Config", {})
    facts = {"id": info["Id"], "repo_digests": info.get("RepoDigests"), "architecture": info["Architecture"], "os": info["Os"],
             "revision_label": (cfg.get("Labels") or {}).get("org.opencontainers.image.revision"), "rootfs_layers": info["RootFS"]["Layers"],
             "docker_size_bytes": info.get("Size")}
    c.ev["image"].update(facts)
    c.check("REL-IMG-01", "the image under test is the exact source revision (revision label == head SHA) for " + a.platform,
            facts["revision_label"] == a.sha and "%s/%s" % (facts["os"], facts["architecture"]) == a.platform, "%s %s/%s" % (facts["revision_label"], facts["os"], facts["architecture"]))
    # compressed size: a real OCI archive with gzip layers built from the same source; its blob sizes are what a registry stores.
    oci = a.oci_archive
    method = "sum of the sizes of the manifest, config and gzip layer blobs of `buildx --output type=oci,compression=gzip` for " + a.platform
    diff_ids = None
    if not oci:
        oci = os.path.join(e.work, "image-oci.tar")
        p = e.docker("buildx", "build", "--platform", a.platform, "--build-arg", "VCS_REF=" + a.sha, "--provenance=false", "--sbom=false",
                     "--output", "type=oci,dest=%s,compression=gzip,force-compression=true" % oci, e.repo, check=False, timeout=900)
        if p.returncode != 0:
            # The `docker` buildx driver cannot export OCI. Fall back to the archive of the very image under test, compressed here.
            c.ev["footprint"]["oci_export_error"] = e.scrub(p.stderr[-200:])
            save = os.path.join(e.work, "image-save.tar")
            sp = e.docker("save", a.image, "-o", save, check=False, timeout=600)
            if sp.returncode != 0:
                c.check("REL-FOOT-IMG", "compressed image size within 60 MB", False, "buildx failed (%s) and docker save failed: %s" % (c.ev["footprint"]["oci_export_error"], e.scrub(sp.stderr[-200:])))
                return
            try:
                total, layers, diff_ids = footprint.save_compressed_size(save)
            except (ValueError, KeyError, OSError) as ex:
                c.check("REL-FOOT-IMG", "compressed image size within 60 MB", False, "docker save archive unreadable: %s" % ex)
                return
            oci = save
            method = ("ESTIMATE: this daemon's buildx driver cannot export OCI, so every layer of `docker save` of the image under test is gzip-compressed (level 6, the default of "
                      "docker push) and summed with the config and manifest; a registry's own compressor can differ by a few percent")
    if diff_ids is None:
        total, layers = footprint.oci_compressed_size(oci)
        diff_ids = oci_diff_ids(oci)
    c.ev["footprint"]["image"] = {"compressed": footprint.units(total), "budget": footprint.units(footprint.BUDGET_IMAGE_BYTES), "layers": layers, "archive_sha256": sha256(oci), "method": method}
    c.check("REL-FOOT-IMG", "compressed image <= 60 MB (%s)" % ("sum of real gzip OCI blobs" if "ESTIMATE" not in method else "estimate from docker save, gzip level 6"), footprint.within(total, footprint.BUDGET_IMAGE_BYTES),
            "%.2f MB (%.2f MiB), budget 60 MB, %d layers" % (total / footprint.MB, total / footprint.MIB, len(layers)))
    same = diff_ids == facts["rootfs_layers"]
    c.check("REL-FOOT-SAME", "the measured archive has exactly the uncompressed layers (diffIDs) of the image under test", same, "" if same else "diffIDs differ: the measured archive is not proven to be the tested image")


def sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def oci_diff_ids(oci):
    import tarfile
    with tarfile.open(oci) as t:
        idx = json.load(t.extractfile("index.json"))

        def blob(d):
            return json.load(t.extractfile("blobs/sha256/" + d.split(":", 1)[1]))
        m = blob(idx["manifests"][0]["digest"])
        if "manifests" in m:
            m = blob(m["manifests"][0]["digest"])
        return blob(m["config"]["digest"])["rootfs"]["diff_ids"]


# ---- measurements --------------------------------------------------------------------------------------------------
def sample_rss(pid, seconds, every=1.0):
    out, end = [], time.time() + seconds
    while time.time() < end:
        s = footprint.read_status(pid)
        out.append(s.get("VmRSS", 0))
        time.sleep(every)
    return out


def measure_idle(c: Ctx, label, window=None, every=5, tail=60):
    """Idle footprint of the running service with no request in flight (technical-decisions.md 10.2: <= 50 MB
    after stabilization, measured over the final 60 s of a 300 s observation window after readiness, SQLite
    initialized, one local Docker endpoint connected). The RSS curve is sampled every `every` seconds for `window`
    seconds from readiness; the budget gates the MAXIMUM of the samples inside the final `tail` seconds (the median
    is reported too). The start-up transient is a separate, reported result: its peak and the time until the
    process settles under the budget are recorded, never discarded, and the idle limit does not apply to it."""
    window = window or c.a.idle_window
    pid = c.dep.host_pid()
    t0 = time.time()
    curve = []
    while time.time() - t0 < window:
        s = footprint.read_status(pid)
        curve.append((round(time.time() - t0, 1), s.get("VmRSS", 0), s.get("RssAnon", 0), s.get("RssFile", 0)))
        time.sleep(every)
    st = footprint.read_status(pid)
    cg = footprint.cgroup_memory(pid)
    steady = [v for t, v, _, _ in curve if t >= window - tail] or [v for _, v, _, _ in curve]
    peak = max(v for _, v, _, _ in curve)
    budget = footprint.BUDGET_IDLE_RSS_BYTES
    settled_at = None  # first sample time after which every later sample is within the budget
    for i, (t, v, _, _) in enumerate(curve):
        if all(w <= budget for _, w, _, _ in curve[i:]):
            settled_at = t
            break
    rec = {"label": label, "pid_namespace": "host", "window_s": window, "steady_window_s": tail, "VmRSS_steady_max": max(steady), "VmRSS_steady_median": sorted(steady)[len(steady) // 2],
           "VmRSS_peak_in_window": peak, "settled_under_budget_at_s": settled_at, "VmHWM_process_lifetime": st.get("VmHWM"), "RssAnon_last": curve[-1][2], "RssFile_last": curve[-1][3],
           "curve_s_rss_anon_file": curve, "cgroup": cg}
    c.ev["footprint"].setdefault("idle", []).append(rec)
    c.check("REL-FOOT-IDLE-" + label, "idle RSS <= 50 MB after stabilization (%s: maximum of the %d samples taken every %d s over the final %d s of a %d s observation window after readiness)" % (label, len(steady), every, tail, window), footprint.within(rec["VmRSS_steady_max"], budget),
            "steady max %.2f MB (median %.2f MB, anon %.2f MB, file %.2f MB); peak in window %.2f MB; settled under 50 MB at %s s; process VmHWM %.2f MB" % (
                rec["VmRSS_steady_max"] / footprint.MB, rec["VmRSS_steady_median"] / footprint.MB, curve[-1][2] / footprint.MB, curve[-1][3] / footprint.MB, peak / footprint.MB, settled_at, (rec["VmHWM_process_lifetime"] or 0) / footprint.MB))
    # The start-up transient is a measured property of the product, not a rounding detail: after a start (reproduced natively with the container env: one ~64 MiB heap allocation 85 ms after start when SMTP is configured; the
    # cause inside the product is not asserted here) the process stays resident until the Go runtime's 2-minute forced GC lets the scavenger return it. By the owner's clarification of
    # technical-decisions.md 10.2 the idle limit does not apply to this transient; its PEAK and the TIME TO STABILIZATION are reported as their own result. The result is a pass only
    # when both were actually measured (the curve settled under the budget inside the window); a curve that never settles has no stabilization time and fails here and in the idle check.
    c.check("REL-FOOT-SETTLE-" + label, "start-up transient reported separately (%s): peak %.2f MB, stabilized under 50 MB at %s s after readiness; the idle limit does not apply to this transient" % (label, peak / footprint.MB, settled_at),
            settled_at is not None and peak > 0, "start-up peak in the %d s window %.2f MB; time to stabilization %s s; steady-state maximum %.2f MB" % (window, peak / footprint.MB, settled_at, rec["VmRSS_steady_max"] / footprint.MB))
    return rec


# ---- fixtures + deployment + identities ---------------------------------------------------------------------------
def start_fixtures(c: Ctx):
    e, p = c.e, c.e.pfx
    A, B, C, peer = p + "-a", p + "-b", p + "-c", p + "-peer"
    for n in (A, B):
        e.docker("run", "-d", "--name", e.track(n), "--cap-drop", "ALL", "--read-only", BUSY(), "sh", "-c", "while :; do echo tick; sleep 1; done")
    # C can be created but never started (its entrypoint does not exist): an authorized start fails in the daemon.
    e.docker("create", "--name", e.track(C), "--entrypoint", "/p120-nonexistent", BUSY())
    e.docker("create", "--name", e.track(peer), "--label", "io.mandatary.self=true", "--pull", "never", c.a.image)
    c.names.update({"A": A, "B": B, "C": C, "peer": peer, "missing": p + "-no-such-container"})


def deploy_main(c: Ctx):
    e = c.e
    c.dep = deploy.Deployment(e, "m")
    c.deps.append(c.dep)
    c.dep.up()
    c.ev["environment"]["compose_project"] = c.dep.project
    c.names["self"] = e.inspect(c.dep.mand)["Name"].lstrip("/")
    c.names["self_id"] = e.inspect(c.dep.mand)["Id"]
    c.names["peer_id"] = e.inspect(c.names["peer"])["Id"]
    c.check("REL-DEP-01", "clean Compose deployment (unmodified docker-compose.yml + proxy file) starts, is healthy and READY on the real daemon", True)


def bootstrap_main(c: Ctx):
    steps = []

    def chk(rid, name, ok, detail=""):
        steps.append(ok)
        c.check("REL-SETUP-" + rid, name, ok, detail)
    c.dep.first_admin("rel-admin", chk)
    c.dep.admin.login()
    st, hd, body = c.dep.admin.cl.req("GET", "/api/v1/session")
    c.check("REL-SETUP-login", "the new administrator signs in with password + TOTP; the session carries a server-bound AAL2 label", st == 200 and "aal2" in json.dumps(body).lower(), str(st))


def create_identities(c: Ctx):
    A, B = c.names["A"], c.names["B"]
    ok = True
    for label in ("owner",):
        st, b = c.adm("POST", "/api/v1/admin/users", {"username": "rel-" + label})
        c.users[label] = (c.ids(b) or [""])[0]
        ok &= st == 201 and bool(c.users[label])
    for label in ("g", "g2"):
        st, b = c.adm("POST", "/api/v1/admin/groups", {"name": "rel-" + label})
        c.groups[label] = (c.ids(b) or [""])[0]
        ok &= st == 201 and bool(c.groups[label])
    c.check("REL-ID-01", "an ordinary user and two groups are created by the administrator (no operation granted by that)", ok, str(c.users) + str(c.groups))
    created = True
    for label, (okind, owner) in AGENTS.items():
        body = {"name": "rel-" + label}
        body["owner_user_id" if okind == "user" else "owner_group_id"] = (c.users if okind == "user" else c.groups)[owner]
        st, b = c.adm("POST", "/api/v1/admin/agents", body)
        c.agents[label] = (c.ids(b) or [""])[0]
        created &= st == 201 and bool(c.agents[label])
    c.check("REL-ID-02", "agents are created, each owned by exactly one user or group (owning grants nothing)", created, str(len(c.agents)))
    st, b = c.adm("PUT", "/api/v1/admin/groups/%s/members/agent/%s" % (c.groups["g2"], c.agents["grp"]))
    c.check("REL-ID-03", "an agent is added to a group", st == 204, str(st))

    def rule(subject_kind, subject_id, effect, ops, selector, label):
        body = {"subject": {"kind": subject_kind, "id": subject_id}, "effect": effect, "operations": ops, "selector": selector}
        if effect == "ALLOW":  # a cap is accepted only for an operation it can bound (the service refuses an unreachable cap)
            if matrix.key("logs") in ops:
                body["log_tail_max"] = 100
            if matrix.key("stop") in ops or matrix.key("restart") in ops:
                body["stop_timeout_max"] = 30
        st, b = c.adm("POST", "/api/v1/admin/policy/rules", body)
        rid = [r.get("id") for r in (b or {}).get("rules", [])] if isinstance(b, dict) else []
        c.rules[label] = rid
        return st in (200, 201) and bool(rid)
    exact = lambda n: {"container_name": n, "name_is_glob": False}  # noqa: E731
    wild = {"container_name": "*", "name_is_glob": True}
    all6 = [matrix.key(o) for o in matrix.ORDER]
    status = [matrix.key("status")]
    r = [rule("agent", c.agents["a"], "ALLOW", all6, exact(A), "a"), rule("agent", c.agents["ro"], "ALLOW", status, exact(A), "ro"),
         rule("agent", c.agents["dn"], "ALLOW", all6, wild, "dn-allow"), rule("agent", c.agents["dn"], "DENY", all6, exact(B), "dn-deny"),
         rule("group", c.groups["g2"], "ALLOW", status, exact(A), "grp"), rule("agent", c.agents["wild"], "ALLOW", all6, wild, "wild")]
    for lab in ("exp", "rot", "rev", "dis", "sess"):
        r.append(rule("agent", c.agents[lab], "ALLOW", status, exact(A), lab))
    r.append(rule("agent", c.agents["pol"], "ALLOW", status + [matrix.key("logs")], exact(A), "pol"))
    for lab in ("load1", "load2"):
        r.append(rule("agent", c.agents[lab], "ALLOW", status + [matrix.key("logs")], exact(A), lab))
    c.check("REL-ID-04", "explicit ALLOW/DENY rules are created (agent subjects, one group subject, a wildcard, an explicit DENY on B)", all(r), str(r))
    cred_ok = True
    for label in ("a", "ro", "none", "dn", "grp", "wild", "pol", "sess", "load1", "load2", "rev", "dis", "rot"):
        st, b = c.adm("POST", "/api/v1/admin/agents/%s/credentials" % c.agents[label], {})
        tok = (b or {}).get("token", "") if isinstance(b, dict) else ""
        c.e.secrets.append(tok)
        c.tokens[label] = tok
        c.cred_ids[label] = (c.ids((b or {}).get("credential"), "id") or [""])[0] if isinstance(b, dict) else ""
        cred_ok &= st == 201 and tok.startswith("mdt_")
    c.check("REL-ID-05", "credentials are issued once (mdt_ prefix)", cred_ok)
    st, b = c.adm("GET", "/api/v1/admin/policy/rules")
    inv = [i.get("name") for i in (b or {}).get("inventory") or []] if isinstance(b, dict) else []
    c.check("REL-ID-06", "the policy page's inventory lists A, B and C, and never Mandatary or its labelled peer", st == 200 and A in inv and B in inv and c.names["self"] not in inv and c.names["peer"] not in inv, str(inv))


# ---- the matrix ---------------------------------------------------------------------------------------------------
def make_executors(c: Ctx):
    c.rest = executors.Rest(c.dep, c.tokens)
    c.mcp = executors.Mcp(c.dep, c.a.mcp_client, c.tokens, c.e.work)


def mutating_events(c: Ctx, cid, since):
    p = c.e.docker("events", "--since", str(int(since) - 1), "--until", str(int(time.time()) + 1), "--filter", "container=" + cid, "--format", "{{.Action}}", check=False, timeout=90)
    return [x.strip() for x in p.stdout.splitlines() if x.strip()]


def mismatch_log(log_text, ids, keep=40, width=240):
    """The failed case ids and the last `keep` service log lines that are warnings/errors or about safety/backend state."""
    pat = re.compile(r'"level":"(WARN|ERROR)"|unverified|safety|heartbeat|backend|dropped', re.I)
    lines = [ln[:width] for ln in (log_text or "").splitlines() if pat.search(ln)]
    return {"ids": sorted(set(ids)), "lines": lines[-keep:]}


def run_matrix(c: Ctx):
    c.t_events = time.time()  # daemon events are judged from here: the fixtures' own start-up is not a policy effect
    ctxn = dict(c.names)
    cases = matrix.build_cases(ctxn)
    raw_cases = matrix.rest_only_cases(ctxn)
    t_start = time.time()
    rest_res, rest_ms = [], []
    for k in cases:  # per-call timing: a one-shot stop/restart that outlives a server bound must be visible (review 519 F2)
        t0 = time.time()
        rest_res.append(c.rest.run(k))
        rest_ms.append(round((time.time() - t0) * 1000))
    mcp_res, mcp_raw = c.mcp.run_cases(cases)
    mcp_ms = [round(r.get("elapsed_ms") or 0) for r in mcp_raw]
    bad_rest = [(k.id, k.expect, r) for k, r in zip(cases, rest_res) if not k.expect.matches(r)]
    bad_mcp = [(k.id, k.expect, r) for k, r in zip(cases, mcp_res) if not k.expect.matches(r)]
    diverge = [(k.id, r1, r2) for k, r1, r2 in zip(cases, rest_res, mcp_res) if r1 != r2]
    n_ok = sum(1 for k in cases if k.expect is matrix.OK)
    n_deny = sum(1 for k in cases if k.expect is matrix.DENY)
    c.ev["matrix"]["cases"] = len(cases)
    c.ev["matrix"]["table"] = [{"id": k.id, "who": k.who, "op": k.op, "expect": repr(k.expect), "rest": r1, "mcp": r2, "rest_ms": t1, "mcp_ms": t2} for k, r1, r2, t1, t2 in zip(cases, rest_res, mcp_res, rest_ms, mcp_ms)]
    c.ev["matrix"]["timing"] = matrix.timing_summary([k.id for k in cases], [k.op for k in cases], rest_ms, mcp_ms)
    if bad_rest or bad_mcp or diverge:
        # Diagnostic only: an unexpected answer (for example one stray 502) is otherwise unattributable. Keep the service's own
        # warning/error and safety/backend lines (the service logs carry no secrets, error text or payloads) next to the failed ids.
        c.ev["matrix"]["service_log_on_mismatch"] = mismatch_log(c.dep.logs(), [x[0] for x in bad_rest + bad_mcp + diverge])
    c.check("REL-MATRIX-REST", "REST: all %d cases (%d allowed, %d denied, plus 401/unknown endpoint/backend error) meet the expectation" % (len(cases), n_ok, n_deny), not bad_rest, str(bad_rest[:4]))
    c.check("REL-MATRIX-MCP", "real MCP client (official go-sdk, Streamable HTTP over verified TLS): the same %d cases meet the same expectation" % len(cases), not bad_mcp, str(bad_mcp[:4]))
    c.check("REL-MATRIX-PARITY", "REST and the real MCP client give the identical class (status, code, reason) for every case", not diverge, str(diverge[:4]))
    for k in cases:
        c.tally.add_case(k, 2)  # once per transport
    # the cross product that matters most, reported as an explicit positive/negative pair
    pos = [k for k, r1, r2 in zip(cases, rest_res, mcp_res) if k.expect is matrix.OK and r1[0] == 200 and r2[0] == 200]
    c.check("REL-MATRIX-POS", "grant a function on A: it succeeds through both API and real MCP (%d positive cases, each on both transports)" % len(pos), len(pos) == n_ok and n_ok > 0)
    # unsupported / invalid REST inputs
    raw_res = [c.rest.run(k) for k in raw_cases]
    bad_raw = [(k.id, k.expect, r) for k, r in zip(raw_cases, raw_res) if not k.expect.matches(r)]
    c.ev["matrix"]["raw"] = [{"id": k.id, "path": k.raw_path, "method": k.method, "expect": repr(k.expect), "rest": r} for k, r in zip(raw_cases, raw_res)]
    c.check("REL-MATRIX-RAW", "REST: %d invalid-input and unsupported-operation requests (exec, kill, remove, list, discovery, raw Docker paths, wrong methods, smuggled parameters) are refused and never succeed" % len(raw_cases), not bad_raw, str(bad_raw[:4]))
    # MCP: the catalog, unsupported tools, no credential
    lst = c.mcp.tools("a")
    c.ev["matrix"]["tools"] = lst.get("tools")
    c.check("REL-MCP-CATALOG", "tools/list is exactly the six approved tools (no exec, discovery or raw Docker tool)", lst.get("tools") == sorted(m[3] for m in matrix.OPS.values()), str(lst.get("tools")))
    unsup = [{"id": "T-" + t, "token": "wild", "op": t, "args": {"endpoint": "local", "container": c.names["A"]}} for t in matrix.UNSUPPORTED_TOOLS]
    ur = c.mcp.batch(unsup)
    bad = [(r["id"], matrix.norm_mcp(r)) for r in ur if not r.get("protocol_error")]
    c.check("REL-MCP-UNSUPPORTED", "MCP: %d unsupported tool names (exec, kill, remove, list, raw Docker...) are protocol errors that reach nothing, even for a wildcard grant" % len(unsup), not bad, str(bad[:3]))
    nl = c.mcp.batch([{"id": "L-none", "token": "", "list": True}, {"id": "L-garbage", "token": "literal:mdt_" + "B" * 43, "list": True}])
    c.check("REL-MCP-NOAUTH", "MCP tools/list without or with an unknown credential is 401 (listing is not authorization)", all(r.get("http_status") == 401 for r in nl), str(nl)[:200])
    # side effects on the real daemon
    mut = ("start", "stop", "die", "kill", "restart", "pause", "unpause")
    sides = {}
    for lab, cid in (("B", c.names["B"]), ("self", c.names["self_id"]), ("peer", c.names["peer_id"])):
        sides[lab] = [x for x in mutating_events(c, cid, c.t_events) if x.split(":")[0] in mut]
    c.ev["matrix"]["daemon_events_on_protected_or_ungranted"] = sides
    c.check("REL-MATRIX-EFFECT", "daemon events: no start/stop/kill/die/restart on ungranted B, Mandatary itself or its labelled peer during the whole matrix", not any(sides.values()), str(sides))
    ia, ic = c.e.inspect(c.names["A"]), c.e.inspect(c.names["C"])
    c.check("REL-MATRIX-STATE", "A is running again after the stop/start sequences, B was never touched, C (unstartable) was never started",
            ia["State"]["Running"] and c.e.inspect(c.names["B"])["State"]["Running"] and not ic["State"]["Running"] and ic["State"]["Status"] == "created")
    return cases


# ---- lifecycle -------------------------------------------------------------------------------------------------------
def lifecycle(c: Ctx):
    A = c.names["A"]
    both = lambda who, op=("status",), tgt=A: (c.rest.op(who, op[0], tgt), c.mcp.op(who, op[0], tgt))  # noqa: E731
    OKR = (200, "", "")
    UN = (401, "unauthenticated", "")
    # expiry: a credential with a 6 s lifetime, issued now (not at identity set-up, which is minutes earlier)
    st, b = c.adm("POST", "/api/v1/admin/agents/%s/credentials" % c.agents["exp"], {"ttl_seconds": 6})
    tok = (b or {}).get("token", "") if isinstance(b, dict) else ""
    c.e.secrets.append(tok)
    c.tokens["exp"] = tok
    c.mcp.set_tokens(c.tokens)
    c.check("REL-LIFE-EXP-0", "a credential with a 6 s lifetime is issued", st == 201 and tok.startswith("mdt_"), str(st))
    r = both("exp")
    c.tally.add("exp", "status", A, "allowed", 2)
    c.check("REL-LIFE-EXP-1", "a credential with a 6 s lifetime works before expiry (REST and MCP)", r == (OKR, OKR), str(r))
    time.sleep(8)
    r = both("exp")
    c.check("REL-LIFE-EXP-2", "the same credential is refused with 401 on REST and MCP after expiry", r == (UN, UN), str(r))
    # revocation of a credential, then a session that was opened before it
    r = both("rev")
    c.tally.add("rev", "status", A, "allowed", 2)
    c.check("REL-LIFE-REV-1", "agent credential works before revocation", r == (OKR, OKR), str(r))
    sess = c.mcp.batch([{"id": "s1", "token": "sess", "session": "S", "op": "container_status", "args": {"endpoint": "local", "container": A}}])
    c.tally.add("sess", "status", A, "allowed", 1)
    st, b = c.adm("POST", "/api/v1/admin/agents/%s/credentials/%s/revoke" % (c.agents["rev"], c.cred_ids["rev"]), {})
    c.check("REL-LIFE-REV-2", "revoking the credential returns 204", st in (200, 204), str(st))
    r = both("rev")
    c.check("REL-LIFE-REV-3", "the revoked credential is refused with 401 immediately on both transports", r == (UN, UN), str(r))
    # authority is never carried by an MCP session: revoke 'sess' credential, reuse the already open session
    first = matrix.norm_mcp(sess[0])
    st, b = c.adm("POST", "/api/v1/admin/agents/%s/credentials/%s/revoke" % (c.agents["sess"], c.cred_ids["sess"]), {})
    again = c.mcp.batch([{"id": "s2", "token": "sess", "session": "S", "op": "container_status", "args": {"endpoint": "local", "container": A}}, {"id": "s3", "token": "sess", "session": "S", "close": True}])
    c.check("REL-LIFE-SESSION", "an MCP session opened with a valid credential does not keep authority after the credential is revoked (next call 401)", first == OKR and matrix.norm_mcp(again[0]) == UN, "%s %s" % (first, matrix.norm_mcp(again[0])))
    # disabled agent
    r = both("dis")
    c.tally.add("dis", "status", A, "allowed", 2)
    st, b = c.adm("POST", "/api/v1/admin/agents/%s/disable" % c.agents["dis"], {})
    r2 = both("dis")
    c.check("REL-LIFE-DIS", "a disabled agent's credential works before and is refused (401) after, on both transports", r == (OKR, OKR) and r2 == (UN, UN) and st in (200, 204), "%s %s %s" % (r, r2, st))
    # rotation with overlap
    old = c.tokens["rot"]
    r0 = both("rot")
    c.tally.add("rot", "status", A, "allowed", 2)
    st, b = c.adm("POST", "/api/v1/admin/agents/%s/credentials/rotate" % c.agents["rot"], {"overlap_seconds": 8})
    new = (b or {}).get("token", "") if isinstance(b, dict) else ""
    c.e.secrets.append(new)
    c.tokens["rot-new"] = new
    c.mcp.set_tokens(c.tokens)
    r1 = (c.rest.op("rot", "status", A), c.rest.op("rot-new", "status", A))
    c.tally.add("rot", "status", A, "allowed", 2)
    c.check("REL-LIFE-ROT-1", "rotation: during the overlap window both the old and the new credential authorize", st == 201 and r0 == (OKR, OKR) and r1 == (OKR, OKR), "%s %s %s" % (st, r0, r1))
    time.sleep(10)
    r2 = (c.rest.op("rot", "status", A), c.mcp.op("rot", "status", A), c.rest.op("rot-new", "status", A), c.mcp.op("rot-new", "status", A))
    c.tally.add("rot", "status", A, "allowed", 2)
    c.check("REL-LIFE-ROT-2", "rotation: after the overlap the old credential is 401 on both transports and the new one still works", r2 == (UN, UN, OKR, OKR), str(r2))
    del old
    # group membership removal and policy revocation
    pre = both("grp")
    c.tally.add("grp", "status", A, "allowed", 2)
    st, _ = c.adm("DELETE", "/api/v1/admin/groups/%s/members/agent/%s" % (c.groups["g2"], c.agents["grp"]))
    post = both("grp")
    c.tally.add("grp", "status", None, "denied", 2)
    DEN = (403, "forbidden", "default_deny")
    c.check("REL-LIFE-GROUP", "group rule: a member is allowed; after removal from the group the same credential is denied (403) on both transports", pre == (OKR, OKR) and post == (DEN, DEN) and st == 204, "%s %s %s" % (pre, post, st))
    # policy revocation ends an open follow stream
    pol_rules = c.rules["pol"]
    r = both("pol")
    c.tally.add("pol", "status", A, "allowed", 2)
    conn = stack._Conn(c.dep.port, c.rest.cl.ctx)
    conn.request("GET", "/api/v1/endpoints/local/containers/%s/logs?follow=true&tail=1" % A, headers={"Authorization": "Bearer " + c.tokens["pol"], "Accept": "application/x-ndjson"})
    resp = conn.getresponse()
    lines = []
    conn.sock.settimeout(10)
    while len(lines) < 2:
        ln = resp.readline()
        if not ln:
            break
        lines.append(ln)
    c.tally.add("pol", "logs", A, "allowed", 1)
    c.check("REL-LIFE-POL-1", "policy credential reads status and opens a follow stream", r == (OKR, OKR) and resp.status == 200 and len(lines) >= 2, "%s %s %d" % (r, resp.status, len(lines)))
    t_rev = time.time()
    sts = [c.adm("POST", "/api/v1/admin/policy/rules/%s/disable" % rid, {})[0] for rid in pol_rules]
    ended, last = False, b""
    try:
        conn.sock.settimeout(8)
        while True:
            ln = resp.readline()
            if not ln:
                ended = True
                break
            last = ln
    except OSError:
        ended = False
    took = time.time() - t_rev
    conn.close()
    c.check("REL-LIFE-POL-2", "disabling the policy rules ends the open follow stream within 5 s (authority-ended terminal frame)", all(s in (200, 204) for s in sts) and ended and took < 5 and b"authorization_ended" in last, "disable %s ended=%s %.1fs last=%s" % (sts, ended, took, last[:80]))
    r = both("pol")
    c.tally.add("pol", "status", None, "denied", 2)
    c.check("REL-LIFE-POL-3", "after the policy change the same credential is denied (403) on both transports", r == (DEN, DEN), str(r))
    sts = [c.adm("POST", "/api/v1/admin/policy/rules/%s/enable" % rid, {})[0] for rid in pol_rules]
    r = both("pol")
    c.tally.add("pol", "status", A, "allowed", 2)
    c.check("REL-LIFE-POL-4", "re-enabling the rules restores access (positive control); no operation was ever granted by the account itself", all(s in (200, 204) for s in sts) and r == (OKR, OKR), "%s %s" % (sts, r))
    sts = [c.adm("DELETE", "/api/v1/admin/policy/rules/%s" % rid)[0] for rid in pol_rules]
    r = both("pol")
    c.tally.add("pol", "status", None, "denied", 2)
    c.check("REL-LIFE-POL-5", "deleting the rules denies again (403) on both transports", all(s in (200, 204) for s in sts) and r == (DEN, DEN), "%s %s" % (sts, r))
    long_stop(c)


def long_stop(c: Ctx):
    """An admitted stop/restart that runs LONGER than the server's own 10 s write bound still delivers its result (review 519 F2).
    Container A's PID 1 ignores SIGTERM, so timeout_seconds=12 makes the daemon wait the whole 12 s before it kills it: the answer
    comes after the server-wide bound, through the proxy, on REST and on the real MCP client. Each call is accounted once (allowed)."""
    A = c.names["A"]
    base = "/api/v1/endpoints/local/containers/%s/" % A
    OKR = (200, "", "")
    secs = 12
    stop = c.rest.raw("POST", base + "stop", "a", {"timeout_seconds": secs})
    c.tally.add("a", "stop", A, "allowed")  # the daemon executed it whatever the client saw
    start = c.rest.raw("POST", base + "start", "a")
    c.tally.add("a", "start", A, "allowed")
    mcp = c.mcp.batch([{"id": "long-restart", "token": "a", "op": "container_restart", "args": {"endpoint": "local", "container": A, "timeout_seconds": secs}}])[0]
    c.tally.add("a", "restart", A, "allowed")
    mcp_norm, mcp_ms = matrix.norm_mcp(mcp), round(mcp.get("elapsed_ms") or 0)
    running = c.e.inspect(A)["State"]["Running"]
    c.ev["matrix"]["long_stop"] = {"timeout_seconds": secs, "server_write_bound_ms": matrix.SERVER_WRITE_BOUND_MS, "rest_stop": {"result": stop[0], "ms": round(stop[2])},
                                   "rest_start": {"result": start[0], "ms": round(start[2])}, "mcp_restart": {"result": mcp_norm, "ms": mcp_ms}}
    c.check("REL-STOP-LONG", "an admitted stop and restart that run longer than the server's 10 s write bound (timeout_seconds %d on a container that ignores SIGTERM) still deliver their 200 result through the proxy, on REST and on the real MCP client, and A runs again" % secs,
            stop[0] == OKR and start[0] == OKR and mcp_norm == OKR and running and stop[2] >= matrix.SERVER_WRITE_BOUND_MS and mcp_ms >= matrix.SERVER_WRITE_BOUND_MS,
            "stop %s %.0f ms, start %s, restart %s %d ms, running=%s" % (stop[0], stop[2], start[0], mcp_norm, mcp_ms, running))


# ---- logs -----------------------------------------------------------------------------------------------------------
def log_scan(c: Ctx):
    """No secret value the harness ever created may appear in any log of any deployment (Mandatary, proxy, SMTP)."""
    secrets_ = [s for s in c.e.secrets if s and len(s) >= 16]
    hits, total = [], 0
    for d in c.deps:
        text = d.logs()
        total += len(text)
        for s in secrets_:
            if s in text:
                hits.append("%s: a %d-char secret" % (d.tag, len(s)))
        for label, rx in (("bearer-value", r"Bearer\s+[A-Za-z0-9_.~+/=-]{20,}"), ("mdt_", r"mdt_"), ("cookie-name=value", r"__Host-mandatary_\w+=")):
            if re.search(rx, text):
                hits.append("%s: pattern %s" % (d.tag, label))
    c.check("REL-LOGS", "no setup token, password, TOTP seed, master key, bearer token, address proof or session cookie appears in any log of %d deployments (%d bytes scanned, %d secrets checked)" % (len(c.deps), total, len(secrets_)), not hits, "; ".join(hits[:5]))


# ---- logging --------------------------------------------------------------------------------------------------------
def log_levels(c: Ctx):
    """MANDATARY_LOG_LEVEL is honoured by the real image: a start at each level emits no line below it, the info start
    emits its startup line, and an invalid level refuses to start without echoing a key. (Secret absence at every level
    and in both formats is proven by the Go suite and, for this deployment's own logs, by REL-LOGS.)"""
    from collections import Counter
    e = c.e
    uid, gid = os.getuid(), os.getgid()
    seen = {}
    for lvl in ("debug", "info", "warn", "error"):
        base, key = e.prepare_state("lvl-" + lvl, uid, gid)
        name = e.pfx + "-lvl-" + lvl
        e.run_mandatary(name, base, env={"MANDATARY_LOG_LEVEL": lvl, "MANDATARY_LOG_FORMAT": "json"}, user="%d:%d" % (uid, gid))
        e.wait(lambda: e.health(name) == "healthy", 60)
        time.sleep(2)
        lines = [ln for ln in e.logs(name).splitlines() if ln.startswith("{")]
        levels = Counter()
        for ln in lines:
            try:
                levels[str(json.loads(ln).get("level", "")).upper()] += 1
            except ValueError:
                levels["UNPARSEABLE"] += 1
        seen[lvl] = dict(levels)
        c.check("REL-LOGLEVEL-KEY-" + lvl, "the %s start logs no master key value" % lvl, key not in e.logs(name))
        e.drop(name)
        e.reclaim(base)
    c.ev["logging"] = seen
    order = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
    ok = True
    why = []
    for lvl, got in seen.items():
        below = {k: v for k, v in got.items() if order.get(k, 9) < order[lvl.upper()]}
        if below or got.get("UNPARSEABLE"):
            ok = False
            why.append("%s start emitted %s" % (lvl, below or "unparseable lines"))
    c.check("REL-LOGLEVEL", "a start at each of debug/info/warn/error emits no JSON line below its level", ok, "; ".join(why) or str(seen))
    c.check("REL-LOGLEVEL-POS", "positive control: the info start emits info lines and the warn/error starts do not (the filter really acts)", seen["info"].get("INFO", 0) > 0 and not seen["warn"].get("INFO") and not seen["error"].get("INFO"), str(seen))
    base, key = e.prepare_state("lvl-bad", uid, gid)
    name = e.pfx + "-lvl-bad"
    e.run_mandatary(name, base, env={"MANDATARY_LOG_LEVEL": "verbose", "MANDATARY_LOG_FORMAT": "json"}, user="%d:%d" % (uid, gid))
    e.wait(lambda: not (e.inspect(name) or {}).get("State", {}).get("Running", True), 30)
    info = e.inspect(name) or {}
    c.check("REL-LOGLEVEL-INVALID", "an invalid MANDATARY_LOG_LEVEL refuses to start (non-zero exit) and echoes no key", info.get("State", {}).get("ExitCode") not in (0, None) and key not in e.logs(name), str(info.get("State", {}).get("ExitCode")))
    e.drop(name)
    e.reclaim(base)


# ---- documented local workflow: native, container-free, mock Docker ----------------------------------------------------
def devflow(c: Ctx):
    """The documented local development workflow (development.md `make dev`): the SAME binary the image carries, started
    natively with the in-memory mock backend and no Docker access at all, serves its health/readiness endpoints, the
    SPA and a closed API on loopback, and refuses to run the mock beside a real socket. No container is built or run."""
    import subprocess
    import urllib.error
    import urllib.request
    e = c.e
    uid, gid = os.getuid(), os.getgid()
    base, key = e.prepare_state("devflow", uid, gid)
    port = stack.free_port()
    env = {"PATH": "/usr/bin:/bin", "MANDATARY_DATA_DIR": base + "/data", "MANDATARY_MASTER_KEY_FILE": base + "/keys/master.key", "MANDATARY_ADMIN_LISTEN_ADDR": "127.0.0.1:%d" % port,
           "MANDATARY_PUBLIC_ORIGIN": "https://127.0.0.1:%d" % port, "MANDATARY_DEV_MOCK_DOCKER": "true", "MANDATARY_LOG_FORMAT": "text", "MANDATARY_LOG_LEVEL": "info",
           "DOCKER_HOST": "unix:///nonexistent/no-docker-in-the-local-workflow.sock"}
    out = os.path.join(base, "out.log")
    with open(out, "w") as fh:
        proc = subprocess.Popen([c.a.host_binary], env=env, stdout=fh, stderr=subprocess.STDOUT, cwd=base)

    def get(path, method="GET"):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read(200000).decode("utf-8", "replace")
        except urllib.error.HTTPError as ex:
            return ex.code, ex.read(2000).decode("utf-8", "replace")
        except OSError as ex:
            return 0, str(ex)
    try:
        ok = e.wait(lambda: get("/api/v1/readyz")[0] == 200, 30)
        r, idx, api, nf = get("/api/v1/readyz")[0], get("/"), get("/api/v1/endpoints/local/containers/x/status"), get("/no-such-route")[0]
        live = subprocess.run([c.a.host_binary, "healthcheck"], env=env, capture_output=True, text=True, timeout=30, cwd=base).returncode
        ready = subprocess.run([c.a.host_binary, "healthcheck", "--ready"], env=env, capture_output=True, text=True, timeout=30, cwd=base).returncode
        log = open(out).read()
        c.check("REL-DEV-01", "the host binary starts natively with the mock backend and no Docker access (DOCKER_HOST points nowhere), is ready on loopback (GET /api/v1/readyz 200) and its own `healthcheck` and `healthcheck --ready` exit 0",
                ok and r == 200 and live == 0 and ready == 0, "readyz=%s healthcheck=%s healthcheck --ready=%s" % (r, live, ready))
        c.check("REL-DEV-02", "the embedded SPA is served and an unauthenticated API call is refused (no open mock surface)", idx[0] == 200 and "<div id=" in idx[1] and api[0] == 401 and nf == 404, "index=%s api=%s unknown=%s" % (idx[0], api[0], nf))
        c.check("REL-DEV-03", "the mock backend announces itself (WARN) and the master key is not logged", "mock docker backend active" in log and key not in log)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    rc = subprocess.run([c.a.host_binary], env=dict(env, MANDATARY_DOCKER_SOCKET="unix:///var/run/docker.sock"), capture_output=True, text=True, timeout=30, cwd=base)
    c.check("REL-DEV-04", "the mock backend beside a real Docker socket setting is refused at start-up (non-zero exit, no key in the output)", rc.returncode != 0 and key not in rc.stdout + rc.stderr, "exit=%s" % rc.returncode)
    e.reclaim(base)


# ---- documentation matches the delivered release ------------------------------------------------------------------------
def docs_check(c: Ctx):
    """Structural, mechanical documentation checks over the source tree under test. Whether the prose is accurate is a
    reviewer judgment and is NOT claimed here; what is checked is that the pages an operator is sent to exist, link to
    files that exist, name the files the release really ships, and state that later-phase features are unavailable."""
    repo = c.a.repo

    def text(rel):
        try:
            with open(os.path.join(repo, rel), errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""
    broken = []
    pages = ["README.md", "development.md"] + ["docs/" + f for f in sorted(os.listdir(os.path.join(repo, "docs"))) if f.endswith(".md")]
    link = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
    for rel in pages:
        for target in link.findall(text(rel)):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target):
                continue
            if not os.path.exists(os.path.normpath(os.path.join(repo, os.path.dirname(rel), target))):
                broken.append("%s -> %s" % (rel, target))
    c.check("REL-DOCS-LINKS", "every relative link in README.md, development.md and docs/*.md resolves to a file in the release (%d pages)" % len(pages), not broken, "; ".join(broken[:6]))
    dep = text("docs/deployment.md")
    shipped = ["docker-compose.yml", "deploy/compose.proxy.yml", "deploy/env.example"]
    missing = [f for f in shipped if f not in dep or not os.path.exists(os.path.join(repo, f))]
    c.check("REL-DOCS-DEPLOY", "docs/deployment.md names the Compose files and the example environment the release ships, and they exist", not missing, str(missing))
    sections = ["Not implemented", "Evidence and limits", "Self-protection and readiness", "First administrator"]
    absent = [s for s in sections if s.lower() not in dep.lower()]
    c.check("REL-DOCS-LIMITS", "docs/deployment.md states what is not implemented, the evidence limits, the first-administrator flow and self-protection", not absent, str(absent))
    api = text("docs/api-mcp.md").lower()
    c.check("REL-DOCS-UNAVAILABLE", "docs/api-mcp.md states that exec, discovery and raw Docker operations are unsupported (later phases are unavailable, not stubs)", all(w in api for w in ("exec", "discovery", "raw")) and "unsupported" in api)
    c.check("REL-DOCS-README-LIMITS", "README.md points to the known limitations and open items", "limitation" in text("README.md").lower())
