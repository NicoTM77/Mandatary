"""P1.20 release acceptance, part 2: latency and the synchronous usage-write cost, idle/load footprint, exact usage
counts, restart and crash durability."""
import re
import threading
import time

import footprint
import matrix
import rca
import stack
from core import measure_idle
from ctx import Ctx


def latency_probe(c: Ctx, n=150):
    """Sequential latency of three REST classes: accounted-allowed (a backend call plus one synchronous durable
    usage write), accounted-denied (authorization plus the write, no Docker call) and unauthenticated 401
    (authentication only, nothing accounted). The differences bound the cost of one accounted outcome (P115-O1)."""
    A = c.names["A"]
    base = "/api/v1/endpoints/local/containers/%s/status" % A
    out = {}
    for label, who in (("unauth_401", ""), ("denied_accounted", "none"), ("allowed_accounted", "a")):
        ms = []
        for _ in range(n):
            res, _, took = c.rest.raw("GET", base, who)
            ms.append(took)
            want = {"unauth_401": (401, "unauthenticated", ""), "denied_accounted": (403, "forbidden", "default_deny"), "allowed_accounted": (200, "", "")}[label]
            if res != want:
                c.check("REL-LAT-" + label, "latency probe class " + label, False, "unexpected %s" % (res,))
                return
        out[label] = footprint.latency_summary(ms)
    c.tally.add("none", "status", None, "denied", n)
    c.tally.add("a", "status", A, "allowed", n)
    out["usage_write_cost_estimate_p50_ms"] = round(out["denied_accounted"]["p50_ms"] - out["unauth_401"]["p50_ms"], 3)
    out["note"] = "denied_accounted - unauth_401 = authorization + one synchronous durable usage write, measured through the TLS proxy on the isolated host; not a microbenchmark of the write alone"
    c.ev["footprint"]["latency"] = out
    c.check("REL-LAT", "added latency of an accounted outcome measured (%d sequential calls per class)" % n, True,
            "p50 ms: 401 %.2f, denied+accounted %.2f, allowed+accounted %.2f; p99 ms: %.2f / %.2f / %.2f" % (
                out["unauth_401"]["p50_ms"], out["denied_accounted"]["p50_ms"], out["allowed_accounted"]["p50_ms"],
                out["unauth_401"]["p99_ms"], out["denied_accounted"]["p99_ms"], out["allowed_accounted"]["p99_ms"]))


def load(c: Ctx, seconds):
    """20 concurrent API/MCP clients polling status/logs plus 5 active follow streams, with the process RSS sampled each second."""
    A, dep = c.names["A"], c.dep
    pid = dep.host_pid()
    stop = threading.Event()
    lock = threading.Lock()
    rest = {"status": 0, "logs": 0, "errors": 0}
    classes = {}  # (http status, error code) of every non-200 answer, so a protective answer is told apart from a failure
    lat = []
    samples = []
    attempts = []  # [t_ms, interface, op, outcome, duration_ms]: every client call, correlated with the service's safety-proof log (rca.py)
    streams = {"load1": 0, "load2": 0, "opened": 0, "failed": 0, "frames": 0}

    def poller(i):
        cl = stack.Client(dep.port, dep.caroot)
        n = i
        while not stop.is_set():
            op = "status" if n % 2 == 0 else "logs"
            n += 1
            path = "/api/v1/endpoints/local/containers/%s/%s" % (A, "status" if op == "status" else "logs?tail=3")
            t0 = time.time()
            code = ""
            try:
                st, _, body = cl.req("GET", path, bearer=c.tokens["load1"])
                if st != 200 and isinstance(body, dict):
                    err = body.get("error") or {}
                    code = str(err.get("code", ""))
                    if err.get("reason"):
                        code += "/" + str(err.get("reason"))  # the closed 403 reason (safety_unverified is not default_deny)
            except OSError as ex:
                st, code = 0, type(ex).__name__
            d = (time.time() - t0) * 1000
            with lock:
                attempts.append([int(t0 * 1000), "rest", op, "ok" if st == 200 else "%s/%s" % (st, code), round(d, 1)])
                if st == 200:
                    rest[op] += 1
                    lat.append(d)
                else:
                    rest["errors"] += 1
                    classes["%s/%s" % (st, code)] = classes.get("%s/%s" % (st, code), 0) + 1
            time.sleep(0.2)

    def streamer(who):
        conn = stack._Conn(dep.port, c.rest.cl.ctx)
        try:
            conn.request("GET", "/api/v1/endpoints/local/containers/%s/logs?follow=true&tail=1" % A, headers={"Authorization": "Bearer " + c.tokens[who], "Accept": "application/x-ndjson"})
            resp = conn.getresponse()
            with lock:
                if resp.status == 200:
                    streams["opened"] += 1
                    streams[who] += 1
                else:
                    streams["failed"] += 1
                    return
            conn.sock.settimeout(5)
            while not stop.is_set():
                try:
                    ln = resp.readline()
                except OSError:
                    continue
                if not ln:
                    break
                with lock:
                    streams["frames"] += 1
        except OSError:
            with lock:
                streams["failed"] += 1
        finally:
            conn.close()

    def sampler():
        while not stop.is_set():
            samples.append(footprint.read_status(pid).get("VmRSS", 0))
            time.sleep(1)

    mcp_out = {}

    def mcp_load():
        try:
            mcp_out["r"] = c.mcp.batch(None, load={"workers": 10, "duration_s": seconds, "token": "load1", "endpoint": "local", "container": A, "ops": ["container_status", "container_logs"]}, timeout=seconds + 120)
        except Exception as exc:  # noqa: BLE001
            mcp_out["err"] = str(exc)[:200]

    probe = rca.DaemonProbe(dep.e.sock)
    probe.start()
    hostcpu = rca.HostSampler([pid])
    hostcpu.start()
    reset = footprint.reset_peak(pid)  # VmHWM then covers exactly this window (not the one-time Argon2id memory of an earlier sign-in)
    before = footprint.read_status(pid)
    threads = [threading.Thread(target=poller, args=(i,)) for i in range(10)]
    threads += [threading.Thread(target=streamer, args=(w,)) for w in ("load1", "load1", "load1", "load2", "load2")]
    threads.append(threading.Thread(target=sampler))
    mt = threading.Thread(target=mcp_load)
    t0 = time.time()
    for t in threads:
        t.start()
    mt.start()
    mt.join(seconds + 130)
    stop.set()
    for t in threads:
        t.join(30)
    wall = time.time() - t0
    probe_rows = probe.finish()
    cpu_rows = hostcpu.finish()
    after = footprint.read_status(pid)
    cg = footprint.cgroup_memory(pid)
    m = mcp_out.get("r") or {}
    by_op = m.get("by_op", {}) if isinstance(m, dict) else {}
    peak_rss = max(samples) if samples else 0
    rec = {"peak_reset_before_window": reset, "clients": {"rest_pollers": 10, "mcp_sessions": 10, "follow_streams": 5}, "seconds": round(wall, 1), "rest": dict(rest), "rest_error_classes": dict(classes), "rest_latency": footprint.latency_summary(lat),
           "mcp": m, "mcp_error": mcp_out.get("err"), "streams": dict(streams), "VmRSS_peak_sampled": peak_rss, "VmRSS_before": before.get("VmRSS"), "VmRSS_after": after.get("VmRSS"),
           "VmHWM_after": after.get("VmHWM"), "cgroup": cg, "rss_samples": len(samples)}
    log_text = dep.logs()
    rec["service_log_safety_lines"] = [ln[:240] for ln in log_text.splitlines() if re.search(r"unverified|safety|heartbeat|backend", ln, re.I)][-12:]
    # R2: the complete, correlated record of every call, the daemon's own latency and every safety-proof transition of the window.
    for e in (m.get("trace") or []):
        attempts.append([e["t"], "mcp", e["op"], e["out"], e["ms"]])
    if isinstance(m, dict):
        m.pop("trace", None)  # moved into attempts below; the MCP summary stays small
    events = rca.parse_service_events(log_text)
    rec["attempts"] = sorted(attempts)
    rec["daemon_probe"] = probe_rows
    rec["host_cpu"] = cpu_rows  # [t_ms, host busy %, {process: % of one CPU}] once a second
    rec["service_safety_events"] = events
    rec["correlation"] = rca.correlate(sorted(attempts), probe_rows, events)
    c.ev["footprint"]["load"] = rec
    hwm = after.get("VmHWM", 0)
    ran = (not mcp_out.get("err") and streams["opened"] == 5 and streams["failed"] == 0 and rest["status"] > 0 and rest["logs"] > 0 and m.get("ok", 0) > 0
           and (m.get("by_op") or {}).get("container_logs", 0) > 0)
    c.check("REL-LOAD-RUN", "benchmark workload ran for %.0f s: 10 REST + 10 real-MCP polling clients and 5 follow streams, answered with %d REST and %d MCP successes (the footprint below is measured over exactly this window)" % (wall, rest["status"] + rest["logs"], m.get("ok", 0)),
            ran, "rest ok %d, mcp ok %s, streams %s %s" % (rest["status"] + rest["logs"], m.get("ok"), streams, mcp_out.get("err", "")))
    stable = ran and rest["errors"] == 0 and m.get("errors", 1) == 0
    c.check("REL-LOAD-STABLE", "the service keeps authorizing legitimate calls under the workload: no non-200 REST answer and no MCP tool error in %.0f s" % wall, stable,
            "rest errors %d %s; mcp %s; service log lines: %s" % (rest["errors"], dict(classes), {k: m.get(k) for k in ("calls", "ok", "errors", "by_error")}, "; ".join(rec["service_log_safety_lines"][-3:])[:300]))
    c.check("REL-FOOT-LOAD", "RSS under the benchmark workload <= 150 MB (peak sampled %.2f MB; kernel high-water mark VmHWM %.2f MB %s)" % (
        peak_rss / footprint.MB, hwm / footprint.MB, "reset at the start of the window" if reset else "since process start (the reset was not permitted)"),
            footprint.within(max(peak_rss, hwm), footprint.BUDGET_LOAD_RSS_BYTES), "budget 150 MB; %d RSS samples at 1 Hz; rss before %.2f MB after %.2f MB" % (len(samples), (before.get("VmRSS") or 0) / footprint.MB, (after.get("VmRSS") or 0) / footprint.MB))
    # exact accounting of the workload: every successful poll and every opened stream is one outcome
    # A call the client saw refused or time out may still have been accounted by the server (docs/usage-accounting.md): a band, never a guess.
    nonok = {"status": 0, "logs": 0}
    for _t, _iface, op, out, _ms in attempts:
        if out != "ok":
            nonok["status" if op in ("status", "container_status") else "logs"] += 1
    c.tally.add_band("load1", "status", A, nonok["status"])
    c.tally.add_band("load1", "logs", A, nonok["logs"])
    c.tally.add("load1", "status", A, "allowed", rest["status"] + by_op.get("container_status", 0))
    c.tally.add("load1", "logs", A, "allowed", rest["logs"] + by_op.get("container_logs", 0) + streams["load1"])
    c.tally.add("load2", "logs", A, "allowed", streams["load2"])


def read_usage(c: Ctx, label, stop_first=True, rebaseline=False):
    """Stop the service gracefully (the WAL is checkpointed), read the rollups read-only and compare them with the
    tally of everything the harness did. The service is started again afterwards."""
    dep = c.dep
    code, took = dep.stop() if stop_first else (0, 0)
    exp = c.tally.totals()
    daily = matrix.merge_rows(dep.usage_rows("usage_stats_daily"))
    hourly = matrix.merge_rows(dep.usage_rows("usage_stats_hourly"))
    bands = dict(c.tally.bands)
    diffs = matrix.diff_totals(exp, daily, bands)
    hdiffs = matrix.diff_totals(exp, hourly, bands)
    con = dep.db()
    try:
        recent = con.execute("SELECT count(*) FROM usage_recent_events").fetchone()[0]
        cols = sorted(r[1] for r in con.execute("PRAGMA table_info(usage_recent_events)"))
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        fk = con.execute("PRAGMA foreign_key_check").fetchall()
        ctl = con.execute("SELECT count(*) FROM usage_stats_daily").fetchone()[0]
    finally:
        con.close()
    c.ev["usage"][label] = {"expected_cells": len(exp), "expected_events": c.tally.events(), "daily_cells": len(daily), "recent_events": recent, "graceful_exit": code,
                            "diffs": diffs[:20], "hourly_diffs": hdiffs[:20]}
    c.check("REL-USAGE-" + label, "exact usage totals per (agent, owner user, selector, operation) after %s: %d accounted outcomes in %d tuples match the executed sequence" % (label, c.tally.events(), len(exp)),
            not diffs and not hdiffs and code == 0, "graceful exit %s; %s" % (code, "; ".join((diffs + hdiffs)[:4])))
    if rebaseline and (diffs or hdiffs):
        # The mismatch above is reported (and FAILS its check). Later checks continue from what the store really holds, so one anomaly is one
        # failure and not four, and each later stage is still compared exactly against its own additions.
        c.tally.t = {k: list(v) for k, v in daily.items()}
        c.tally.bands = {}
        c.ev["usage"][label]["rebaselined_to_measured"] = True
    cap = 1000
    c.check("REL-USAGE-RING-" + label, "recent-event ring is bounded (<= %d), holds no payload column, and the database passes integrity and foreign-key checks" % cap,
            recent <= cap and not any(x in cols for x in ("payload", "container_name", "token", "ip", "message")) and integrity == "ok" and not fk, "recent=%d integrity=%s fk=%d cols=%s" % (recent, integrity, len(fk), cols))
    dep.start()
    return ctl


def persistence(c: Ctx):
    A, B = c.names["A"], c.names["B"]
    dep = c.dep
    # a graceful stop/start: the credential, the policy and the administrator survive; setup stays closed
    ctl = read_usage(c, "AFTER-WORKLOAD", rebaseline=True)
    measure_idle(c, "after-restart")  # a restart of an installation that already holds data (no first-start setup work)
    r_ok = c.rest.op("a", "status", A)
    r_no = c.rest.op("a", "status", B)
    c.tally.add("a", "status", A, "allowed", 1)
    c.tally.add("a", "status", None, "denied", 1)
    c.check("REL-RESTART-1", "after stop/start the credential still authorizes A and still cannot touch B (policy and credential persisted)", r_ok == (200, "", "") and r_no == (403, "forbidden", "default_deny"), "%s %s" % (r_ok, r_no))
    m_ok = c.mcp.op("a", "status", A)
    c.tally.add("a", "status", A, "allowed", 1)
    c.check("REL-RESTART-2", "the real MCP client sees the same after the restart", m_ok == (200, "", ""), str(m_ok))
    st, _, body = c.dep.admin.cl.req("GET", "/api/v1/session")
    adm = dep.admin
    adm.cl = None
    try:
        adm.login()
        st, b = c.adm("GET", "/api/v1/admin/policy/rules")
        n_rules = len((b or {}).get("rules", [])) if isinstance(b, dict) else -1
        c.check("REL-RESTART-3", "the administrator signs in again (password + TOTP) and the policy listing is intact after the restart", st == 200 and n_rules > 0, "rules=%s" % n_rules)
    except Exception as exc:  # noqa: BLE001
        c.check("REL-RESTART-3", "the administrator signs in again after the restart", False, str(exc)[:200])
    c.ev["persistence"]["rules_after_restart"] = n_rules if "n_rules" in dir() else None
    st, _, _ = stack.Client(dep.port, dep.caroot).req("POST", "/api/v1/setup/exchange", {"token": "ABCD-" * 12 + "ABCD"})
    c.check("REL-RESTART-4", "setup stays closed after a restart (404)", st == 404, str(st))
    # crash durability: acknowledged outcomes survive SIGKILL (security-control writes use synchronous=FULL)
    n = 6
    oks = [c.rest.op("a", "status", A) for _ in range(n)]
    c.tally.add("a", "status", A, "allowed", sum(1 for r in oks if r == (200, "", "")))
    t0 = time.time()
    k = dep.kill9()
    c.ev["persistence"]["crash"] = dict(k, seconds_to_ready=round(time.time() - t0, 1))
    c.check("REL-CRASH-1", "SIGKILL of the service process (from the host): Docker's restart policy restarts it (RestartCount >= 1, new StartedAt) and it is ready again after a fresh verification (%.0f s)" % (time.time() - t0),
            bool(k["restart_count"]) and k["started_at_changed"], str(k))
    r = c.rest.op("a", "status", A)
    c.tally.add("a", "status", A, "allowed", 1 if r == (200, "", "") else 0)
    c.check("REL-CRASH-2", "after the crash the credential still authorizes A", r == (200, "", ""), str(r))
    read_usage(c, "AFTER-CRASH")
    adm = dep.admin
    adm.cl = None
    adm.login()
