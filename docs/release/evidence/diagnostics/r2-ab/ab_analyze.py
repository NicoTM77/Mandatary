#!/usr/bin/env python3
"""Analysis of the P1.20 R2 A/B runs (reviewer plan section 6). Reads <outdir>/<run-id>/release.json for every run listed in
<outdir>/done.list ("<arm> <host> <run-id>") and prints (and writes) per-run rows and the target evaluation.
Usage: python3 -I ab_analyze.py <outdir> [--json out.json]. Every run is reported, aborted ones too; nothing is dropped."""
import json, math, os, statistics, sys, collections

OUT = sys.argv[1]
KINDS = ("ping", "info", "list", "inspect", "logs", "start", "stop", "restart", "other")


def pct(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    k = max(0, min(len(s) - 1, math.ceil(p / 100 * len(s)) - 1))
    return s[k]


def run_row(arm, host, rid):
    path = os.path.join(OUT, rid, "release.json")
    row = {"run": rid, "arm": arm, "host": host, "status": "ABORTED"}
    if not os.path.isfile(path):
        return row
    try:
        d = json.load(open(path))
        ld = d["evidence"]["footprint"]["load"]
    except Exception as exc:  # noqa: BLE001
        row["status"] = "UNREADABLE " + str(exc)[:60]
        return row
    res = {r["id"]: r for r in d["results"]}
    att = ld.get("attempts", [])
    ok = [a for a in att if a[3] == "ok"]
    opened = (ld.get("streams") or {}).get("opened", 0)
    admitted = len(ok) + opened
    kinds = collections.Counter(a[3] for a in att if a[3] != "ok")
    unv = sum(v for k, v in kinds.items() if "safety_unverified" in k)
    dd = sum(v for k, v in kinds.items() if "default_deny" in k)
    timeouts = sum(v for k, v in kinds.items() if k in ("transport", "0/TimeoutError") or "Timeout" in k)
    log_to = sum(1 for a in att if a[3] != "ok" and a[2] in ("logs", "container_logs") and (a[3] in ("transport", "0/TimeoutError") or "Timeout" in a[3]))
    corr = ld.get("correlation") or {}
    drops = corr.get("drops", 0)
    by = corr.get("drops_by_reason_step_cause", {})
    dr = ld.get("daemon_requests") or {}
    delta = dr.get("delta")
    cpu = ld.get("host_cpu") or []
    win = dr.get("window_ms") or ([att[0][0], att[-1][0]] if att else None)
    dcpu = 0.0
    busy = []
    if win:
        for t, b, per in cpu:
            if win[0] <= t <= win[1] + 1000:
                dcpu += sum(v for k, v in per.items() if k.startswith(("dockerd", "containerd:"))) / 100.0
                busy.append(b)
    lat = {}
    for iface in ("rest", "mcp"):
        pass
    for op in ("status", "logs"):
        v = [a[4] for a in ok if a[2] in (op, "container_" + op)]
        lat[op] = {"n": len(v), "p50": pct(v, 50), "p95": pct(v, 95), "p99": pct(v, 99)}
    row.update({
        "status": "OK", "stable": (res.get("REL-LOAD-STABLE") or {}).get("status"), "run_ok": (res.get("REL-LOAD-RUN") or {}).get("status"),
        "attempts": len(att), "admitted": admitted, "refused_unverified": unv, "refused_default_deny": dd, "timeouts": timeouts, "log_timeouts": log_to,
        "drops": drops, "drops_by": by, "events": len(ld.get("service_safety_events") or []),
        "delta": delta, "counted": bool(delta),
        "meta_reads": (delta["info"] + delta["list"] + delta["inspect"]) if delta else None,
        "info": delta["info"] if delta else None,
        "meta_per_call": ((delta["info"] + delta["list"] + delta["inspect"]) / admitted) if delta and admitted else None,
        "info_per_call": (delta["info"] / admitted) if delta and admitted else None,
        "daemon_cpu_s": round(dcpu, 2) if win else None, "cpu_s_per_call": (dcpu / admitted) if win and admitted else None,
        "window_s": round((win[1] - win[0]) / 1000.0, 1) if win else None,
        "meta_reads_per_s": ((delta["info"] + delta["list"] + delta["inspect"]) / ((win[1] - win[0]) / 1000.0)) if delta and win else None,
        "all_requests": sum(delta.values()) if delta else None,
        "host_busy_mean": round(statistics.mean(busy), 1) if busy else None, "lat": lat,
        "dial": [(e[2].get("reason"), e[2].get("step"), e[2].get("cause")) for e in (ld.get("service_safety_events") or []) if e[0] == "dropped"],
    })
    return row


def fisher_one_sided(a_hit, a_n, b_hit, b_n):
    """P(B has <= b_hit drops | totals), i.e. one-sided p that B's drop proportion is lower than A's (hypergeometric tail)."""
    total_hit, total_n = a_hit + b_hit, a_n + b_n
    def pmf(k):
        return math.comb(a_n, total_hit - k) * math.comb(b_n, k) / math.comb(total_n, total_hit) if 0 <= k <= b_n and 0 <= total_hit - k <= a_n else 0.0
    return sum(pmf(k) for k in range(0, b_hit + 1))


def med(vals):
    v = [x for x in vals if x is not None]
    return statistics.median(v) if v else None


def reduction(a, b):
    return None if a in (None, 0) or b is None else 100.0 * (a - b) / a


def main():
    done = [ln.split() for ln in open(os.path.join(OUT, "done.list")) if ln.strip()] if os.path.isfile(os.path.join(OUT, "done.list")) else []
    rows = [run_row(*x) for x in done]
    print("%-12s %-3s %-6s %-8s %-7s %6s %5s %6s %7s %5s %5s %9s %9s %8s" % ("run", "arm", "host", "status", "STABLE", "admit", "unver", "deny", "timeout", "logTO", "drops", "meta/call", "info/call", "cpu_s/c"))
    for r in rows:
        print("%-12s %-3s %-6s %-8s %-7s %6s %5s %6s %7s %5s %5s %9s %9s %8s" % (
            r["run"], r["arm"], r["host"], r["status"][:8], r.get("stable"), r.get("admitted"), r.get("refused_unverified"), r.get("refused_default_deny"), r.get("timeouts"), r.get("log_timeouts"),
            r.get("drops"), "%.2f" % r["meta_per_call"] if r.get("meta_per_call") is not None else "-", "%.3f" % r["info_per_call"] if r.get("info_per_call") is not None else "-",
            "%.4f" % r["cpu_s_per_call"] if r.get("cpu_s_per_call") is not None else "-"))
    summary = {}
    for host in ("clean", "burn"):
        for arm in ("A", "B"):
            rs = [r for r in rows if r["host"] == host and r["arm"] == arm]
            ok = [r for r in rs if r["status"] == "OK"]
            summary[host + "/" + arm] = {
                "runs": len(rs), "readable": len(ok), "aborted": len(rs) - len(ok), "stable_pass": sum(1 for r in ok if r["stable"] == "PASS"),
                "runs_with_drop": sum(1 for r in ok if (r["drops"] or 0) > 0), "total_drops": sum(r["drops"] or 0 for r in ok),
                "runs_with_refusal": sum(1 for r in ok if (r["refused_unverified"] or 0) + (r["refused_default_deny"] or 0) > 0),
                "unverified_refusals": sum(r["refused_unverified"] or 0 for r in ok), "default_deny_refusals": sum(r["refused_default_deny"] or 0 for r in ok),
                "timeouts": sum(r["timeouts"] or 0 for r in ok), "median_log_timeouts": med([r["log_timeouts"] for r in ok]), "median_timeouts": med([r["timeouts"] for r in ok]),
                "median_meta_per_call": med([r["meta_per_call"] for r in ok]), "median_info_per_call": med([r["info_per_call"] for r in ok]),
                "median_cpu_s_per_call": med([r["cpu_s_per_call"] for r in ok]), "median_admitted": med([r["admitted"] for r in ok]),
                "median_daemon_cpu_s_window": med([r["daemon_cpu_s"] for r in ok]), "median_meta_reads_per_s": med([r["meta_reads_per_s"] for r in ok]),
                "median_all_requests": med([r["all_requests"] for r in ok]),
                "median_p95_status_ms": med([r["lat"]["status"]["p95"] for r in ok]), "median_p95_logs_ms": med([r["lat"]["logs"]["p95"] for r in ok]),
                "median_p50_status_ms": med([r["lat"]["status"]["p50"] for r in ok]), "median_p50_logs_ms": med([r["lat"]["logs"]["p50"] for r in ok]),
                "median_host_busy": med([r["host_busy_mean"] for r in ok]),
            }
    print()
    for k, v in summary.items():
        print(k, json.dumps(v))
    ev = {}
    a, b = summary["clean/A"], summary["clean/B"]
    if a["readable"] and b["readable"]:
        ev["clean"] = {
            "meta_reads_per_call_reduction_pct": reduction(a["median_meta_per_call"], b["median_meta_per_call"]), "target_ge": 65,
            "info_per_call_reduction_pct": reduction(a["median_info_per_call"], b["median_info_per_call"]), "info_target_ge": 90,
            "daemon_cpu_per_call_reduction_pct": reduction(a["median_cpu_s_per_call"], b["median_cpu_s_per_call"]), "cpu_target_ge": 30,
            "p95_status_A_B_ms": [a["median_p95_status_ms"], b["median_p95_status_ms"]], "p95_logs_A_B_ms": [a["median_p95_logs_ms"], b["median_p95_logs_ms"]],
            "p95_no_worse": (b["median_p95_status_ms"] is not None and b["median_p95_status_ms"] <= a["median_p95_status_ms"] and b["median_p95_logs_ms"] <= a["median_p95_logs_ms"]),
            "B_stable_pass": "%d/%d" % (b["stable_pass"], b["runs"]), "B_zero_refusals_drops_timeouts": (b["total_drops"] == 0 and b["unverified_refusals"] == 0 and b["default_deny_refusals"] == 0 and b["timeouts"] == 0),
        }
    a, b = summary["burn/A"], summary["burn/B"]
    if a["readable"] and b["readable"]:
        ev["contended"] = {
            "A_runs_with_drop": "%d/%d" % (a["runs_with_drop"], a["readable"]), "B_runs_with_drop": "%d/%d" % (b["runs_with_drop"], b["readable"]),
            "fisher_one_sided_p": fisher_one_sided(a["runs_with_drop"], a["readable"], b["runs_with_drop"], b["readable"]),
            "median_log_timeouts_A_B": [a["median_log_timeouts"], b["median_log_timeouts"]], "log_timeout_reduction_pct": reduction(a["median_log_timeouts"], b["median_log_timeouts"]), "log_timeout_target_ge": 50,
            "median_timeouts_A_B": [a["median_timeouts"], b["median_timeouts"]],
        }
    print()
    print(json.dumps(ev, indent=1))
    if "--json" in sys.argv:
        json.dump({"rows": rows, "summary": summary, "evaluation": ev}, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)


main()
