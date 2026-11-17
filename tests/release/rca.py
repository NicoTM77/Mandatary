"""Causal correlation of the approved workload (P1.20, R2). Standard library only.

Three independent timelines are recorded during the workload and joined here by wall-clock time (the harness,
the service container and the daemon share one host clock):

  attempts   one record per client call: [t_ms, interface, op, outcome, duration_ms]. `outcome` is "ok", a
             "<status>/<code>[/<reason>]" refusal or "transport". Nothing but timing and the closed outcome class.
  probe      one record per daemon read made BY THE HARNESS straight on the fixture daemon, independently of the
             service: [t_ms, call, duration_ms, ok]. It is the daemon's own latency as an outside observer sees it.
  events     the service's secret-free safety-proof lines: ["dropped"|"restored", t_ms, {fields}].

`correlate` answers the questions of the investigation without opinion: how many refusals fell inside a window in
which the service had dropped its proof, which drops there were (reason/step/cause), how long each outage lasted,
what the daemon's latency was before each drop, and which refusals are NOT explained by a recorded drop.
"""
import json
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone

from footprint import latency_summary

REFUSAL = re.compile(r"^403/")


def _proc_stat_total():
    """(busy_jiffies, total_jiffies) of the whole host from /proc/stat."""
    with open("/proc/stat") as fh:
        f = [int(x) for x in fh.readline().split()[1:]]
    idle = f[3] + (f[4] if len(f) > 4 else 0)
    return sum(f) - idle, sum(f)


def _find_pids(names):
    out = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open("/proc/%s/comm" % d) as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if comm in names:
            out.setdefault(comm, []).append(int(d))
    return out


def _cpu_jiffies(pid):
    try:
        with open("/proc/%d/stat" % pid) as fh:
            f = fh.read().rsplit(")", 1)[1].split()
        return int(f[11]) + int(f[12])  # utime + stime
    except (OSError, IndexError, ValueError):
        return None


class HostSampler(threading.Thread):
    """Once a second: the host's busy CPU share and the CPU share (of one CPU) of the daemon-side processes (dockerd,
    containerd, the Caddy proxy, the service). It says whether the host or the daemon was the bottleneck while the workload ran.
    Reads /proc only."""

    NAMES = ("dockerd", "containerd", "caddy", "mandatary")

    def __init__(self, extra_pids=()):
        super().__init__(daemon=True)
        self.stop_ev, self.rows, self.extra = threading.Event(), [], list(extra_pids)

    def run(self):
        hz = os.sysconf("SC_CLK_TCK")
        pids = _find_pids(self.NAMES)
        flat = {"%s:%d" % (n, p): p for n, ps in pids.items() for p in ps}
        for p in self.extra:
            flat.setdefault("service:%d" % p, p)
        prev_total, prev_t = _proc_stat_total(), time.time()
        prev = {k: _cpu_jiffies(p) for k, p in flat.items()}
        while not self.stop_ev.wait(1.0):
            now, total = time.time(), _proc_stat_total()
            dt = max(now - prev_t, 1e-3)
            busy = 100.0 * (total[0] - prev_total[0]) / max(total[1] - prev_total[1], 1)
            per = {}
            for k, p in flat.items():
                cur = _cpu_jiffies(p)
                if cur is not None and prev.get(k) is not None:
                    per[k] = round(100.0 * (cur - prev[k]) / hz / dt, 1)
                prev[k] = cur
            self.rows.append([int(now * 1000), round(busy, 1), per])
            prev_total, prev_t = total, now

    def finish(self):
        self.stop_ev.set()
        self.join(10)
        return self.rows


def parse_service_events(log_text):
    """Extract the safety-proof lines from the service's JSON log: [(kind, t_ms, fields)]. Lines that are not JSON or
    carry another message are ignored; no other field of a line is kept."""
    out = []
    for ln in log_text.splitlines():
        i = ln.find("{")
        if i < 0:
            continue
        try:
            d = json.loads(ln[i:])
        except ValueError:
            continue
        msg = d.get("msg", "")
        if msg == "docker safety proof dropped":
            kind = "dropped"
        elif msg == "docker safety proof restored":
            kind = "restored"
        elif msg in ("docker backend unverified", "docker backend verified"):
            kind = msg.split()[-1]
        else:
            continue
        try:
            t = datetime.fromisoformat(d["time"].replace("Z", "+00:00")).astimezone(timezone.utc)
        except (KeyError, ValueError):
            continue
        keep = {k: d[k] for k in ("reason", "step", "cause", "elapsed_ms", "inflight", "streams", "outage_ms") if k in d}
        out.append([kind, int(t.timestamp() * 1000), keep])
    return out


REQUEST_KINDS = ("ping", "info", "list", "inspect", "logs", "start", "stop", "restart", "other")


def parse_request_counts(log_text):
    """The service's daemon request counter lines ("docker daemon requests", one count per closed kind, totals since the
    process started): [[t_ms, {kind: n}]] in log order. Nothing else of a line is kept."""
    out = []
    for ln in log_text.splitlines():
        i = ln.find("{")
        if i < 0:
            continue
        try:
            d = json.loads(ln[i:])
        except ValueError:
            continue
        if d.get("msg") != "docker daemon requests":
            continue
        try:
            t = datetime.fromisoformat(d["time"].replace("Z", "+00:00")).astimezone(timezone.utc)
            counts = {k: int(d["req_" + k]) for k in REQUEST_KINDS}
        except (KeyError, ValueError, TypeError):
            continue
        out.append([int(t.timestamp() * 1000), counts])
    return out


def metadata_reads(counts):
    """The reads that verify safety: /info, container list and container inspect."""
    return counts["info"] + counts["list"] + counts["inspect"]


def outages(events):
    """Pair each drop with the next restoration -> [{start, end, fields}] (end None when never restored)."""
    res, cur = [], None
    for kind, t, f in sorted(events, key=lambda e: e[1]):
        if kind == "dropped":
            if cur is None:
                cur = {"start": t, "end": None, "drop": f}
        elif kind == "restored" and cur is not None:
            cur["end"] = t
            res.append(cur)
            cur = None
    if cur is not None:
        res.append(cur)
    return res


def _inside(t, o, slack_ms):
    end = o["end"] if o["end"] is not None else float("inf")
    return o["start"] - slack_ms <= t <= end + slack_ms


def correlate(attempts, probe, events, slack_ms=1500):
    """`slack_ms` widens an outage window on both sides: a call that STARTED a moment before the drop is refused
    after it, and one that started just after the restoration may still carry the old refusal."""
    outs = outages(events)
    refusals = [a for a in attempts if REFUSAL.match(a[3] or "") or (a[3] or "").startswith("forbidden/")]
    explained, unexplained = [], []
    for a in refusals:
        t_end = a[0] + a[4]  # a call is refused when it ends; its start may precede the drop
        (explained if any(_inside(t_end, o, slack_ms) for o in outs) else unexplained).append(a)
    by_reason = {}
    for o in outs:
        k = "%s/%s/%s" % (o["drop"].get("reason"), o["drop"].get("step"), o["drop"].get("cause"))
        by_reason[k] = by_reason.get(k, 0) + 1
    ok_probe = [p for p in probe if p[3]]
    lat_before = []
    for o in outs:
        window = [p[2] for p in ok_probe if o["start"] - 5000 <= p[0] <= o["start"]]
        lat_before.append({"drop_t": o["start"], "probe_max_ms_5s_before": max(window) if window else None, "probe_n": len(window),
                           "elapsed_ms": o["drop"].get("elapsed_ms"), "inflight": o["drop"].get("inflight"), "streams": o["drop"].get("streams")})
    classes = {}
    for a in refusals:
        classes[a[3]] = classes.get(a[3], 0) + 1
    dur = [(o["end"] - o["start"]) for o in outs if o["end"] is not None]
    return {
        "attempts": len(attempts), "ok": sum(1 for a in attempts if a[3] == "ok"), "refusals": len(refusals), "refusal_classes": classes,
        "refusals_inside_a_recorded_outage": len(explained), "refusals_not_explained_by_a_recorded_drop": len(unexplained),
        "unexplained_samples": unexplained[:5],
        "drops": len(outs), "drops_by_reason_step_cause": by_reason,
        "outage_ms": latency_summary(dur) if dur else None, "outages_unrestored": sum(1 for o in outs if o["end"] is None),
        "daemon_probe_ms": latency_summary([p[2] for p in ok_probe]) if ok_probe else None,
        "daemon_probe_failures": sum(1 for p in probe if not p[3]),
        "drop_context": lat_before[:40],
    }


class DaemonProbe(threading.Thread):
    """Times read-only daemon calls on the fixture daemon's own socket, from the harness, independently of the service.
    GET /_ping, /info and /containers/json only: the same reads the service makes, and nothing that changes state."""

    CALLS = ("/_ping", "/info", "/containers/json?all=1")

    def __init__(self, sock_path, period=0.4):
        super().__init__(daemon=True)
        self.path, self.period, self.stop_ev, self.rows = sock_path, period, threading.Event(), []

    def _get(self, target):
        t0 = time.time()
        ok = False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(20)
            s.connect(self.path)
            s.sendall(("GET %s HTTP/1.0\r\nHost: docker\r\n\r\n" % target).encode())
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            ok = buf.startswith(b"HTTP/1.") and b" 200 " in buf.split(b"\r\n", 1)[0]
            s.close()
        except OSError:
            ok = False
        self.rows.append([int(t0 * 1000), target.split("?")[0], round((time.time() - t0) * 1000, 2), ok])

    def run(self):
        i = 0
        while not self.stop_ev.is_set():
            self._get(self.CALLS[i % len(self.CALLS)])
            i += 1
            self.stop_ev.wait(self.period)

    def finish(self):
        self.stop_ev.set()
        self.join(30)
        return self.rows
