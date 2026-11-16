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
import re
import socket
import threading
import time
from datetime import datetime, timezone

from footprint import latency_summary

REFUSAL = re.compile(r"^403/")


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
