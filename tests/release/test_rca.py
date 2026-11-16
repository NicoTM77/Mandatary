#!/usr/bin/env python3
"""Hermetic tests of the causal correlation of the approved workload (tests/release/rca.py, P1.20 R2): they run
on synthetic timelines and need no Docker. Each positive case has a negative twin, so a correlator that explains
everything (or nothing) is caught here.

    python3 tests/release/test_rca.py
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "image"))
sys.path.insert(0, HERE)
import rca  # noqa: E402


def line(t_iso, msg, **kw):
    return json.dumps(dict({"time": t_iso, "level": "WARN", "msg": msg}, **kw))


class ServiceEvents(unittest.TestCase):
    LOG = "\n".join([
        "mandatary-1  | " + line("2026-11-16T10:00:00.250Z", "docker safety proof dropped", reason="check_deadline", step="inventory", cause="deadline", elapsed_ms=2001, inflight=17, streams=5),
        "mandatary-1  | " + line("2026-11-16T10:00:04.750Z", "docker safety proof restored", outage_ms=4500),
        "mandatary-1  | " + line("2026-11-16T10:00:05.000Z", "request completed", method="GET", status=200),
        "mandatary-1  | not json at all",
        "mandatary-1  | " + line("2026-11-16T10:00:06.000Z", "docker safety proof dropped", reason="[REDACTED]", step="[REDACTED]", secret="x"),
    ])

    def test_only_the_closed_fields_of_the_proof_lines_are_kept(self):
        ev = rca.parse_service_events(self.LOG)
        self.assertEqual([e[0] for e in ev], ["dropped", "restored", "dropped"])
        self.assertEqual(ev[0][2], {"reason": "check_deadline", "step": "inventory", "cause": "deadline", "elapsed_ms": 2001, "inflight": 17, "streams": 5})
        self.assertNotIn("secret", ev[2][2])

    def test_a_line_with_another_message_is_ignored(self):
        self.assertEqual(rca.parse_service_events(line("2026-11-16T10:00:00Z", "request completed", status=403)), [])


class Outages(unittest.TestCase):
    def test_a_drop_is_paired_with_the_next_restoration(self):
        ev = [["dropped", 1000, {"reason": "r"}], ["restored", 5000, {}], ["dropped", 9000, {"reason": "s"}]]
        o = rca.outages(ev)
        self.assertEqual([(x["start"], x["end"]) for x in o], [(1000, 5000), (9000, None)])


class Correlation(unittest.TestCase):
    EVENTS = [["dropped", 10_000, {"reason": "check_deadline", "step": "inventory", "cause": "deadline", "elapsed_ms": 2000, "inflight": 20, "streams": 5}],
              ["restored", 14_000, {"outage_ms": 4000}]]

    def test_refusals_inside_the_outage_are_explained(self):
        att = [[9_000, "rest", "status", "ok", 100.0],
               [11_000, "rest", "status", "403/forbidden/safety_unverified", 50.0],
               [12_000, "mcp", "container_logs", "forbidden/safety_unverified", 50.0],
               [20_000, "rest", "status", "ok", 80.0]]
        c = rca.correlate(att, [[9_900, "/info", 800.0, True]], self.EVENTS)
        self.assertEqual((c["refusals"], c["refusals_inside_a_recorded_outage"], c["refusals_not_explained_by_a_recorded_drop"]), (2, 2, 0))
        self.assertEqual(c["drops_by_reason_step_cause"], {"check_deadline/inventory/deadline": 1})
        self.assertEqual(c["drop_context"][0]["probe_max_ms_5s_before"], 800.0)

    def test_a_refusal_outside_every_outage_is_reported_as_not_explained(self):
        att = [[30_000, "rest", "status", "403/forbidden/default_deny", 40.0], [31_000, "mcp", "container_status", "forbidden/default_deny", 40.0]]
        c = rca.correlate(att, [], self.EVENTS)
        self.assertEqual(c["refusals_not_explained_by_a_recorded_drop"], 2)
        self.assertEqual(c["refusals_inside_a_recorded_outage"], 0)

    def test_no_drop_and_no_refusal_is_clean(self):
        c = rca.correlate([[1, "rest", "status", "ok", 3.0]], [[1, "/_ping", 2.0, True]], [])
        self.assertEqual((c["refusals"], c["drops"], c["outages_unrestored"]), (0, 0, 0))

    def test_an_unrestored_proof_explains_every_later_refusal(self):
        att = [[15_000, "rest", "status", "403/forbidden/safety_unverified", 5.0], [99_000, "rest", "status", "403/forbidden/safety_unverified", 5.0]]
        c = rca.correlate(att, [], [["dropped", 10_000, {"reason": "operation_fault"}]])
        self.assertEqual((c["refusals_inside_a_recorded_outage"], c["outages_unrestored"]), (2, 1))

    def test_a_probe_failure_is_counted_and_not_a_latency(self):
        c = rca.correlate([], [[1, "/info", 20_000.0, False], [2, "/info", 10.0, True]], [])
        self.assertEqual(c["daemon_probe_failures"], 1)
        self.assertEqual(c["daemon_probe_ms"]["n"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
