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
import matrix  # noqa: E402
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


class RequestCounters(unittest.TestCase):
    KINDS = {"ping": 1, "info": 2, "list": 3, "inspect": 4, "logs": 5, "start": 6, "stop": 7, "restart": 8, "other": 9}

    def counter_line(self, t, **over):
        f = {"req_" + k: v for k, v in self.KINDS.items()}
        f.update(over)
        return "mandatary-1  | " + line(t, "docker daemon requests", **f)

    def test_the_counter_lines_are_parsed_in_order_with_only_the_closed_kinds(self):
        log = "\n".join([self.counter_line("2026-11-16T10:00:00.000Z"), "garbage", self.counter_line("2026-11-16T10:01:00.000Z", req_info=40, secret="x"),
                         line("2026-11-16T10:01:01Z", "request completed", status=200)])
        got = rca.parse_request_counts(log)
        self.assertEqual([g[1]["info"] for g in got], [2, 40])
        self.assertLess(got[0][0], got[1][0])
        self.assertEqual(set(got[1][1]), set(rca.REQUEST_KINDS))

    def test_a_line_with_a_missing_or_malformed_count_is_ignored_never_guessed(self):
        bad = json.loads(self.counter_line("2026-11-16T10:00:00Z").split("|", 1)[1])
        del bad["req_logs"]
        self.assertEqual(rca.parse_request_counts(json.dumps(bad)), [])
        bad2 = json.loads(self.counter_line("2026-11-16T10:00:00Z").split("|", 1)[1])
        bad2["req_info"] = "many"
        self.assertEqual(rca.parse_request_counts(json.dumps(bad2)), [])

    def test_metadata_reads_are_info_plus_list_plus_inspect(self):
        self.assertEqual(rca.metadata_reads(self.KINDS), 2 + 3 + 4)


class UsageBand(unittest.TestCase):
    """The server's documented accounting rule is not recomputed from what the client saw (P1.20 R2, L2): an observed refusal may
    still be accounted `allowed` (the daemon completed it after the authorization ended) or `denied` or not at all."""

    K = ("rel-load1", "rel-owner", "ctr-a", "container:status")

    def test_without_unobserved_attempts_the_comparison_stays_exact(self):
        self.assertEqual(matrix.diff_totals({self.K: (10, 0, 0)}, {self.K: (10, 0, 0)}, {}), [])
        self.assertTrue(matrix.diff_totals({self.K: (10, 0, 0)}, {self.K: (11, 0, 0)}, {}))  # one more allowed than the client saw: a failure

    def test_unobserved_attempts_may_be_accounted_as_allowed_or_denied_or_not_at_all(self):
        exp = {self.K: (10, 0, 0)}
        band = {self.K: 3}
        for got in ((10, 0, 0), (13, 0, 0), (11, 2, 0), (10, 1, 0), (12, 0, 1)):
            self.assertEqual(matrix.diff_totals(exp, {self.K: got}, band), [], got)

    def test_more_outcomes_than_attempts_is_still_a_failure(self):
        self.assertTrue(matrix.diff_totals({self.K: (10, 0, 0)}, {self.K: (14, 0, 0)}, {self.K: 3}))
        self.assertTrue(matrix.diff_totals({self.K: (10, 0, 0)}, {self.K: (11, 3, 0)}, {self.K: 3}))

    def test_an_observed_success_that_was_not_accounted_is_a_failure_even_inside_a_band(self):
        self.assertTrue(matrix.diff_totals({self.K: (10, 0, 0)}, {self.K: (9, 3, 0)}, {self.K: 3}))
        self.assertTrue(matrix.diff_totals({self.K: (10, 0, 0)}, {}, {self.K: 3}))

    def test_a_band_applies_to_its_own_cell_only(self):
        other = ("rel-load1", "rel-owner", "ctr-a", "container:logs")
        exp = {self.K: (10, 0, 0), other: (5, 0, 0)}
        got = {self.K: (12, 0, 0), other: (6, 0, 0)}
        self.assertEqual(len(matrix.diff_totals(exp, got, {self.K: 2})), 1)

    def test_the_tally_collects_bands_per_cell_and_clears_to_exact_with_no_attempts(self):
        t = matrix.Tally(lambda who: "rel-" + who, lambda who: "rel-owner")
        t.add_band("load1", "status", "ctr-a", 0)
        self.assertEqual(t.bands, {})
        t.add_band("load1", "status", "ctr-a", 2)
        t.add_band("load1", "status", "ctr-a", 1)
        self.assertEqual(list(t.bands.values()), [3])


class SealedAdverseRuns(unittest.TestCase):
    """A clean final run never erases a contradictory same-content failure (P1.20 R2/A)."""

    CRIT = lambda self, state: [{"id": "C", "text": "", "evidence": ["A@r"],
                                 "adverse": {"state": state, "refs": ["X@diagnostics/d.json"], "disposition": "why"}}]

    def test_an_open_adverse_failure_fails_the_criterion_despite_a_passing_final_run(self):
        import report
        rows = report.evaluate(self.CRIT("open"), {"A@r": "PASS"}, {"r": "00", "diagnostics/d.json": "11"}, {"X@diagnostics/d.json": "FAIL"})
        self.assertEqual(rows[0]["status"], "FAIL")

    def test_a_dispositioned_adverse_failure_no_longer_counts_but_stays_listed(self):
        import report
        rows = report.evaluate(self.CRIT("dispositioned"), {"A@r": "PASS"}, {"r": "00", "diagnostics/d.json": "11"}, {"X@diagnostics/d.json": "FAIL"})
        self.assertEqual(rows[0]["status"], "PASS")
        self.assertEqual(rows[0]["adverse_links"][0]["result"], "FAIL")

    def test_an_open_adverse_run_that_cannot_be_read_is_unverified_never_a_pass(self):
        import report
        rows = report.evaluate(self.CRIT("open"), {"A@r": "PASS"}, {"r": "00"}, {})
        self.assertEqual(rows[0]["status"], "UNVERIFIED")

    def test_an_open_adverse_run_that_passed_does_not_fail_the_criterion(self):
        import report
        rows = report.evaluate(self.CRIT("open"), {"A@r": "PASS"}, {"r": "00", "diagnostics/d.json": "11"}, {"X@diagnostics/d.json": "PASS"})
        self.assertEqual(rows[0]["status"], "PASS")

    def test_a_criterion_without_adverse_runs_is_unchanged(self):
        import report
        rows = report.evaluate([{"id": "C", "text": "", "evidence": ["A@r"]}], {"A@r": "PASS"}, {"r": "00"})
        self.assertEqual(rows[0]["status"], "PASS")


class HostSampling(unittest.TestCase):
    @unittest.skipUnless(os.path.exists("/proc/stat"), "needs a Linux /proc")
    def test_the_sampler_reads_the_host_and_the_named_processes_from_proc_only(self):
        s = rca.HostSampler([os.getpid()])
        s.start()
        t_end = __import__("time").time() + 2.6
        while __import__("time").time() < t_end:
            sum(i * i for i in range(20000))
        rows = s.finish()
        self.assertGreaterEqual(len(rows), 1)
        t, busy, per = rows[-1]
        self.assertTrue(0.0 <= busy <= 100.0, busy)
        self.assertIn("service:%d" % os.getpid(), per)  # the caller's own process is sampled like the service would be
        self.assertGreater(per["service:%d" % os.getpid()], 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
