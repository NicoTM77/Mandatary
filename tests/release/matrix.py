"""The positive/negative authorization matrix of the P1.20 release acceptance and its exact usage tally.

The same ordered case list is executed through REST and through a real MCP client; each outcome is reduced to
(HTTP status, error code, reason) so the two transports are compared to the expectation AND to each other. Every
case also declares what the accounting contract (docs/usage-accounting.md) must have recorded for it, so the
expected totals are derived from the executed sequence rather than copied from a result:

  * a verified principal that was blocked by policy (403 default_deny, explicit DENY, missing target)  -> denied
  * a backend call that succeeded                                                                     -> allowed
  * an authorized call the daemon failed                                                              -> error
  * any 401, invalid input, unsupported operation, and refusals of Mandatary itself or its labelled
    peers (they precede authentication, decision D2)                                                  -> nothing

Pure functions only (no I/O) so tests/release/test_release.py can pin them with positive and negative fixtures.
"""
from collections import Counter

STATUS_OF_CODE = {"unauthenticated": 401, "forbidden": 403, "invalid_request": 400, "not_found": 404, "method_not_allowed": 405,
                  "payload_too_large": 413, "unsupported_media": 415, "too_many_streams": 429, "canceled": 499, "backend_failed": 502,
                  "backend_unavailable": 503, "timeout": 504, "internal": 500}

# label -> (permission key, REST method, REST path suffix, MCP tool, MCP/REST arguments)
OPS = {
    "status": ("container:inspect_status", "GET", "status", "container_status", {}),
    "config": ("container:inspect_config", "GET", "config", "container_config", {}),
    "logs": ("container:logs", "GET", "logs?tail=3", "container_logs", {"tail": 3}),
    "start": ("container:start", "POST", "start", "container_start", {}),
    "stop": ("container:stop", "POST", "stop", "container_stop", {"timeout_seconds": 5}),
    "restart": ("container:restart", "POST", "restart", "container_restart", {"timeout_seconds": 5}),
}
ORDER = ["status", "config", "logs", "restart", "stop", "start"]  # stop is always followed by start


def key(op):
    return OPS[op][0]


class Expect:
    """What a caller must observe. reasons is the set of acceptable `reason` values ('' = none)."""

    def __init__(self, status, code="", reasons=("",)):
        self.status, self.code, self.reasons = status, code, tuple(reasons)
        self.codes = tuple(code) if isinstance(code, (tuple, list)) else (code,)

    def matches(self, got):
        s, c, r = got
        return s == self.status and c in self.codes and r in self.reasons

    def __repr__(self):
        return "%s/%s/%s" % (self.status, "|".join(self.codes), "|".join(self.reasons))


OK = Expect(200)
DENY = Expect(403, "forbidden", ("default_deny",))
UNAUTH = Expect(401, "unauthenticated")
INVALID = Expect(400, "invalid_request")
NOT_FOUND = Expect(404, ("not_found", ""))  # a path outside the machine namespace is answered by the site with a plain 404
METHOD = Expect(405, "method_not_allowed")


class Either(Expect):
    """Any one of several exact classes (the daemon's refusal is classified by the backend adapter, see docs/api-mcp.md)."""

    def __init__(self, *options):
        self.options = options
        self.status, self.code, self.reasons, self.codes = 0, "", ("",), ("",)

    def matches(self, got):
        return any(o.matches(got) for o in self.options)

    def __repr__(self):
        return " or ".join(repr(o) for o in self.options)


# An authorized, well-formed request that the DAEMON refuses (the unstartable container C). The adapter reports a daemon
# refusal of this kind either as 502 backend_failed or, when the daemon classifies it as an invalid parameter, 400
# invalid_request. Either way it is an authorized call whose execution failed, so it is accounted as an error.
BACKEND = Either(Expect(502, "backend_failed"), Expect(400, "invalid_request"))
NO_ENDPOINT = Expect(403, "forbidden", ("safety_unverified", "endpoint_inactive", "default_deny"))


class Case:
    """one request. who: agent label, "" (no credential) or "literal:<garbage>". target: container name/ID.
    count: None (nothing is accounted) or (agent label, selector name or None, outcome)."""

    def __init__(self, cid, who, op, target, expect, count=None, endpoint="local", query=None, body=None, raw_path=None, tool=None, args=None, method=None):
        self.id, self.who, self.op, self.target, self.expect, self.count = cid, who, op, target, expect, count
        self.endpoint, self.query, self.body, self.raw_path, self.tool, self.args, self.method = endpoint, query, body, raw_path, tool, args, method


def norm_rest(status, body):
    """(status, code, reason) of a REST response."""
    if 200 <= status < 300:
        return (200, "", "")
    err = (body or {}).get("error", {}) if isinstance(body, dict) else {}
    return (status, err.get("code", ""), err.get("reason", "") or "")


def norm_mcp(res):
    """(status, code, reason) of one real-MCP-client step result (tests/release/mcpclient)."""
    if res.get("http_status"):
        return (res["http_status"], res.get("http_code", ""), res.get("error_reason", "") or "")
    if res.get("protocol_error"):
        return (404, "not_found", "protocol")  # an unknown tool is a protocol error that reaches nothing
    if res.get("is_error"):
        code = res.get("error_code", "")
        return (STATUS_OF_CODE.get(code, 0), code, res.get("error_reason", "") or "")
    return (200, "", "") if res.get("connected") else (0, "unconnected", "")


def op_case(cid, who, op, target, expect, count, **kw):
    return Case(cid, who, op, target, expect, count, **kw)


def build_cases(ctx):
    """ctx: names {A,B,C,self,self_id,peer,peer_id} and agent label -> user label ("" for a group-owned agent).
    Returns the ordered list of cases. Selector names in `count` are real container names or '*'."""
    A, B, C = ctx["A"], ctx["B"], ctx["C"]
    cases = []

    def add(*a, **k):
        cases.append(Case(*a, **k))

    # ---- cross product: agent x operation x target ------------------------------------------------------
    # a: all six on A; ro: status only on A; none: nothing; dn: ALLOW * but explicit DENY on B; grp: status via a group rule.
    grants = {"a": {"A": {o: A for o in ORDER}}, "ro": {"A": {"status": A}}, "none": {}, "dn": {"A": {o: "*" for o in ORDER}}, "grp": {"A": {"status": A}}}
    for who in ("a", "ro", "none", "dn", "grp"):
        for tgt_label, tgt in (("A", A), ("B", B)):
            for op in ORDER:
                cid = "X-%s-%s-%s" % (who, op, tgt_label)
                sel = grants[who].get(tgt_label, {}).get(op)
                if sel is not None:
                    add(cid, who, op, tgt, OK, (who, sel, "allowed"))
                else:
                    attributed = B if (who == "dn" and tgt_label == "B") else None  # an explicit DENY is attributed to its selector
                    add(cid, who, op, tgt, DENY, (who, attributed, "denied"))
    # ---- positive control for a wildcard grant on the other container ------------------------------------------
    add("P-wild-status-B", "wild", "status", B, OK, ("wild", "*", "allowed"))
    add("P-wild-logs-B", "wild", "logs", B, OK, ("wild", "*", "allowed"))
    # ---- self-protection: refused before authentication, even for a wildcard ALLOW; nothing is accounted -------
    for cid, tgt in (("S-self-name", ctx["self"]), ("S-self-id", ctx["self_id"]), ("S-peer-name", ctx["peer"]), ("S-peer-id", ctx["peer_id"])):
        for op in ("status", "config", "logs", "stop", "restart", "start"):
            add("%s-%s" % (cid, op), "wild", op, tgt, DENY, None)
    # ---- missing target (before authorization it is indistinguishable from ungranted) -> denied, no selector ----
    add("T-missing-status", "wild", "status", ctx["missing"], DENY, ("wild", None, "denied"))
    add("T-missing-stop", "wild", "stop", ctx["missing"], DENY, ("wild", None, "denied"))
    # ---- unknown endpoint: never data -----------------------------------------------------------------------------
    add("E-unknown-endpoint", "wild", "status", A, NO_ENDPOINT, None, endpoint="00000000-0000-4000-8000-0000000000ff")
    # ---- authentication failures: 401 before anything is looked at, nothing accounted -----------------------------
    add("U-no-credential", "", "status", A, UNAUTH, None)
    add("U-garbage-wellformed", "literal:mdt_" + "A" * 43, "status", A, UNAUTH, None)
    add("U-garbage-malformed", "literal:not-a-token", "stop", A, UNAUTH, None)
    add("U-no-credential-stop", "", "stop", B, UNAUTH, None)
    # ---- authorized call the daemon fails (container C cannot start) -> error ---------------------------------
    add("D-backend-error-start-C", "wild", "start", C, BACKEND, ("wild", "*", "error"))
    return cases


def rest_only_cases(ctx):
    """Invalid input and unsupported operations that exist as REST paths (never accounted, never reach Docker)."""
    A = ctx["A"]
    base = "/api/v1/endpoints/local/containers/" + A
    c = []

    def add(cid, who, method, path, expect, body=None):
        c.append(Case(cid, who, "raw", A, expect, None, raw_path=path, method=method, body=body))
    # invalid input from an authenticated caller: strict schema, nothing reaches Docker
    for cid, path in (("tail-zero", base + "/logs?tail=0"), ("tail-huge", base + "/logs?tail=999999"), ("unknown-param-all", base + "/status?all=true"),
                      ("unknown-param-force", base + "/status?force=1"), ("repeat-param", base + "/logs?tail=1&tail=2"), ("follow-numeric", base + "/logs?follow=1")):
        add("I-" + cid, "a", "GET", path, INVALID)
    add("I-timeout-zero", "a", "POST", base + "/stop", INVALID, {"timeout_seconds": 0})
    add("I-timeout-huge", "a", "POST", base + "/restart", INVALID, {"timeout_seconds": 301})
    add("I-unknown-field", "a", "POST", base + "/stop", INVALID, {"timeout_seconds": 5, "force": True})
    add("I-signal-field", "a", "POST", base + "/stop", INVALID, {"signal": "SIGKILL"})
    add("I-encoded-slash", "a", "GET", "/api/v1/endpoints/local/containers/a%2Fb/status", INVALID)
    # unsupported operations are absent, not denied (404), whoever asks and whatever they hold
    for cid, method, path in (("exec", "POST", base + "/exec"), ("kill", "POST", base + "/kill"), ("pause", "POST", base + "/pause"), ("remove", "DELETE", "/api/v1/endpoints/local/containers/" + A),
                              ("list", "GET", "/api/v1/endpoints/local/containers"), ("list-slash", "GET", "/api/v1/endpoints/local/containers/"), ("images", "GET", "/api/v1/endpoints/local/images"),
                              ("networks", "GET", "/api/v1/endpoints/local/networks"), ("info", "GET", "/api/v1/endpoints/local/info"), ("discovery", "GET", "/api/v1/endpoints"),
                              ("docker-path", "GET", "/containers/json"), ("docker-versioned", "GET", "/v1.44/containers/json"), ("docker-sock", "GET", "/var/run/docker.sock"),
                              ("dotdot", "GET", base + "/status/../../json"), ("case-variant", "GET", base.upper() + "/status")):
        add("N-" + cid, "wild", method, path, NOT_FOUND)
    # a known route with the wrong method is 405, with no state change
    add("N-post-status", "a", "POST", base + "/status", METHOD)
    add("N-get-stop", "a", "GET", base + "/stop", METHOD)
    add("N-delete-start", "a", "DELETE", base + "/start", METHOD)
    return c


UNSUPPORTED_TOOLS = ["container_exec", "container_kill", "container_pause", "container_remove", "container_list", "container_inspect", "container_create", "docker_api", "docker_raw", "image_list", "volume_list", "network_list"]


class Tally:
    """Exact expected usage totals: {(agent_name, user_name|None, selector_name|None, operation): [allowed, denied, error]}."""

    def __init__(self, agent_name, user_of):
        self.agent_name, self.user_of = agent_name, user_of
        self.t = {}
        # Calls whose outcome the CLIENT could not observe (refused or timed out while in flight). The server accounts each of them
        # per docs/usage-accounting.md (a call whose authorization ended meanwhile is `allowed` when the daemon completed it, `denied`
        # when it was cut off or refused at admission, and nothing when it never reached accounting), so the exact total is only known to
        # lie between the observed successes and the successes plus these attempts. {cell key: attempts}.
        self.bands = {}

    def add_band(self, who, op, selector, attempts):
        """Record `attempts` calls of one cell whose accounting the client cannot observe. 0 attempts is exactness."""
        if attempts:
            k = (self.agent_name(who), self.user_of(who), selector, key(op))
            self.bands[k] = self.bands.get(k, 0) + attempts

    def add(self, who, op, selector, outcome, n=1):
        k = (self.agent_name(who), self.user_of(who), selector, key(op))
        cell = self.t.setdefault(k, [0, 0, 0])
        cell[("allowed", "denied", "error").index(outcome)] += n

    def add_case(self, case, n=1):
        if case.count is not None:
            who, sel, outcome = case.count
            self.add(who, case.op, sel, outcome, n)

    def totals(self):
        return {k: tuple(v) for k, v in self.t.items()}

    def events(self):
        return sum(sum(v) for v in self.t.values())


def diff_totals(expected, got, bands=None):
    """Human-readable differences between expected and measured totals ([] means agreement).

    Without `bands` the comparison is exact equality. A cell with a band of n unobserved attempts is held to the documented rule instead:
    every observed outcome must be accounted (each measured component >= the expected one) and at most n further outcomes may exist
    (total measured <= total expected + n). A cell without a band stays exact, so a clean run is compared exactly."""
    bands = bands or {}
    out = []
    for k in sorted(set(expected) | set(got), key=str):
        e, g = expected.get(k), got.get(k)
        if e == g:
            continue
        n = bands.get(k, 0)
        if not n:
            out.append("%s expected %s got %s" % (k, e, g))
            continue
        base, have = e or (0, 0, 0), g or (0, 0, 0)
        if any(h < b for b, h in zip(base, have)):
            out.append("%s expected at least %s got %s" % (k, e, g))
        elif sum(have) - sum(base) > n:
            out.append("%s expected %s plus at most %d unobserved, got %s" % (k, e, n, g))
    return out


def merge_rows(rows):
    """Rows of the usage rollups -> totals keyed like Tally. Zero rows are dropped."""
    out = Counter()
    cells = {}
    for agent, user, sel, op, a, d, e in rows:
        cell = cells.setdefault((agent, user, sel, op), [0, 0, 0])
        cell[0] += int(a or 0)
        cell[1] += int(d or 0)
        cell[2] += int(e or 0)
    del out
    return {k: tuple(v) for k, v in cells.items() if any(v)}
