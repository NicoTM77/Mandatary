"""Shared state of one P1.20 release-acceptance run: the isolated-daemon environment, the result recorder, the
fixture containers, the identities and credentials created through the administrative API, the usage tally and the
measurements that end up in the versioned report."""
import re
import time

import matrix
import stack

AGENTS = {  # label -> (owner kind, owner label)
    "a": ("user", "owner"), "ro": ("group", "g"), "none": ("user", "owner"), "dn": ("user", "owner"), "grp": ("user", "owner"), "wild": ("user", "owner"),
    "exp": ("user", "owner"), "rot": ("user", "owner"), "rev": ("user", "owner"), "dis": ("user", "owner"), "pol": ("user", "owner"), "sess": ("user", "owner"),
    "load1": ("user", "owner"), "load2": ("user", "owner"),
}


class Ctx:
    def __init__(self, env, args):
        self.e, self.a = env, args
        self.res = env.res
        self.ev = {"environment": {}, "image": {}, "footprint": {}, "matrix": {}, "usage": {}, "persistence": {}, "restore": {}, "migration": {}, "lifecycle": {}}
        self.dep = None
        self.deps = []
        self.rest = self.mcp = None
        self.users, self.groups, self.agents, self.cred_ids, self.rules = {}, {}, {}, {}, {}
        self.tokens = {}
        self.names = {}
        self.tally = matrix.Tally(lambda who: "rel-" + who, self.user_of)
        self.t_events = time.time()

    # ---- recording -----------------------------------------------------------------------------------------
    def check(self, rid, name, ok, detail=""):
        return self.res.check(rid, name, bool(ok), self.e.scrub(str(detail))[:400] if detail != "" else "")

    def blocked(self, rid, name, why):
        self.res.blocked(rid, name, why)

    # ---- helpers ---------------------------------------------------------------------------------------------
    def user_of(self, who):
        kind, owner = AGENTS[who]
        return "rel-" + owner if kind == "user" else None

    def adm(self, method, path, body=None):
        st, _, b = self.dep.admin.req(method, path, body)
        return st, b

    def ids(self, body, key="id"):
        return stack.find_ids(body, key)

    def sel_name(self, label):
        return {"A": self.names["A"], "B": self.names["B"], "*": "*"}.get(label, label)

    def resolve_count(self, c):
        """Case.count uses real names already; kept for symmetry."""
        return c

    def record_ok(self, who, op, selector, outcome="allowed", n=1):
        self.tally.add(who, op, selector, outcome, n)

    @staticmethod
    def redact(text):
        return re.sub(r"mdt_[A-Za-z0-9_-]{20,}", "mdt_[X]", text)
