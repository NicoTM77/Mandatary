"""Transport executors of the P1.20 matrix: REST over the TLS proxy and the real MCP client (tests/release/mcpclient)."""
import json
import os
import subprocess
import time

import matrix
import stack


class Rest:
    def __init__(self, dep, tokens):
        self.dep, self.tokens = dep, tokens
        self.cl = stack.Client(dep.port, dep.caroot)

    def token(self, who):
        if who.startswith("literal:"):
            return who[len("literal:"):]
        return self.tokens.get(who) if who else None

    def raw(self, method, path, who="", body=None):
        t0 = time.time()
        # A bearer client is not a browser: it never sends an Origin header (a request that carries one is refused, 403 forbidden_origin).
        st, hd, b = self.cl.req(method, path, body=body, bearer=self.token(who), origin=False)
        return matrix.norm_rest(st, b), b, (time.time() - t0) * 1000

    def run(self, case):
        if case.raw_path is not None:
            return self.raw(case.method, case.raw_path, case.who, case.body)[0]
        key, method, suffix, _, args = matrix.OPS[case.op]
        body = None
        if method == "POST" and "timeout_seconds" in args:
            body = dict(args)
        path = "/api/v1/endpoints/%s/containers/%s/%s" % (case.endpoint, case.target, suffix)
        return self.raw(method, path, case.who, body)[0]

    def op(self, who, op, target, endpoint="local"):
        return self.run(matrix.Case("adhoc", who, op, target, None, None, endpoint=endpoint))


class Mcp:
    """Runs the official go-sdk MCP client (one process per batch) against the deployment's proxy."""

    def __init__(self, dep, binary, tokens, work):
        self.dep, self.binary, self.work = dep, binary, work
        self.tokfile = os.path.join(work, "mcp-tokens.json")
        self.set_tokens(tokens)

    def set_tokens(self, tokens):
        with open(self.tokfile, "w", opener=lambda p, f: os.open(p, f, 0o600)) as fh:
            json.dump(tokens, fh)

    def batch(self, steps, load=None, timeout=300):
        script = os.path.join(self.work, "mcp-script.json")
        doc = {"url": self.dep.origin + "/mcp", "steps": steps}
        if load:
            doc = {"url": self.dep.origin + "/mcp", "load": load}
        with open(script, "w") as fh:
            json.dump(doc, fh)
        p = subprocess.run([self.binary, "-script", script, "-tokens", self.tokfile, "-ca", self.dep.caroot, "-dial", "127.0.0.1:%d" % self.dep.port,
                            "-server-name", stack.HOST], capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError("mcpclient exit %d: %s" % (p.returncode, p.stderr[-300:]))
        return json.loads(p.stdout)

    @staticmethod
    def step_of(case):
        who = case.who
        if case.tool:
            args = dict(case.args or {})
            return {"id": case.id, "token": who, "op": case.tool, "args": args}
        key, method, suffix, tool, args = matrix.OPS[case.op]
        a = {"endpoint": case.endpoint, "container": case.target}
        a.update(args)
        return {"id": case.id, "token": who, "op": tool, "args": a}

    def run_cases(self, cases):
        res = self.batch([self.step_of(c) for c in cases])
        return [matrix.norm_mcp(r) for r in res], res

    def op(self, who, op, target, endpoint="local"):
        c = matrix.Case("adhoc", who, op, target, None, None, endpoint=endpoint)
        return self.run_cases([c])[0][0]

    def tools(self, who):
        r = self.batch([{"id": "list", "token": who, "list": True}])[0]
        return r
