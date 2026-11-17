"""One real Compose deployment of the release image for the P1.20 acceptance (standard library only).

A Deployment is what an operator would run: the unmodified docker-compose.yml + deploy/compose.proxy.yml, the
acceptance overlay (tests/image/compose.acceptance.yml: TLS SMTP receiver and the fixture CA, nothing else), a
private data directory and master key, and the real Docker daemon of the declared isolated fixture host. It
drives the product only through its public surfaces (HTTPS through the TLS proxy, the host-local helper on a real
pty, the daemon) exactly like tests/image/stack.py, whose client helpers it reuses.
"""
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import time
import uuid

import stack  # tests/image/stack.py: Client, totp, reveal_token, pty_run, mailpit, find_ids, free_port, make_certs


class DeployError(Exception):
    pass


def refusal(body):
    """' [code/reason]' of a refusal body (the service's closed vocabulary only, never free text), or ''. Diagnostics: a bare 403 says nothing."""
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return ""
    code, reason = str(err.get("code", ""))[:40], str(err.get("reason", ""))[:40]
    return " [%s/%s]" % (code, reason) if code or reason else ""


class Admin:
    """A signed-in administrator session (password + TOTP, AAL2) and the credentials needed to sign in again."""

    def __init__(self, dep, username, password, seed):
        self.dep, self.username, self.password, self.seed = dep, username, password, seed
        self.cl = None
        self.signed_in_at = 0.0
        self.last_period = 0

    def login(self):
        """Password then TOTP. A TOTP code is accepted once per period, so wait for a new period first."""
        while int(time.time() // 30) <= self.last_period:
            time.sleep(0.5)
        cl = stack.Client(self.dep.port, self.dep.caroot)
        st, _, body = cl.req("POST", "/api/v1/login", {"username": self.username, "password": self.password})
        if st != 200 or not isinstance(body, dict) or body.get("step") != "factor":
            raise DeployError("login step 1: %s%s" % (st, refusal(body)))
        cl.csrf = body.get("csrf_token")
        self.last_period = int(time.time() // 30)
        st, _, body = cl.req("POST", "/api/v1/login/totp", {"code": stack.totp(self.seed)})
        if st != 200 or not isinstance(body, dict) or body.get("step") != "session":
            raise DeployError("login step 2: %s%s (TOTP period %d, second %.1f of it)" % (st, refusal(body), int(time.time() // 30), time.time() % 30))
        st, _, body = cl.req("GET", "/api/v1/session")
        cl.csrf = (body or {}).get("csrf_token") if isinstance(body, dict) else None
        self.cl, self.signed_in_at = cl, time.time()
        return cl

    def fresh(self):
        """The session whose AAL2 evidence is younger than the 15-minute step-up window (re-signing in if needed)."""
        if self.cl is None or time.time() - self.signed_in_at > 8 * 60:
            self.login()
        return self.cl

    def req(self, method, path, body=None):
        return self.fresh().req(method, path, body)


class Deployment:
    def __init__(self, env, tag, key_from=None, bind_uuid=None):
        self.e = env
        self.tag = tag
        self.pfx = env.pfx + tag
        uid, gid = os.getuid(), os.getgid()
        self.uid, self.gid = uid, gid
        if key_from is None:
            self.base, self.key = env.prepare_state(tag, uid, gid)
        else:  # the same master key on a fresh data directory (a same-key restore target)
            self.base, self.key = self._prepare_with_key(tag, key_from)
        self.port, self.mp_port = stack.free_port(), stack.free_port()
        self.bind = bind_uuid or str(uuid.uuid4())
        self.certs = os.path.join(env.work, tag + "-certs")
        os.makedirs(self.certs, mode=0o755)
        stack.make_certs(self.certs)
        self.envfile = os.path.join(env.work, tag + "-stack.env")
        self.project = self.pfx + "stk"
        self.caroot = os.path.join(env.work, tag + "-caddy-root.crt")
        self.mand = self.proxy = None
        self.admin = None
        self.cl = None
        self.origin = "https://%s:%d" % (stack.HOST, self.port)

    def _prepare_with_key(self, tag, key):
        e = self.e
        base = os.path.join(e.work, tag)
        os.makedirs(base, mode=0o700)
        os.chmod(base, 0o700)
        for sub in ("keys", "data"):
            os.makedirs(os.path.join(base, sub), mode=0o700)
            os.chmod(os.path.join(base, sub), 0o700)
        with open(os.path.join(base, "keys", "master.key"), "w", opener=lambda p, f: os.open(p, f, 0o600)) as fh:
            fh.write(key + "\n")
        os.chmod(os.path.join(base, "keys", "master.key"), 0o400)
        return base, key

    # ---- compose ------------------------------------------------------------------------------------------
    def _cmd(self):
        e = self.e
        return ["docker", "--host", e.ep, "compose", "-p", self.project, "--env-file", self.envfile, "-f", "docker-compose.yml", "-f", "deploy/compose.proxy.yml", "-f", "tests/image/compose.acceptance.yml"]

    def compose(self, *args, check=True, timeout=300):
        p = subprocess.run(self._cmd() + list(args), cwd=self.e.repo, capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise DeployError("compose " + " ".join(args) + ": " + self.e.scrub(p.stderr[-300:]))
        return p

    def _write_env(self, image=None):
        e, a = self.e, self.e.a
        env = {
            "MANDATARY_IMAGE": image or a.image, "MANDATARY_INSTANCE_UUID": self.bind, "MANDATARY_PUBLIC_ORIGIN": self.origin,
            "MANDATARY_PUBLIC_HOST": stack.HOST, "MANDATARY_DATA_HOST_DIR": self.base + "/data", "MANDATARY_MASTER_KEY_HOST_FILE": self.base + "/keys/master.key",
            "MANDATARY_DOCKER_SOCKET_HOST": e.sock, "DOCKER_SOCKET_GID": e.docker_gid,
            "MANDATARY_SMTP_RELAY": "smtp.test:1025", "MANDATARY_SMTP_TLS": "starttls", "MANDATARY_SMTP_SENDER": "mandatary@mandatary.test",
            "MANDATARY_NOTICE_CONTACT": "ops@mandatary.test", "MANDATARY_PROXY_HTTPS_PORT": str(self.port), "MANDATARY_LOG_LEVEL": "info",
            "ACC_UID": str(self.uid), "ACC_GID": str(self.gid), "ACC_CERTS_DIR": self.certs, "ACC_MAILPIT_PORT": str(self.mp_port),
        }
        with open(self.envfile, "w", opener=lambda p, f: os.open(p, f, 0o600)) as fh:
            fh.write("".join("%s=%s\n" % kv for kv in env.items()))

    def up(self, image=None):
        e = self.e
        e.stacks.append({"down": self._cmd() + ["down", "-v", "--timeout", "10"]})
        # A host port chosen a moment earlier can be taken by another process before Compose binds it (observed on shared hosted runners):
        # that is a harness race, not a product result, so only that exact failure is retried, on fresh ports, before anything has started.
        for attempt in range(4):
            self.origin = "https://%s:%d" % (stack.HOST, self.port)
            self._write_env(image)
            try:
                self.compose("up", "-d")
                break
            except DeployError as ex:
                if attempt == 3 or not re.search(r"failed to bind host port|address already in use", str(ex)):
                    raise
                self.compose("down", "-v", "--timeout", "10", check=False)
                self.port, self.mp_port = stack.free_port(), stack.free_port()
        self.mand = self.compose("ps", "-q", "mandatary").stdout.strip()
        self.proxy = self.compose("ps", "-q", "proxy").stdout.strip()
        e.containers += [c for c in (self.mand, self.proxy) if c]
        if not e.wait(lambda: e.health(self.mand) == "healthy", 90):
            raise DeployError("mandatary did not become healthy: " + e.logs(self.mand)[-200:])
        if not e.wait(lambda: e.ready_exec(self.mand), 60):
            raise DeployError("mandatary did not become ready: " + e.logs(self.mand)[-200:])
        if not e.wait(lambda: e.docker("cp", self.proxy + ":/data/caddy/pki/authorities/local/root.crt", self.caroot, check=False).returncode == 0, 60):
            raise DeployError("the proxy never issued its local CA")
        self.cl = stack.Client(self.port, self.caroot)
        return self

    def down(self):
        self.compose("down", "-v", "--timeout", "10", check=False)
        self.e.stacks[:] = [s for s in self.e.stacks if s["down"] != self._cmd() + ["down", "-v", "--timeout", "10"]]

    def stop(self):
        t = time.time()
        self.compose("stop", "-t", "15", "mandatary")
        return self.e.inspect(self.mand)["State"]["ExitCode"], time.time() - t

    def start(self):
        self.compose("start", "mandatary")
        if not self.e.wait(lambda: self.e.ready_exec(self.mand), 90):
            raise DeployError("not ready after start")

    def restart(self):
        self.compose("restart", "mandatary")
        if not self.e.wait(lambda: self.e.ready_exec(self.mand), 90):
            raise DeployError("not ready after restart")

    def kill9(self):
        """SIGKILL the service (a crash). Docker's restart policy (unless-stopped) brings it back."""
        before = self.e.inspect(self.mand)["State"]["StartedAt"]
        # A real crash: SIGKILL delivered to the service's process from the host. `docker kill` is NOT used: the daemon records an explicit
        # kill as a manual stop and (correctly) never applies the restart policy to it, which would test nothing about crash recovery.
        os.kill(self.host_pid(), signal.SIGKILL)
        if not self.e.wait(lambda: (self.e.inspect(self.mand) or {}).get("State", {}).get("StartedAt") != before and self.e.ready_exec(self.mand), 120):
            raise DeployError("the service did not come back after SIGKILL")
        st = self.e.inspect(self.mand)
        return {"restart_count": st.get("RestartCount"), "started_at_changed": st["State"]["StartedAt"] != before}

    def host_pid(self):
        return int(self.e.inspect(self.mand)["State"]["Pid"])

    def logs(self):
        return self.compose("logs", "--no-color", check=False).stdout

    # ---- host-local helper (the same binary the image runs, on the host) -------------------------------------
    def helper(self, *args):
        return stack.pty_run([self.e.a.host_binary, *args, "--data-dir", self.base + "/data", "--master-key-file", self.base + "/keys/master.key"])

    # ---- setup: the same flow for first-admin setup and for restore-administrator recovery ------------------
    def complete_setup(self, token, username, check):
        """Exchange a host-revealed token and enrol ONE administrator (two notification addresses, one confirmed,
        TOTP with a live code). `check(id, name, ok, detail)` records each step. Returns an Admin (not signed in)."""
        e, port, caroot = self.e, self.port, self.caroot
        cl = stack.Client(port, caroot)
        st, _, body = cl.req("POST", "/api/v1/setup/exchange", {"token": token})
        cl.csrf = (body or {}).get("csrf_token") if isinstance(body, dict) else None
        check("setup-exchange", "the host-revealed token exchanges once for a setup-only session", st == 200 and bool(cl.csrf), str(st))
        password = "Tq7-" + secrets.token_urlsafe(18) + "-vP"
        e.secrets.append(password)
        st, _, body = cl.req("POST", "/api/v1/setup/account", {"username": username, "password": password, "addresses": [username + "@mandatary.test", username + "-2@mandatary.test"]})
        addrs = (body or {}).get("addresses", []) if isinstance(body, dict) else []
        check("setup-account", "administrator staged with two notification addresses", st == 200 and len(addrs) == 2, str(st))
        aid = addrs[0]["id"] if addrs else ""
        st, _, _ = cl.req("POST", "/api/v1/setup/addresses/proof", {"address_id": aid})
        proof = ""
        for _ in range(40):
            msgs = stack.mailpit(self.mp_port, "/api/v1/messages").get("messages", [])
            hit = [m for m in msgs if "confirmation" in m.get("Subject", "") and any(t.get("Address") == username + "@mandatary.test" for t in m.get("To", []))]
            if hit:
                txt = stack.mailpit(self.mp_port, "/api/v1/message/" + hit[0]["ID"]).get("Text", "")
                mm = re.search(r"code: ([A-Z2-7-]{26,40})", txt)
                proof = mm.group(1) if mm else ""
                break
            time.sleep(1)
        e.secrets.append(proof)
        check("setup-proof", "address-control proof delivered over verified-TLS SMTP", st in (200, 202, 204) and bool(proof), str(st))
        st, _, _ = cl.req("POST", "/api/v1/setup/addresses/confirm", {"address_id": aid, "proof": proof})
        check("setup-confirm", "address confirmed with the mailed proof", st in (200, 204), str(st))
        st, _, body = cl.req("POST", "/api/v1/setup/totp", {"algorithm": "SHA256"})
        seed = (body or {}).get("secret", "") if isinstance(body, dict) else ""
        e.secrets.append(seed)
        period = int(time.time() // 30)
        st2, _, _ = cl.req("POST", "/api/v1/setup/totp/confirm", {"code": stack.totp(seed)}) if seed else (0, 0, 0)
        check("setup-totp", "TOTP enrolled only after proof with a live code", st == 200 and st2 in (200, 204), "%s %s" % (st, st2))
        st, _, body = cl.req("POST", "/api/v1/setup/complete", {})
        check("setup-complete", "setup completes and issues no session", st == 200 and isinstance(body, dict) and body.get("login_required") is True, str(st))
        adm = Admin(self, username, password, seed)
        adm.last_period = period
        return adm

    def first_admin(self, username, check):
        out, code = stack.reveal_token(self.e.a.host_binary, self.base + "/data", self.base + "/keys/master.key")
        m = re.search(r"(?:[A-Z2-7]{4}-){12}[A-Z2-7]{4}", out)
        token = m.group(0) if m else ""
        self.e.secrets.append(token)
        check("setup-reveal", "the host helper reveals the setup token on a real controlling terminal", code == 0 and bool(token), "exit %s" % code)
        self.admin = self.complete_setup(token, username, check)
        return self.admin

    def restore_admin(self, username, check):
        """Host-authorized restore-administrator recovery after a restore quarantine (RESTORE-08)."""
        out, code = self.helper("recovery", "restore-admin", "--acknowledge-restore-recovery")
        check("recovery-issue", "recovery restore-admin accepted on the host", code == 0, "exit %s: %s" % (code, re.sub(r"(?:[A-Z2-7]{4}-){12}[A-Z2-7]{4}", "[TOKEN]", out)[-200:]))
        out, code = self.helper("recovery", "reveal", "--restore-admin")
        m = re.search(r"(?:[A-Z2-7]{4}-){12}[A-Z2-7]{4}", out)
        token = m.group(0) if m else ""
        self.e.secrets.append(token)
        check("recovery-reveal", "the recovery token is revealed once on a real terminal", code == 0 and bool(token), "exit %s" % code)
        self.admin = self.complete_setup(token, username, check)
        return self.admin

    # ---- store (read-only, only while the service is stopped so the WAL is checkpointed) ----------------------
    def db(self):
        return sqlite3.connect("file:%s?mode=ro" % (self.base + "/data/mandatary.db"), uri=True)

    def usage_rows(self, table="usage_stats_daily"):
        con = self.db()
        try:
            return [tuple(r) for r in con.execute(
                "SELECT a.name, u.username, s.container_name, d.operation, sum(d.allowed_count), sum(d.denied_count), sum(d.error_count) FROM %s d "
                "LEFT JOIN agents a ON a.id = d.agent_id LEFT JOIN users u ON u.id = d.user_id LEFT JOIN container_selectors s ON s.id = d.selector_id "
                "GROUP BY a.name, u.username, s.container_name, d.operation" % table)]
        finally:
            con.close()

    def recent_outcomes(self):
        con = self.db()
        try:
            return {o: n for o, n in con.execute("SELECT outcome, count(*) FROM usage_recent_events GROUP BY outcome")}
        finally:
            con.close()

    def schema_version(self):
        con = self.db()
        try:
            return con.execute("SELECT max(version_id) FROM goose_db_version WHERE is_applied = 1").fetchone()[0]
        finally:
            con.close()
