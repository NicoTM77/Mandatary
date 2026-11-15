"""STACK scenario of tests/image/acceptance.py: the real Compose files, TLS reverse proxy, TLS SMTP fixture and
real Docker daemon, driven over HTTPS exactly as a browser/agent would reach them."""
import base64
import hmac
import http.client
import json
import os
import pty
import re
import secrets
import select
import socket
import ssl
import struct
import subprocess
import time
import urllib.request
import uuid

HOST = "mandatary.test"
OPS = ["container:logs", "container:inspect_status", "container:inspect_config", "container:start", "container:stop", "container:restart"]


def free_port():
    for _ in range(50):
        p = 20000 + secrets.randbelow(20000)
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError("no free port")


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def make_certs(d):
    """Test CA + server certificate for smtp.test. Ephemeral material under the run's work directory only."""
    def o(*a):
        p = sh(["openssl", *a], cwd=d)
        if p.returncode != 0:
            raise RuntimeError("openssl: " + p.stderr[-200:])
    o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "2", "-subj", "/CN=p119-test-ca")
    o("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "smtp.key", "-out", "smtp.csr", "-subj", "/CN=smtp.test")
    with open(os.path.join(d, "ext.cnf"), "w") as fh:
        fh.write("subjectAltName=DNS:smtp.test\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
    o("x509", "-req", "-in", "smtp.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", "smtp.crt", "-days", "2", "-extfile", "ext.cnf")
    for f in os.listdir(d):
        os.chmod(os.path.join(d, f), 0o600)  # same uid reads them inside the fixtures; nothing here is world-readable


class _Conn(http.client.HTTPSConnection):
    def __init__(self, port, ctx):
        super().__init__(HOST, port, context=ctx, timeout=30)
        self._real, self._ctx = port, ctx

    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self._real), 15)
        self.sock = self._ctx.wrap_socket(raw, server_hostname=HOST)


class Client:
    def __init__(self, port, cafile):
        self.port, self.ctx = port, ssl.create_default_context(cafile=cafile)
        self.origin = "https://%s:%d" % (HOST, port)
        self.cookies, self.csrf = {}, None

    def req(self, method, path, body=None, bearer=None, origin=True, csrf=True, raw_body=None, extra=None):
        h = {"Accept": "application/json"}
        data = None
        if body is not None or raw_body is not None:
            data = raw_body if raw_body is not None else json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if bearer:
            h["Authorization"] = "Bearer " + bearer
        if origin and method not in ("GET", "HEAD") and not bearer:
            h["Origin"] = self.origin
        if csrf and self.csrf and not bearer and method not in ("GET", "HEAD"):
            h["X-CSRF-Token"] = self.csrf
        if self.cookies and not bearer:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        h.update(extra or {})
        c = _Conn(self.port, self.ctx)
        try:
            c.request(method, path, body=data, headers=h)
            resp = c.getresponse()
            payload = resp.read()
            for sc in resp.msg.get_all("Set-Cookie") or []:
                name, _, rest = sc.partition("=")
                value = rest.split(";", 1)[0]
                if "max-age=0" in sc.lower() or value == "":
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = value
            try:
                parsed = json.loads(payload) if payload else None
            except ValueError:
                parsed = payload.decode(errors="replace")
            return resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), parsed
        finally:
            c.close()


def totp(secret, algo="SHA256", at=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((at or time.time()) // 30)
    h = hmac.new(key, struct.pack(">Q", counter), {"SHA1": "sha1", "SHA256": "sha256"}[algo]).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** 6)


def reveal_token(binary, data_dir, keyfile):
    """Run the host helper on a REAL controlling terminal (pty), as a host administrator would."""
    return pty_run([binary, "setup", "reveal", "--data-dir", data_dir, "--master-key-file", keyfile])


def pty_run(argv):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    out = b""
    while True:
        ready, _, _ = select.select([fd], [], [], 30)
        if not ready:
            break
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    _, status = os.waitpid(pid, 0)
    return out.decode(errors="replace"), os.waitstatus_to_exitcode(status)


def mailpit(port, path):
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=10) as r:
        return json.loads(r.read())


def find_ids(o, key):
    """Collect values of `key` from any nested JSON (the admin wire wrappers are not assumed)."""
    out = []
    if isinstance(o, dict):
        for k, v in o.items():
            if k == key:
                out.append(v)
            out += find_ids(v, key)
    elif isinstance(o, list):
        for v in o:
            out += find_ids(v, key)
    return out


def run_stack(e):
    r, a = e.res, e.a
    uid, gid = os.getuid(), os.getgid()
    base, key = e.prepare_state("stack", uid, gid)
    port, mp_port = free_port(), free_port()
    certs = os.path.join(e.work, "certs")
    os.makedirs(certs, mode=0o755)
    make_certs(certs)
    bind = str(uuid.uuid4())
    envfile = os.path.join(e.work, "stack.env")
    env = {
        "MANDATARY_IMAGE": a.image, "MANDATARY_INSTANCE_UUID": bind, "MANDATARY_PUBLIC_ORIGIN": "https://%s:%d" % (HOST, port),
        "MANDATARY_PUBLIC_HOST": HOST, "MANDATARY_DATA_HOST_DIR": base + "/data", "MANDATARY_MASTER_KEY_HOST_FILE": base + "/keys/master.key",
        "MANDATARY_DOCKER_SOCKET_HOST": "/var/run/docker.sock", "DOCKER_SOCKET_GID": e.docker_gid,
        "MANDATARY_SMTP_RELAY": "smtp.test:1025", "MANDATARY_SMTP_TLS": "starttls", "MANDATARY_SMTP_SENDER": "mandatary@mandatary.test",
        "MANDATARY_NOTICE_CONTACT": "ops@mandatary.test", "MANDATARY_PROXY_HTTPS_PORT": str(port), "MANDATARY_LOG_LEVEL": "debug",
        "ACC_UID": str(uid), "ACC_GID": str(gid), "ACC_CERTS_DIR": certs, "ACC_MAILPIT_PORT": str(mp_port),
    }
    with open(envfile, "w", opener=lambda p, f: os.open(p, f, 0o600)) as fh:
        fh.write("".join("%s=%s\n" % kv for kv in env.items()))
    project = e.pfx + "stk"
    base_cmd = ["docker", "compose", "-p", project, "--env-file", envfile, "-f", "docker-compose.yml", "-f", "deploy/compose.proxy.yml", "-f", "tests/image/compose.acceptance.yml"]
    e.stacks.append({"down": base_cmd + ["down", "-v", "--timeout", "10"]})

    def compose(*args, check=True):
        p = subprocess.run(base_cmd + list(args), cwd=e.repo, capture_output=True, text=True, timeout=300)
        if check and p.returncode != 0:
            raise RuntimeError("compose " + " ".join(args) + ": " + e.scrub(p.stderr[-300:]))
        return p

    # ---- the unmodified production files must render (required variables enforced) ---------------------
    p = compose("config", "-q", check=False)
    r.check("STACK-00", "docker-compose.yml + deploy/compose.proxy.yml + overlay render (Compose %s)" % sh(["docker", "compose", "version", "--short"]).stdout.strip(), p.returncode == 0, p.stderr[-200:])
    bare = subprocess.run(["docker", "compose", "-f", "docker-compose.yml", "config", "-q"], cwd=e.repo, capture_output=True, text=True, env={k: v for k, v in os.environ.items() if not k.startswith("MANDATARY_")})
    r.check("STACK-00N", "the production file refuses to render without its required variables (no silent defaults)", bare.returncode != 0, bare.stderr[-120:])
    rendered = json.loads(compose("config", "--format", "json").stdout)
    svc = rendered["services"]["mandatary"]
    r.check("STACK-01", "rendered service: read_only, cap_drop ALL, no-new-privileges, no published ports, only data+socket binds",
            svc.get("read_only") is True and svc.get("cap_drop") == ["ALL"] and "no-new-privileges:true" in svc.get("security_opt", []) and not svc.get("ports")
            and sorted(v["target"] for v in svc["volumes"]) == ["/certs", "/data", "/var/run/docker.sock"], str({k: svc.get(k) for k in ("read_only", "cap_drop", "security_opt", "ports")}))

    # ---- fixtures: ordinary containers A and B, a stopped labelled peer -----------------------------------
    t0 = time.time()
    name_a, name_b, peer = e.pfx + "-a", e.pfx + "-b", e.pfx + "-peer"
    for n in (name_a, name_b):
        e.docker("run", "-d", "--name", e.track(n), "--cap-drop", "ALL", "--read-only", BUSY(), "sh", "-c", "while :; do echo tick; sleep 1; done")
    e.docker("create", "--name", e.track(peer), "--label", "io.mandatary.self=true", "--pull", "never", a.image)

    compose("up", "-d")
    mand = compose("ps", "-q", "mandatary").stdout.strip()
    proxy = compose("ps", "-q", "proxy").stdout.strip()
    e.containers += [c for c in (mand, proxy) if c]
    ok = e.wait(lambda: e.health(mand) == "healthy", 90)
    r.check("STACK-02", "Compose stack comes up; Mandatary container healthy", ok, str(e.health(mand)))
    selfinfo = e.inspect(mand)
    self_id = selfinfo["Id"]
    r.check("STACK-03", "deployment labels present on the container (self + instance binding) and runtime user is the mapped test identity",
            selfinfo["Config"]["Labels"].get("io.mandatary.self") == "true" and selfinfo["Config"]["Labels"].get("io.mandatary.self.instance-uuid") == bind
            and selfinfo["Config"]["User"] == "%d:%d" % (uid, gid))
    ready = e.wait(lambda: e.ready_exec(mand), 60)
    r.check("STACK-04", "readiness true through the real compose deployment (self-protection verified on the real daemon)", ready, e.logs(mand)[-200:])
    caroot = os.path.join(e.work, "caddy-root.crt")
    got = e.wait(lambda: e.docker("cp", proxy + ":/data/caddy/pki/authorities/local/root.crt", caroot, check=False).returncode == 0, 60)
    r.check("STACK-05", "reverse proxy issued its local CA; client verifies the proxy certificate for the public name", got)
    cl = Client(port, caroot)
    st, hd, body = cl.req("GET", "/api/v1/readyz")
    r.check("STACK-06", "GET /api/v1/readyz through TLS proxy: 200 ready=true", st == 200 and isinstance(body, dict) and body.get("ready") is True, "%s %s" % (st, body))
    st, hd, body = cl.req("GET", "/setup")
    r.check("STACK-07", "setup page served over TLS with a strict CSP and without any third-party origin", st == 200 and "content-security-policy" in hd and "script-src 'self'" in hd["content-security-policy"] and "http" not in hd["content-security-policy"], str(hd.get("content-security-policy")))

    # ---- SETUP: secret-free URL, host-local reveal on a real tty, protected exchange ----------------------
    logs = e.logs(mand)
    urls = [json.loads(l) for l in logs.splitlines() if '"initial setup available"' in l]
    r.check("SETUP-02a", "only the secret-free setup URL is logged (exactly the configured origin + /setup)", len(urls) == 1 and urls[0].get("setup_url") == cl.origin + "/setup", str(urls)[:200])
    st, _, _ = cl.req("POST", "/api/v1/setup/exchange", {"token": "A" * 4})
    r.check("SETUP-05a", "before a host reveal the setup surface does not exist (404), whatever is posted", st == 404, str(st))
    out, code = reveal_token(a.host_binary, base + "/data", base + "/keys/master.key")
    m = re.search(r"(?:[A-Z2-7]{4}-){12}[A-Z2-7]{4}", out)
    token = m.group(0) if m else ""
    e.secrets.append(token)
    r.check("SETUP-11a", "host helper (same binary, mapped uid) reveals the token on a real controlling terminal, exit 0", code == 0 and bool(token), "exit %s: %s" % (code, re.sub(r"(?:[A-Z2-7]{4}-){12}[A-Z2-7]{4}", "[TOKEN]", out)[-300:]))
    st, _, _ = cl.req("POST", "/api/v1/setup/exchange", {"token": token}, extra={"Origin": "https://evil.test"})
    r.check("SETUP-05b", "exchange with a foreign Origin is refused", st == 403, str(st))
    st, _, _ = cl.req("GET", "/api/v1/setup/exchange")
    r.check("SETUP-05c", "GET never mutates or exposes setup (405)", st == 405, str(st))
    st, _, _ = Client(port, caroot).req("POST", "/api/v1/setup/exchange", {"token": "ABCD-" * 12 + "ABCD"})
    r.check("SETUP-05d", "a guessed token is refused (401) and consumes nothing", st == 401, str(st))
    st, hd, body = cl.req("POST", "/api/v1/setup/exchange", {"token": token})
    cl.csrf = (body or {}).get("csrf_token") if isinstance(body, dict) else None
    r.check("SETUP-05e", "the revealed token exchanges once for a setup-only session (HttpOnly Secure __Host- cookie)", st == 200 and bool(cl.csrf) and any(k.startswith("__Host-") for k in cl.cookies), str(st))
    st, _, _ = Client(port, caroot).req("POST", "/api/v1/setup/exchange", {"token": token})
    r.check("SETUP-05f", "replaying the consumed token is refused", st in (401, 404), str(st))
    st, _, _ = cl.req("GET", "/api/v1/admin/users")
    r.check("SETUP-06a", "the setup-only session cannot reach any administrative or Docker route", st in (401, 403, 404), str(st))
    password = "Tq7-" + secrets.token_urlsafe(18) + "-vP"
    e.secrets.append(password)
    st, _, body = cl.req("POST", "/api/v1/setup/account", {"username": "admin-acc", "password": password, "addresses": ["admin@mandatary.test", "second@mandatary.test"]})
    addrs = (body or {}).get("addresses", []) if isinstance(body, dict) else []
    r.check("SETUP-a", "first administrator staged with two notification addresses", st == 200 and len(addrs) == 2, str(st))
    aid = addrs[0]["id"] if addrs else ""
    st, _, _ = cl.req("POST", "/api/v1/setup/addresses/proof", {"address_id": aid})
    diag = ""
    if st not in (200, 202, 204):
        diag = e.scrub(compose("logs", "--no-color", "--tail", "8", "smtp", check=False).stdout[-700:])
    r.check("SETUP-b", "address-control proof sent over verified-TLS SMTP (STARTTLS, fixture CA)", st in (200, 202, 204), "%s %s" % (st, diag))
    code_txt = ""
    for _ in range(40):
        msgs = mailpit(mp_port, "/api/v1/messages").get("messages", [])
        hit = [m for m in msgs if "confirmation" in m.get("Subject", "") and any(t.get("Address") == "admin@mandatary.test" for t in m.get("To", []))]
        if hit:
            txt = mailpit(mp_port, "/api/v1/message/" + hit[0]["ID"]).get("Text", "")
            mm = re.search(r"code: ([A-Z2-7-]{26,40})", txt)
            code_txt = mm.group(1) if mm else ""
            break
        time.sleep(1)
    e.secrets.append(code_txt)
    r.check("SETUP-c", "the proof arrived at the TLS receiver", bool(code_txt))
    st, _, _ = cl.req("POST", "/api/v1/setup/addresses/confirm", {"address_id": aid, "proof": code_txt})
    r.check("SETUP-d", "address confirmed with the mailed proof", st == 204 or st == 200, str(st))
    st, _, body = cl.req("POST", "/api/v1/setup/totp", {"algorithm": "SHA256"})
    seed = (body or {}).get("secret", "") if isinstance(body, dict) else ""
    e.secrets.append(seed)
    st2, _, _ = cl.req("POST", "/api/v1/setup/totp/confirm", {"code": totp(seed)}) if seed else (0, 0, 0)
    proof_period = int(time.time() // 30)
    r.check("SETUP-06b", "TOTP enrolled only after proof of control with a live code", st == 200 and st2 in (200, 204), "%s %s" % (st, st2))
    st, _, body = cl.req("POST", "/api/v1/setup/complete", {})
    r.check("SETUP-e", "setup completes and issues NO session (login required)", st == 200 and isinstance(body, dict) and body.get("login_required") is True and not any(k.startswith("__Host-mandatary_session") for k in cl.cookies), str(st))
    st, _, _ = Client(port, caroot).req("POST", "/api/v1/setup/exchange", {"token": token})
    r.check("SETUP-08", "after the first administrator committed, the setup surface is closed (404)", st == 404, str(st))
    # ordinary login: password-only is not a session; password+TOTP is AAL2
    cl2 = Client(port, caroot)
    st, _, body = cl2.req("POST", "/api/v1/login", {"username": "admin-acc", "password": password})
    r.check("SETUP-06c", "password alone yields only a preauth step (factor required), never an administrative session", st == 200 and isinstance(body, dict) and body.get("step") == "factor", str(st))
    cl2.csrf = (body or {}).get("csrf_token") if isinstance(body, dict) else None
    probe = Client(port, caroot)  # a refused probe may clear the cookie it carried: use a copy, keep the real preauth session
    probe.cookies, probe.csrf = dict(cl2.cookies), cl2.csrf
    st, _, _ = probe.req("GET", "/api/v1/admin/users")
    r.check("SETUP-06d", "a password-only (preauth) session is refused by the administrative API", st in (401, 403), str(st))
    while int(time.time() // 30) <= proof_period:
        time.sleep(1)
    st, _, body = cl2.req("POST", "/api/v1/login/totp", {"code": totp(seed)})
    r.check("SETUP-10", "ordinary password + TOTP login succeeds after setup (AAL2 session)", st == 200 and isinstance(body, dict) and body.get("step") == "session", "%s %s" % (st, str(body)[:120]))
    st, _, body = cl2.req("GET", "/api/v1/session")
    cl2.csrf = (body or {}).get("csrf_token") if isinstance(body, dict) else None
    r.check("SETUP-10b", "session information carries a server-bound assurance label", st == 200 and isinstance(body, dict) and "aal2" in json.dumps(body).lower(), str(body)[:160])

    # security notice for the authenticator binding must arrive at the second (unconfirmed) -> only confirmed gets it
    got = False
    for _ in range(100):
        msgs = mailpit(mp_port, "/api/v1/messages").get("messages", [])
        hit = [m for m in msgs if any(t.get("Address") == "admin@mandatary.test" for t in m.get("To", [])) and "confirmation" not in m.get("Subject", "")]
        if hit:
            got = True
            break
        time.sleep(1)
    r.check("N1-binding-notice", "authenticator-binding security notice delivered to the confirmed address over verified TLS", got)

    # ---- administration: agents, rules, credentials --------------------------------------------------------
    st, _, body = cl2.req("GET", "/api/v1/admin/users")
    ids = find_ids(body, "id")
    admin_id = ids[0] if ids else ""
    agents = {}
    for label in ("one", "wild", "stream"):
        st, _, body = cl2.req("POST", "/api/v1/admin/agents", {"name": "acc-" + label, "owner_user_id": admin_id})
        aid_ = (find_ids(body, "id") or [""])[0]
        agents[label] = {"id": aid_}
        r.check("ADMIN-" + label, "agent %s created (owner = the administrator; owning grants nothing)" % label, st == 201 and bool(aid_), "%s %s" % (st, str(body)[:200]))
    selectors = {"one": {"container_name": name_a, "name_is_glob": False}, "wild": {"container_name": "*", "name_is_glob": True}, "stream": {"container_name": name_a, "name_is_glob": False}}
    for label in ("one", "wild", "stream"):
        st, _, body = cl2.req("POST", "/api/v1/admin/policy/rules", {"subject": {"kind": "agent", "id": agents[label]["id"]}, "effect": "ALLOW", "operations": OPS, "selector": selectors[label], "log_tail_max": 100, "stop_timeout_max": 30})
        r.check("ADMIN-rule-" + label, "explicit ALLOW (all six keys) created for agent %s" % label, st in (200, 201), "%s %s" % (st, str(body)[:200]))
        st, _, body = cl2.req("POST", "/api/v1/admin/agents/%s/credentials" % agents[label]["id"], {})
        tok = (body or {}).get("token", "") if isinstance(body, dict) else ""
        e.secrets.append(tok)
        agents[label]["token"] = tok
        agents[label]["cred"] = (find_ids((body or {}).get("credential"), "id") or [""])[0] if isinstance(body, dict) else ""
        r.check("ADMIN-cred-" + label, "credential issued once (mdt_ prefix, shown once)", st == 201 and tok.startswith("mdt_"), str(st))

    st, _, body = cl2.req("GET", "/api/v1/admin/policy/rules")
    inv = [i.get("name") for i in (body or {}).get("inventory") or []] if isinstance(body, dict) else []
    r.check("ADMIN-targets", "the policy page's container source is the shared authorizer's view (WithTargetSource): endpoint verified, A and B listed, Mandatary and its labelled peer never listed",
            st == 200 and isinstance(body, dict) and body.get("endpoint", {}).get("safety") == "verified" and name_a in inv and name_b in inv and mand_name(e, mand) not in inv and peer not in inv,
            "%s safety=%s inventory=%s" % (st, (body or {}).get("endpoint") if isinstance(body, dict) else None, inv))

    # ---- backup service wired (SetBackup): administrator export works, anonymous export does not ---------------
    st, hd, body = cl2.req("POST", "/api/v1/admin/backup/export", {"mode": "clean"})
    dump = json.dumps(body) if body is not None else ""
    secret_free = all(v and v not in dump for v in (password, seed, agents["one"]["token"], agents["wild"]["token"], key))
    r.check("BACKUP-01", "the administrator can export a clean backup (SetBackup is wired; the archive carries no password, seed, token or key)",
            st == 200 and isinstance(body, dict) and secret_free, "%s" % st)
    st, _, _ = Client(port, caroot).req("POST", "/api/v1/admin/backup/export", {"mode": "clean"})
    r.check("BACKUP-02", "an anonymous export is refused", st in (401, 403), str(st))
    st, _, _ = Client(port, caroot).req("POST", "/api/v1/admin/restore", {"confirm": "RESTORE"})
    r.check("BACKUP-03", "an anonymous restore is refused and does not enter quarantine (readiness stays true)", st in (401, 403) and e.ready_exec(mand), str(st))

    # ---- REST + MCP authorization on the real daemon -------------------------------------------------------
    api = Client(port, caroot)
    t_events = time.time()

    def rest(token, method, path, body=None):
        return api.req(method, "/api/v1/endpoints/local/containers/" + path, body=body, bearer=token)

    one, wild = agents["one"]["token"], agents["wild"]["token"]
    started_a = e.inspect(name_a)["State"]["StartedAt"]
    st, _, body = rest(one, "GET", name_a + "/status")
    r.check("AUTHZ-01", "agent ONE: status of A (granted) -> 200 with allowlisted fields", st == 200 and isinstance(body, dict), "%s %s" % (st, str(body)[:100]))
    st, _, body = rest(one, "GET", name_a + "/logs?tail=3")
    r.check("AUTHZ-02", "agent ONE: bounded logs of A -> 200", st == 200, str(st))
    st, _, body = rest(one, "POST", name_a + "/restart", {"timeout_seconds": 5})
    time.sleep(2)
    r.check("AUTHZ-03", "agent ONE: restart A really restarts it on the daemon", st in (200, 204) and e.inspect(name_a)["State"]["StartedAt"] != started_a, "%s" % st)
    for rid, label, method, path, body in (("AUTHZ-04", "B (ungranted) status", "GET", name_b + "/status", None), ("AUTHZ-05", "B (ungranted) stop", "POST", name_b + "/stop", {"timeout_seconds": 5}),
                                            ("AUTHZ-06", "Mandatary itself by name", "GET", mand_name(e, mand) + "/status", None), ("AUTHZ-07", "Mandatary itself by full ID", "GET", self_id + "/status", None)):
        st, _, b = rest(one, method, path, body)
        r.check(rid, "agent ONE: %s -> 403 default_deny" % label, st == 403 and "default_deny" in json.dumps(b), "%s %s" % (st, str(b)[:120]))
    st, _, b = rest(wild, "GET", name_b + "/status")
    r.check("AUTHZ-08", "agent WILD (wildcard ALLOW): B status -> 200 (the wildcard is effective: positive control)", st == 200, str(st))
    for rid, label, method, path, body in (
            ("SELF-04a", "self by name", "GET", mand_name(e, mand) + "/status", None), ("SELF-04b", "self by full ID", "GET", self_id + "/status", None),
            ("SELF-04c", "self config", "GET", self_id + "/config", None), ("SELF-04d", "self logs", "GET", self_id + "/logs?tail=3", None),
            ("SELF-04e", "self stop", "POST", mand_name(e, mand) + "/stop", {"timeout_seconds": 5}), ("SELF-04f", "self restart", "POST", self_id + "/restart", {"timeout_seconds": 5}),
            ("SELF-12a", "stopped labelled peer status", "GET", peer + "/status", None), ("SELF-12b", "stopped labelled peer start", "POST", peer + "/start", None),
            ("SELF-12c", "labelled peer by full ID", "GET", e.inspect(peer)["Id"] + "/status", None)):
        st, _, b = rest(wild, method, path, body)
        r.check(rid, "wildcard ALLOW + administrator-owned agent: %s -> 403 default_deny" % label, st == 403 and "default_deny" in json.dumps(b), "%s %s" % (st, str(b)[:120]))
    st, _, _ = rest(None, "GET", name_a + "/status")
    r.check("AUTHZ-09", "no credential -> 401", st == 401, str(st))
    st, _, _ = rest("mdt_" + "A" * 43, "GET", name_a + "/status")
    r.check("AUTHZ-10", "unknown well-formed credential -> 401", st == 401, str(st))
    for path in ("/containers/json", "/v1.44/containers/json", "/api/v1/endpoints/local/containers", "/api/v1/endpoints/local/containers/" + name_a + "/exec", "/var/run/docker.sock", "/api/v1/endpoints/local/containers/" + name_a + "/status/../../json"):
        st, _, _ = api.req("GET", path, bearer=wild)
        r.check("AUTHZ-11:" + path[:40], "raw Docker / unsupported path is not routed (404/405, never 200)", st in (404, 405, 400), str(st))
    # MCP (raw Streamable-HTTP JSON-RPC; the official SDK client is exercised by tests/adapters and P1.20)
    def mcp(token, method, params, rid=1):
        return api.req("POST", "/mcp", body={"jsonrpc": "2.0", "id": rid, "method": method, "params": params}, bearer=token, extra={"Accept": "application/json, text/event-stream"})
    st, _, body = mcp(wild, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "p119-acceptance", "version": "1"}})
    r.check("MCP-01", "MCP initialize over TLS with a Bearer credential", st == 200 and isinstance(body, dict) and "result" in body, "%s %s" % (st, str(body)[:120]))
    st, _, body = mcp(wild, "tools/call", {"name": "container_status", "arguments": {"endpoint": "local", "container": name_b}}, 2)
    r.check("MCP-02", "MCP container_status on B (wildcard) succeeds", st == 200 and isinstance(body, dict) and not body.get("result", {}).get("isError"), str(body)[:160])
    for rid, target in (("MCP-03a", self_id), ("MCP-03b", mand_name(e, mand)), ("MCP-03c", peer)):
        st, _, body = mcp(wild, "tools/call", {"name": "container_status", "arguments": {"endpoint": "local", "container": target}}, 3)
        res = (body or {}).get("result", {}) if isinstance(body, dict) else {}
        r.check(rid, "MCP status of a protected target (SELF-10) is an error result, never data", res.get("isError") is True and "default_deny" in json.dumps(res), str(body)[:160])
    st, _, _ = api.req("POST", "/mcp", body={"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}}, origin=False, extra={"Accept": "application/json, text/event-stream"})
    r.check("MCP-04", "MCP without a credential -> 401 before the body is parsed", st == 401, str(st))
    st, _, body = mcp(one, "tools/call", {"name": "container_stop", "arguments": {"endpoint": "local", "container": name_b, "timeout_seconds": 5}}, 4)
    res = (body or {}).get("result", {}) if isinstance(body, dict) else {}
    r.check("MCP-05", "MCP stop of ungranted B is denied", res.get("isError") is True and "default_deny" in json.dumps(res), str(body)[:160])

    # ---- a follow stream ends when its credential is revoked (the admin notifier and the pull path are both composed) ----
    stream_tok = agents["stream"]["token"]
    conn = _Conn(port, api.ctx)
    conn.request("GET", "/api/v1/endpoints/local/containers/" + name_a + "/logs?follow=true&tail=1", headers={"Authorization": "Bearer " + stream_tok, "Accept": "application/x-ndjson"})
    resp = conn.getresponse()
    lines = []
    conn.sock.settimeout(10)
    while len(lines) < 2:
        ln = resp.readline()
        if not ln:
            break
        lines.append(ln)
    r.check("STREAM-01", "a follow log stream opens through the TLS proxy and delivers frames", resp.status == 200 and len(lines) >= 2, "%s %d" % (resp.status, len(lines)))
    t_rev = time.time()
    st, _, _ = cl2.req("POST", "/api/v1/admin/agents/%s/credentials/%s/revoke" % (agents["stream"]["id"], agents["stream"]["cred"]), {})
    ended = False
    try:
        conn.sock.settimeout(8)
        while True:
            ln = resp.readline()
            if not ln:
                ended = True
                break
    except (socket.timeout, OSError):
        ended = False
    took = time.time() - t_rev
    conn.close()
    r.check("STREAM-02", "revoking the credential ends the open follow stream within 5 s (composed revocation path)", st in (200, 204) and ended and took < 5, "revoke %s ended=%s after %.1fs" % (st, ended, took))
    st, _, _ = rest(stream_tok, "GET", name_a + "/status")
    r.check("STREAM-03", "the revoked credential is refused immediately (401)", st == 401, str(st))

    # ---- real-daemon evidence: nothing touched self, the peer or B ----------------------------------------
    def events(cid):
        p = e.docker("events", "--since", str(int(t_events) - 1), "--until", str(int(time.time()) + 1), "--filter", "container=" + cid, "--format", "{{.Action}}", check=False, timeout=60)
        return [x.strip() for x in p.stdout.splitlines() if x.strip()]
    ev_self, ev_peer, ev_b = events(self_id), events(e.inspect(peer)["Id"]), events(e.inspect(name_b)["Id"])
    mutating = ("start", "stop", "die", "kill", "restart", "pause", "unpause")
    r.check("SELF-EVT", "daemon events: no start/stop/kill/die/restart on Mandatary itself, the labelled peer or the ungranted B", not [x for x in ev_self + ev_peer + ev_b if x.split(":")[0] in mutating], str((ev_self, ev_peer, ev_b)))
    r.check("SELF-STATE", "self still running, peer still never started, B still running with its original StartedAt", e.inspect(mand)["State"]["Running"] and e.inspect(peer)["State"]["Status"] == "created" and e.inspect(name_b)["State"]["Running"])
    st, _, body = Client(port, caroot).req("GET", "/api/v1/readyz")
    r.check("STACK-08", "still ready after the whole matrix", st == 200 and isinstance(body, dict) and body.get("ready") is True)

    # ---- restart: proof is re-established from scratch; credentials and setup state persist -----------------
    compose("restart", "mandatary")
    ok = e.wait(lambda: e.ready_exec(mand), 90)
    r.check("STACK-09", "after a container restart readiness returns only after a fresh verification", ok)
    st, _, _ = rest(one, "GET", name_a + "/status")
    r.check("STACK-10", "the credential persisted across restart and still authorizes A", st == 200, str(st))
    st, _, _ = Client(port, caroot).req("POST", "/api/v1/setup/exchange", {"token": token})
    r.check("STACK-11", "setup stays closed after restart (no new token minted)", st == 404, str(st))
    again = [l for l in e.logs(mand).splitlines() if '"initial setup available"' in l]
    r.check("STACK-12", "restart never issues a new setup generation", len(again) == 1, str(len(again)))
    t1 = time.time()
    compose("stop", "-t", "15", "mandatary")
    r.check("STACK-13", "compose stop ends the service gracefully (exit 0)", e.inspect(mand)["State"]["ExitCode"] == 0 and time.time() - t1 < 14, str(e.inspect(mand)["State"]["ExitCode"]))
    # The service is stopped, so the WAL is checkpointed and the store can be read read-only by the same uid.
    # Expected totals are derived from the accounting contract (docs/usage-accounting.md): only decisions about an
    # AUTHENTICATED principal count; refusals of Mandatary itself / labelled peers happen before authentication (D2)
    # and any 401 counts nothing.
    import sqlite3
    con = sqlite3.connect("file:%s?mode=ro" % (base + "/data/mandatary.db"), uri=True)
    try:
        got = {(n_, op): (int(a_), int(d_), int(x_)) for n_, op, a_, d_, x_ in con.execute(
            "SELECT a.name, d.operation, sum(d.allowed_count), sum(d.denied_count), sum(d.error_count) FROM usage_stats_daily d JOIN agents a ON a.id = d.agent_id GROUP BY a.name, d.operation")}
        recent = con.execute("SELECT count(*) FROM usage_recent_events").fetchone()[0]
        cols = sorted(c[1] for c in con.execute("PRAGMA table_info(usage_recent_events)"))
    finally:
        con.close()
    want = {("acc-one", "container:inspect_status"): (2, 1, 0), ("acc-one", "container:logs"): (1, 0, 0), ("acc-one", "container:restart"): (1, 0, 0),
            ("acc-one", "container:stop"): (0, 2, 0), ("acc-wild", "container:inspect_status"): (2, 0, 0), ("acc-stream", "container:logs"): (1, 0, 0)}
    r.check("USAGE-01", "persistent usage ledger is wired: exact allowed/denied/error totals per (agent, operation) after the real matrix and a graceful stop", got == want, "got %s want %s" % (got, want))
    r.check("USAGE-02", "recent-event ring holds exactly the 10 accounted outcomes and no payload columns", recent == 10 and "payload" not in " ".join(cols) and not any(c in cols for c in ("container_name", "token", "ip", "message")), "%s %s" % (recent, cols))
    compose("start", "mandatary")
    e.wait(lambda: e.ready_exec(mand), 90)

    # ---- no secret reached any log -------------------------------------------------------------------------
    alllogs = compose("logs", "--no-color", check=False).stdout
    leaked = [n for n, v in (("setup token", token), ("password", password), ("totp seed", seed), ("master key", key), ("agent one token", one), ("agent wild token", wild), ("address proof", code_txt)) if v and v in alllogs]
    cookies = [v for v in list(cl.cookies.values()) + list(cl2.cookies.values()) if v and len(v) > 16 and v in alllogs]
    r.check("SETUP-02", "none of the setup token, password, TOTP seed, master key, agent tokens, address proof or session cookies appear in any container log (Mandatary, proxy, SMTP)", not leaked and not cookies, str(leaked) + str(len(cookies)))
    hits = []
    for label, rx in (("bearer-value", r"Bearer\s+[A-Za-z0-9_.~+/=-]{20,}"), ("mdt_", r"mdt_"), ("cookie-name=value", r"__Host-mandatary_\w+=")):
        for m_ in re.finditer(rx, alllogs):
            hits.append(label + ": ..." + e.scrub(re.sub(r"[A-Za-z0-9_\-]{20,}", "[X]", alllogs[max(0, m_.start() - 80):m_.end() + 40])) + "...")
            break
    r.check("SETUP-02b", "no bearer value, agent token or Cookie header value appears in any log (the proxy access log drops them)", not hits, " | ".join(hits))
    for c in (name_a, name_b, peer):
        e.drop(c)
    compose("down", "-v", "--timeout", "10", check=False)
    e.stacks.clear()
    e.reclaim(base)


def BUSY():
    return "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"


def mand_name(e, cid):
    return e.inspect(cid)["Name"].lstrip("/")
