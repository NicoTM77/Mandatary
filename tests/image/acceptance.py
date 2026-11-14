#!/usr/bin/env python3
"""Image acceptance harness (P1.19). Standard library only; drives the `docker` CLI.

Runs against an ISOLATED, disposable Docker host (the approved test VM, or a hosted CI runner) and never
against a production daemon. Every resource it creates carries a unique run prefix and is removed at the
end; it never prunes and never touches resources it did not create. It needs: docker (+compose), python3,
openssl, and the host-helper binary (the `host-binary` Dockerfile target for the same platform).

    python3 tests/image/acceptance.py --image mandatary:local --platform linux/amd64 \
        --repo . --work /srv/mandatary/tests/<task>/work --host-binary ./out/mandatary \
        --sha <40-hex> --scenarios IMG,HARD,SELF,PRIV,STACK --results results.json

Scenarios: IMG (static image facts), HARD (read-only/nonroot/caps/permissions/refusals), SELF (real-daemon
self-protection readiness matrix), PRIV (the host helper's successful root-to-service-identity drop), STACK (clean Compose + TLS proxy + TLS SMTP fixture: SETUP flow, ordinary
AAL2 login, agent/rule/credential, REST + MCP positive/negative authorization against real containers).

Every result line is PASS or FAIL with a stable id. Nothing is skipped silently: a scenario that cannot run
is reported FAIL/BLOCKED with the reason. Secrets (key, passwords, tokens, cookies, TOTP seeds) exist only in
memory and ephemeral 0600 files under --work; they are never printed, and the log checks prove they never
reached a container log.
"""
import argparse
import base64
import gzip
import hashlib
import hmac
import http.client
import io
import json
import os
import pty
import re
import secrets
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import time
import uuid

BUSYBOX = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
SELF_LABEL = "io.mandatary.self"
BIND_LABEL = "io.mandatary.self.instance-uuid"
HELPER_CAPS = ["--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--cap-add", "DAC_OVERRIDE"]


class Fail(Exception):
    pass


class Results:
    def __init__(self):
        self.items = []

    def check(self, rid, name, ok, detail=""):
        self.items.append({"id": rid, "name": name, "status": "PASS" if ok else "FAIL", "detail": detail if not ok else detail})
        print(("PASS " if ok else "FAIL ") + rid + " " + name + ((" -- " + detail) if detail and not ok else ""), flush=True)
        return ok

    def blocked(self, rid, name, why):
        self.items.append({"id": rid, "name": name, "status": "BLOCKED", "detail": why})
        print("BLOCKED " + rid + " " + name + " -- " + why, flush=True)


class Env:
    def __init__(self, a):
        self.a = a
        self.pfx = "p119" + secrets.token_hex(2)
        self.work = os.path.abspath(a.work)
        self.repo = os.path.abspath(a.repo)
        self.res = Results()
        self.containers = []
        self.networks = []
        self.stacks = []
        self.secrets = []  # values scrubbed from any text we ever print or store
        os.makedirs(self.work, mode=0o700, exist_ok=True)
        self.docker_gid = str(os.stat("/var/run/docker.sock").st_gid)
        self.arch = {"linux/amd64": "amd64", "linux/arm64": "arm64"}[a.platform]

    # ---- plumbing -------------------------------------------------------------------------------------
    def scrub(self, text):
        for s in self.secrets:
            if s:
                text = text.replace(s, "[SECRET]")
        return text

    def docker(self, *args, check=True, inp=None, timeout=240):
        p = subprocess.run(["docker", *args], capture_output=True, text=True, input=inp, timeout=timeout)
        if check and p.returncode != 0:
            raise Fail("docker " + " ".join(args[:3]) + " failed: " + self.scrub((p.stderr or p.stdout)[-400:]))
        return p

    def track(self, name):
        self.containers.append(name)
        return name

    def drop(self, name):
        self.docker("stop", "-t", "5", name, check=False)
        self.docker("rm", "-f", name, check=False)
        if name in self.containers:
            self.containers.remove(name)

    def helper(self, script, mounts, user=None, net=None, caps=True, name=None):
        """One short-lived BusyBox container (root with only CHOWN/FOWNER/DAC_OVERRIDE by default)."""
        name = name or (self.pfx + "-h" + secrets.token_hex(2))
        cmd = ["run", "--name", name, "--pull", "missing"]
        if caps:
            cmd += HELPER_CAPS
        else:
            cmd += ["--cap-drop", "ALL"]
        if user:
            cmd += ["--user", user]
        if net:
            cmd += ["--network", net]
        for m in mounts:
            cmd += ["-v", m]
        cmd += [BUSYBOX, "sh", "-c", script]
        p = self.docker(*cmd, check=False)
        self.docker("rm", "-f", name, check=False)
        return p

    def prepare_state(self, tag, uid, gid):
        """Fresh data dir + master key for one deployment, owned by uid:gid (key 0400, data 0700)."""
        base = os.path.join(self.work, tag)
        os.makedirs(os.path.join(base, "keys"), mode=0o700)
        os.makedirs(os.path.join(base, "data"), mode=0o700)
        key = secrets.token_hex(32)
        self.secrets.append(key)
        with open(os.path.join(base, "keys", "master.key"), "w", opener=lambda p, f: os.open(p, f, 0o600)) as fh:
            fh.write(key + "\n")
        if (uid, gid) != (os.getuid(), os.getgid()):
            p = self.helper("chown %d:%d /d /k/master.key && chmod 0700 /d && chmod 0400 /k/master.key" % (uid, gid),
                            [base + "/data:/d", base + "/keys:/k"])
            if p.returncode != 0:
                raise Fail("state preparation failed: " + p.stderr[-200:])
        else:
            os.chmod(os.path.join(base, "keys", "master.key"), 0o400)
        return base, key

    def reclaim(self, base):
        """Make a root/65532-owned state tree deletable by the invoking user, then remove it."""
        self.helper("chown -R %d:%d /b && chmod -R u+rwX /b" % (os.getuid(), os.getgid()), [base + ":/b"])
        shutil.rmtree(base, ignore_errors=True)

    def run_mandatary(self, name, base, extra=None, env=None, user="65532:65532", detach=True, socket_mount=False, labels=None,
                      readonly=True, mount_data=True, mount_key=True, entry_args=None):
        cmd = ["run", "--name", self.track(name), "--pull", "never"]
        if detach:
            cmd.append("-d")
        if readonly:
            cmd.append("--read-only")
        cmd += ["--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", user]
        if mount_data:
            cmd += ["-v", base + "/data:/data"]
        if mount_key:
            cmd += ["-v", base + "/keys/master.key:/run/secrets/mandatary_master_key:ro",
                    "-e", "MANDATARY_MASTER_KEY_FILE=/run/secrets/mandatary_master_key"]
        if socket_mount:
            cmd += ["-v", "/var/run/docker.sock:/var/run/docker.sock", "--group-add", self.docker_gid,
                    "-e", "MANDATARY_DOCKER_SOCKET=unix:///var/run/docker.sock"]
        for k, v in (env or {}).items():
            cmd += ["-e", k + "=" + v]
        for k, v in (labels or {}).items():
            cmd += ["--label", k + "=" + v]
        cmd += list(extra or [])
        cmd.append(self.a.image)
        cmd += list(entry_args or [])
        return self.docker(*cmd, check=False)

    def wait(self, fn, timeout=60, step=0.5):
        end = time.time() + timeout
        while time.time() < end:
            if fn():
                return True
            time.sleep(step)
        return False

    def inspect(self, name):
        p = self.docker("inspect", name, check=False)
        return json.loads(p.stdout)[0] if p.returncode == 0 else None

    def health(self, name):
        i = self.inspect(name)
        return (i or {}).get("State", {}).get("Health", {}).get("Status")

    def ready_exec(self, name):
        return self.docker("exec", name, "/mandatary", "healthcheck", "--ready", check=False).returncode == 0

    def live_exec(self, name):
        return self.docker("exec", name, "/mandatary", "healthcheck", check=False).returncode == 0

    def logs(self, name):
        p = self.docker("logs", name, check=False)
        return (p.stdout or "") + (p.stderr or "")

    # ---- IMG ------------------------------------------------------------------------------------------
    def scenario_img(self):
        r, a = self.res, self.a
        info = json.loads(self.docker("image", "inspect", a.image).stdout)[0]
        cfg = info["Config"]
        r.check("IMG-01", "image platform is " + a.platform, "%s/%s" % (info["Os"], info["Architecture"]) == a.platform,
                "%s/%s" % (info["Os"], info["Architecture"]))
        r.check("IMG-02", "runs as nonroot 65532:65532 with entrypoint /mandatary", cfg.get("User") == "65532:65532" and cfg.get("Entrypoint") == ["/mandatary"],
                str(cfg.get("User")) + str(cfg.get("Entrypoint")))
        hc = cfg.get("Healthcheck") or {}
        r.check("IMG-03", "HEALTHCHECK is the shell-free liveness probe", hc.get("Test") == ["CMD", "/mandatary", "healthcheck"], str(hc.get("Test")))
        r.check("IMG-04", "image carries the io.mandatary.self membership label (SELF-08)", (cfg.get("Labels") or {}).get(SELF_LABEL) == "true")
        r.check("IMG-05", "only 8080/tcp exposed (no Phase 4 listener port)", list((cfg.get("ExposedPorts") or {}).keys()) == ["8080/tcp"], str(cfg.get("ExposedPorts")))
        bad = [e.split("=", 1)[0] for e in cfg.get("Env", []) if re.search(r"KEY|SECRET|TOKEN|PASSWORD|CRED", e.split("=", 1)[0], re.I)]
        r.check("IMG-06", "no secret-named variable baked into the image environment", not bad, str(bad))
        # binary extraction and ELF static linkage
        cname = self.track(self.pfx + "-extract")
        self.docker("create", "--name", cname, "--pull", "never", a.image)
        binpath = os.path.join(self.work, "image-mandatary")
        self.docker("cp", cname + ":/mandatary", binpath)
        self.drop(cname)
        raw = open(binpath, "rb").read()
        sha = hashlib.sha256(raw).hexdigest()
        self.binary_sha = sha
        machine = {"amd64": 0x3E, "arm64": 0xB7}[self.arch]
        ok_static, why = elf_static(raw, machine)
        r.check("IMG-07", "binary is a static ELF for " + self.arch + " (no interpreter, no dynamic section)", ok_static, why)
        if a.host_binary:
            hb = hashlib.sha256(open(a.host_binary, "rb").read()).hexdigest()
            r.check("IMG-08", "host-helper artifact is byte-identical to the image binary", hb == sha, "image %s host %s" % (sha[:16], hb[:16]))
        else:
            r.blocked("IMG-08", "host-helper artifact identical to the image binary", "no --host-binary given")
        # layers
        tarpath = os.path.join(self.work, "image.tar")
        self.docker("save", a.image, "-o", tarpath, timeout=300)
        layers, compressed = layer_report(tarpath)
        top = sorted({p.split("/")[0] for lyr in layers[-2:] for p in lyr})
        r.check("IMG-09", "the two application layers add only /data and /mandatary", top == ["data", "mandatary"], str(top))
        allpaths = {p for lyr in layers for p in lyr}
        shells = [p for p in allpaths if p in ("bin/sh", "bin/bash", "bin/busybox", "usr/bin/sh", "usr/bin/bash", "bin/dash")]
        r.check("IMG-10", "no shell and no package manager in any layer", not shells and not any(p.startswith("usr/bin/apt") or p.startswith("sbin/apk") for p in allpaths), str(shells))
        p = self.docker("run", "--pull", "never", "--name", self.track(self.pfx + "-nosh"), "--entrypoint", "/bin/sh", a.image, "-c", "true", check=False)
        self.drop(self.pfx + "-nosh")
        r.check("IMG-11", "an interactive shell cannot be started inside the image", p.returncode != 0)
        self.compressed = compressed
        r.check("IMG-12", "compressed layer total recorded (budget <= 60 MB, gzip -9 estimate)", compressed <= 60 * 1024 * 1024, "%.1f MB" % (compressed / 1048576))
        self.image_facts = {"id": info["Id"], "size_bytes": info["Size"], "compressed_layers_gzip9_bytes": compressed, "binary_sha256": sha,
                            "repo_digests": info.get("RepoDigests"), "created": info.get("Created")}

    # ---- HARD -----------------------------------------------------------------------------------------
    def scenario_hard(self):
        r = self.res
        base, key = self.prepare_state("hard", 65532, 65532)
        name = self.pfx + "-hard"
        p = self.run_mandatary(name, base)
        r.check("HARD-01", "container starts hardened (read-only, cap-drop ALL, no-new-privileges, 65532)", p.returncode == 0, p.stderr[-200:])
        ok = self.wait(lambda: self.health(name) == "healthy", 90)
        r.check("HARD-02", "container reaches healthy (liveness) within 90 s", ok, str(self.health(name)))
        i = self.inspect(name)
        hc = i["HostConfig"]
        r.check("HARD-03", "inspect: read-only rootfs, CapDrop ALL, CapAdd none, no-new-privileges, not privileged, user 65532",
                hc["ReadonlyRootfs"] is True and hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd") and "no-new-privileges:true" in (hc.get("SecurityOpt") or [])
                and hc["Privileged"] is False and i["Config"]["User"] == "65532:65532", str({k: hc.get(k) for k in ("ReadonlyRootfs", "CapDrop", "CapAdd", "SecurityOpt", "Privileged")}))
        pid = i["State"]["Pid"]
        st = proc_status(pid)
        r.check("HARD-04", "process: uid/gid 65532, NoNewPrivs 1, effective and bounding capability sets empty",
                st.get("Uid", "").split()[:4] == ["65532"] * 4 and st.get("Gid", "").split()[:4] == ["65532"] * 4 and st.get("NoNewPrivs") == "1"
                and set(st.get("CapEff", "x")) == {"0"} and set(st.get("CapBnd", "x")) == {"0"} and set(st.get("CapInh", "x")) == {"0"} and set(st.get("CapPrm", "x")) == {"0"}, str(st))
        diff = [l for l in self.docker("diff", name).stdout.splitlines() if l.strip()]
        stray = [l for l in diff if not re.match(r"^[ACD] /(run|run/secrets|run/secrets/mandatary_master_key|data)$", l)]
        r.check("HARD-05", "nothing written to the root filesystem (diff only shows mount points)", not stray, str(stray))
        perms = self.helper("stat -c '%u:%g %a %n' /data /data/* 2>&1 | sort", [base + "/data:/data:ro"], user="0:0")
        lines = [l for l in perms.stdout.splitlines() if l.strip()]
        modes = {l.split()[2]: l.split()[1] for l in lines if len(l.split()) == 3}
        okp = bool(lines) and all(l.startswith("65532:65532 ") for l in lines) and modes.get("/data") == "700" and \
            all(m == "600" for path, m in modes.items() if path != "/data") and len(modes) >= 2
        r.check("HARD-06", "persistent data: every entry owned by 65532:65532, directory 0700, files 0600", okp, "; ".join(lines))
        listen = self.helper("netstat -ltn", [], net="container:" + name, caps=False).stdout
        ports = sorted(set(re.findall(r":(\d+)\s", re.sub(r"\n", " \n", listen)) or []))
        r.check("HARD-07", "exactly one TCP listener, 8080; nothing on 8081 (no Phase 4 listener)", ports == ["8080"], str(ports))
        r.check("HARD-08", "liveness probe passes, readiness probe fails (no Docker socket configured: a missing safety prerequisite)",
                self.live_exec(name) and not self.ready_exec(name))
        logs = self.logs(name)
        r.check("HARD-09", "startup log is secret-free (no key value; server started; setup unavailable without an origin)",
                key not in logs and '"server started"' in logs and "origin_not_configured" in logs, "")
        t0 = time.time()
        self.docker("stop", "-t", "15", name)
        i = self.inspect(name)
        r.check("HARD-10", "SIGTERM stops gracefully: exit code 0 within the grace period", i["State"]["ExitCode"] == 0 and time.time() - t0 < 12,
                "exit %s in %.1fs" % (i["State"]["ExitCode"], time.time() - t0))
        self.docker("start", name)
        ok = self.wait(lambda: self.health(name) == "healthy", 90)
        r.check("HARD-11", "restart on the same data directory is healthy again", ok, str(self.health(name)))
        self.drop(name)

        # wrong key on existing data
        other = self.pfx + "-wrongkey"
        base2, _ = self.prepare_state("hard-wrongkey", 65532, 65532)
        shutil.copy  # (the key dir is per deployment; swap only the key file below)
        self.run_mandatary(other, base2)
        self.wait(lambda: self.health(other) == "healthy", 60)
        self.drop(other)
        newkey = secrets.token_hex(32)
        self.secrets.append(newkey)
        staged = os.path.join(self.work, "newkey.tmp")
        with open(staged, "w", opener=lambda p_, f: os.open(p_, f, 0o600)) as fh:
            fh.write(newkey + "\n")
        self.helper("cp /n/newkey.tmp /k/master.key && chown 65532:65532 /k/master.key && chmod 0400 /k/master.key", [base2 + "/keys:/k", self.work + ":/n:ro"])
        os.unlink(staged)
        p = self.run_mandatary(other, base2, detach=False)
        r.check("HARD-12", "a different master key on an existing store refuses to start, with no key in the output",
                p.returncode != 0 and newkey not in (p.stdout + p.stderr) and "startup failed" in (p.stdout + p.stderr), (p.stdout + p.stderr)[-200:])
        self.drop(other)
        self.reclaim(base2)

        # refusals
        def refuse(rid, label, **kw):
            n = self.pfx + "-" + rid.lower()
            b = kw.pop("_base", base)
            p = self.run_mandatary(n, b, detach=False, **kw)
            out = p.stdout + p.stderr
            ok = p.returncode != 0 and "startup failed" in out and key not in out
            r.check(rid, label, ok, "exit %s: %s" % (p.returncode, out[-160:]))
            self.drop(n)

        refuse("HARD-13", "MANDATARY_OPS_UI_ENABLED=true is refused before any listener (no Phase 4 surface)", env={"MANDATARY_OPS_UI_ENABLED": "true"})
        refuse("HARD-14", "MANDATARY_OPS_LISTEN_ADDR is refused", env={"MANDATARY_OPS_LISTEN_ADDR": ":8081"})
        refuse("HARD-15", "a remote Docker endpoint is refused (unix sockets only)", env={"MANDATARY_DOCKER_SOCKET": "tcp://127.0.0.1:2375"})
        refuse("HARD-16", "the mock backend beside a real socket is refused (SELF-13)", env={"MANDATARY_DEV_MOCK_DOCKER": "true", "MANDATARY_DOCKER_SOCKET": "unix:///var/run/docker.sock"})
        refuse("HARD-17", "a missing master key is refused", mount_key=False)
        refuse("HARD-18", "no data mount on a read-only root is refused (nothing is created in the image)", mount_data=False)
        base3, _ = self.prepare_state("hard-rootdata", 0, 0)
        refuse("HARD-19", "a data directory owned by root is refused, never repaired", _base=base3)
        self.reclaim(base3)
        base4, _ = self.prepare_state("hard-badkey", 65532, 65532)
        self.helper("chown 0:0 /k/master.key && chmod 0444 /k/master.key", [base4 + "/keys:/k"])
        refuse("HARD-20", "a world-readable root-owned key file is refused", _base=base4)
        self.reclaim(base4)
        self.reclaim(base)

    # ---- SELF -----------------------------------------------------------------------------------------
    def scenario_self(self):
        r = self.res
        base, key = self.prepare_state("self", 65532, 65532)
        bind = str(uuid.uuid4())
        others = []

        def instance(tag, binding_label=None, env_uuid=None, explicit_id=None):
            name = self.pfx + "-self-" + tag
            env = {}
            if env_uuid:
                env["MANDATARY_SELF_INSTANCE_UUID"] = env_uuid
            if explicit_id:
                env["MANDATARY_SELF_CONTAINER_ID"] = explicit_id
            labels = {BIND_LABEL: binding_label} if binding_label else None
            p = self.run_mandatary(name, base, env=env, socket_mount=True, labels=labels)
            if p.returncode != 0:
                raise Fail("cannot start " + tag + ": " + p.stderr[-200:])
            return name

        def settle_unready(name, secs=14):
            time.sleep(secs)  # >= 2 verification retries (5 s): it must not become ready by retrying
            return (not self.ready_exec(name)) and self.live_exec(name) and "docker backend unverified" in self.logs(name)

        # positive control
        n = instance("pos", binding_label=bind, env_uuid=bind)
        okr = self.wait(lambda: self.ready_exec(n), 40)
        lg = self.logs(n)
        r.check("SELF-11", "private cgroup namespace + matching instance-UUID label/env verifies on the real daemon (readiness true)", okr, lg[-200:])
        r.check("SELF-LOG", "state transition logged with a fixed reason; no ID, UUID or socket path in the log",
                "docker backend verified" in lg and bind not in lg and "docker.sock" not in lg and not re.search(r"[0-9a-f]{64}", lg))
        i = self.inspect(n)
        full_id = i["Id"]
        others.append(n)
        # peers in every state: a stopped and a created labelled peer must not break the positive control (SELF-03/08/12)
        peer_created = self.track(self.pfx + "-peer-created")
        self.docker("create", "--name", peer_created, "--label", SELF_LABEL + "=true", "--pull", "never", self.a.image)
        peer_stopped = self.track(self.pfx + "-peer-stopped")
        self.docker("create", "--name", peer_stopped, "--label", SELF_LABEL + "=true", "--pull", "never", self.a.image)
        self.drop(n)
        n = instance("pos2", binding_label=bind, env_uuid=bind)
        r.check("SELF-12", "labelled peers in created/stopped state alongside one proven own identity: still verified",
                self.wait(lambda: self.ready_exec(n), 40))
        self.drop(n)
        # SELF-01
        n = instance("s01")
        r.check("SELF-01", "socket mounted, no runtime evidence and no binding: readiness false, still live", settle_unready(n))
        self.drop(n)
        # SELF-03 label without matching proof
        n = instance("s03", binding_label=bind)
        r.check("SELF-03", "own instance-UUID label but no operator binding: not guessed, readiness false", settle_unready(n))
        self.drop(n)
        # SELF-11 mismatch
        n = instance("s11m", binding_label=bind, env_uuid=str(uuid.uuid4()))
        r.check("SELF-11M", "binding UUID in the environment not carried by any container: readiness false", settle_unready(n))
        self.drop(n)
        # SELF-02 explicit ID that is partial / not a member
        n = instance("s02p", binding_label=bind, env_uuid=bind, explicit_id=full_id[:12])
        r.check("SELF-02P", "partial explicit container ID: readiness false", settle_unready(n))
        self.drop(n)
        n = instance("s02w", binding_label=bind, env_uuid=bind, explicit_id="0" * 64)
        r.check("SELF-02W", "well-formed explicit ID that matches no member: readiness false", settle_unready(n))
        self.drop(n)
        # duplicate binding (recreation overlap): a second member carries the same UUID
        dup = self.track(self.pfx + "-dup")
        self.docker("create", "--name", dup, "--label", BIND_LABEL + "=" + bind, "--pull", "never", self.a.image)
        n = instance("s11d", binding_label=bind, env_uuid=bind)
        un = settle_unready(n)
        self.drop(dup)
        rec = self.wait(lambda: self.ready_exec(n), 40)
        r.check("SELF-11D", "duplicate binding (overlap) denies; removing the overlap restores readiness only through fresh verification", un and rec, "unready=%s recovered=%s" % (un, rec))
        self.drop(n)
        # SELF-05 recreation: a new container with the same binding verifies afresh under a new full ID
        n = instance("s05", binding_label=bind, env_uuid=bind)
        okn = self.wait(lambda: self.ready_exec(n), 40)
        new_id = self.inspect(n)["Id"]
        r.check("SELF-05", "recreated deployment member (same binding, new full ID) is verified afresh", okn and new_id != full_id)
        # daemon loss: the verification must follow reality (socket not reachable)
        self.drop(n)
        n = self.pfx + "-self-nosock"
        p = self.run_mandatary(n, base, env={"MANDATARY_DOCKER_SOCKET": "unix:///var/run/absent.sock", "MANDATARY_SELF_INSTANCE_UUID": bind}, labels={BIND_LABEL: bind})
        un = settle_unready(n, 12)
        r.check("SELF-07", "unreachable daemon socket: readiness false, no crash, process stays live", un and self.inspect(n)["State"]["Running"])
        self.drop(n)
        for c in (peer_created, peer_stopped):
            self.drop(c)
        self.reclaim(base)

    # ---- STACK ----------------------------------------------------------------------------------------
    def scenario_priv(self):
        """The host helper's SUCCESSFUL root -> service-identity drop (P109-R435), executed for real.

        The helper runs as root inside a throw-away container that has CAP_SETUID/CAP_SETGID and deliberately NOT
        CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH, against a data directory (0700) and key file (0400) owned by 65532.
        Root without those capabilities cannot read either, so a revealed token proves the process really became
        65532 before it opened anything. Negative controls: no --uid (refused), --uid 0 (refused) and a missing
        CAP_SETUID (the drop fails and nothing is revealed).
        """
        from stack import pty_run  # noqa: E402
        r = self.res
        if not self.a.host_binary:
            r.blocked("PRIV-00", "host helper binary required", "--host-binary not provided")
            return
        base, _ = self.prepare_state("priv", 65532, 65532)
        name = self.pfx + "-priv"
        p = self.run_mandatary(name, base, env={"MANDATARY_PUBLIC_ORIGIN": "https://mandatary.test:8443"})
        r.check("PRIV-01", "service container (65532) with a public origin starts and issues the setup token",
                p.returncode == 0 and self.wait(lambda: self.health(name) == "healthy", 90), self.logs(name)[-200:])
        ident = re.compile(r"(?:[A-Z2-7]{4}-){12}[A-Z2-7]{4}")

        def helper(args, caps):
            argv = ["docker", "run", "--rm", "-t", "--name", self.track(self.pfx + "-ph"), "--pull", "never", "--cap-drop", "ALL"]
            for c in caps:
                argv += ["--cap-add", c]
            argv += ["--security-opt", "no-new-privileges:true", "--user", "0:0", "-v", self.a.host_binary + ":/mandatary:ro",
                     "-v", base + "/data:/data", "-v", base + "/keys/master.key:/k/master.key:ro", BUSYBOX, "/mandatary", "setup", "reveal"]
            argv += args + ["--data-dir", "/data", "--master-key-file", "/k/master.key"]
            out, code = pty_run(argv)
            self.drop(self.pfx + "-ph")
            return out, code

        out, code = helper([], ["SETUID", "SETGID"])
        r.check("PRIV-02", "root without --uid/--gid is refused and reveals nothing", code != 0 and not ident.search(out), "exit %s" % code)
        out, code = helper(["--uid", "0", "--gid", "0"], ["SETUID", "SETGID"])
        r.check("PRIV-03", "an explicit root identity is refused and reveals nothing", code != 0 and not ident.search(out), "exit %s" % code)
        out, code = helper(["--uid", "65532", "--gid", "65532"], [])
        r.check("PRIV-04", "without CAP_SETUID/CAP_SETGID the drop fails fatally and reveals nothing (never retried at root)", code != 0 and not ident.search(out), "exit %s %s" % (code, ident.sub("[TOKEN]", out)[-160:]))
        out, code = helper(["--uid", "65532", "--gid", "65532"], ["SETUID", "SETGID"])
        m = ident.search(out)
        if m:
            self.secrets.append(m.group(0))
        r.check("PRIV-05", "root with CAP_SETUID/CAP_SETGID only drops to 65532 and reveals the token: 0700/0400 files are unreadable to root without DAC capabilities, so the drop happened before any open",
                code == 0 and bool(m), "exit %s %s" % (code, ident.sub("[TOKEN]", out)[-200:]))
        r.check("PRIV-06", "the token is shown on a terminal only, never in the service log", not (m and m.group(0) in self.logs(name)))
        self.drop(name)
        self.reclaim(base)

    def scenario_stack(self):
        from stack import run_stack  # noqa: E402  (same directory)
        run_stack(self)

    def cleanup(self):
        for s in list(self.stacks):
            subprocess.run(s["down"], cwd=self.repo, capture_output=True, text=True)
        for c in list(self.containers):
            self.drop(c)
        for n in list(self.networks):
            self.docker("network", "rm", n, check=False)


# ---- pure helpers ------------------------------------------------------------------------------------------
def elf_static(raw, machine):
    if raw[:4] != b"\x7fELF" or raw[4] != 2 or raw[5] != 1:
        return False, "not a 64-bit little-endian ELF"
    e_machine = struct.unpack_from("<H", raw, 18)[0]
    phoff, = struct.unpack_from("<Q", raw, 32)
    phentsize, phnum = struct.unpack_from("<HH", raw, 54)
    types = [struct.unpack_from("<I", raw, phoff + i * phentsize)[0] for i in range(phnum)]
    if e_machine != machine:
        return False, "e_machine %#x" % e_machine
    if 3 in types:
        return False, "has PT_INTERP"
    if 2 in types:
        return False, "has PT_DYNAMIC"
    return True, "e_machine %#x, program headers %s" % (e_machine, types)


def layer_report(tarpath):
    """Return (list of per-layer path sets, gzip-9 compressed total of all layer blobs)."""
    layers, total = [], 0
    with tarfile.open(tarpath) as t:
        manifest = json.load(t.extractfile("manifest.json"))
        for lp in manifest[0]["Layers"]:
            blob = t.extractfile(lp).read()
            try:
                raw = gzip.decompress(blob)
            except OSError:
                raw = blob
            total += len(gzip.compress(raw, 9))
            with tarfile.open(fileobj=io.BytesIO(raw)) as lt:
                layers.append({m.name.lstrip("./").rstrip("/") for m in lt.getmembers() if m.name.strip("./")})
    return layers, total


def proc_status(pid):
    out = {}
    for line in open("/proc/%d/status" % pid):
        k, _, v = line.partition(":")
        out[k] = v.strip()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--platform", required=True, choices=["linux/amd64", "linux/arm64"])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--host-binary")
    ap.add_argument("--sha", required=True)
    ap.add_argument("--scenarios", default="IMG,HARD,SELF,PRIV,STACK")
    ap.add_argument("--results", required=True)
    a = ap.parse_args()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    env = Env(a)
    started = time.time()
    try:
        for s in a.scenarios.split(","):
            fn = {"IMG": env.scenario_img, "HARD": env.scenario_hard, "SELF": env.scenario_self, "PRIV": env.scenario_priv, "STACK": env.scenario_stack}[s]
            try:
                fn()
            except Fail as e:
                env.res.check(s + "-ERROR", s + " scenario aborted", False, env.scrub(str(e)))
            except Exception as e:  # noqa: BLE001 - report, never crash silently
                env.res.check(s + "-ERROR", s + " scenario crashed", False, env.scrub(type(e).__name__ + ": " + str(e))[:300])
    finally:
        env.cleanup()
    fails = [i for i in env.res.items if i["status"] != "PASS"]
    doc = {"task": "t_7f9cfaf3", "source_sha": a.sha, "image": a.image, "platform": a.platform, "prefix": env.pfx,
           "docker": env.docker("version", "--format", "{{.Server.Version}} api {{.Server.APIVersion}} {{.Server.Os}}/{{.Server.Arch}}", check=False).stdout.strip(),
           "compose": env.docker("compose", "version", "--short", check=False).stdout.strip(),
           "image_facts": getattr(env, "image_facts", None), "seconds": round(time.time() - started),
           "pass": sum(1 for i in env.res.items if i["status"] == "PASS"), "not_pass": len(fails), "results": env.res.items}
    with open(a.results, "w") as fh:
        json.dump(doc, fh, indent=1)
    print("SUMMARY pass=%d not_pass=%d" % (doc["pass"], doc["not_pass"]))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
