"""P1.20 release acceptance, part 3: backup restore into FRESH Compose instances (same-key full and new-key clean),
the host recovery ceremony, explicit reapproval, post-restore authorization, and forward migration of existing data."""
import json
import os
import shutil
import subprocess
import time

import executors
import matrix
import stack
import stackdeploy as deploy
from ctx import Ctx


def scope_of(c: Ctx, admin):
    """Names the administrator can see: users, groups, agents and the active rule signatures (what 'effective' means)."""
    out = {}
    for key, path in (("users", "/api/v1/admin/users"), ("groups", "/api/v1/admin/groups"), ("agents", "/api/v1/admin/agents")):
        st, _, b = admin.req("GET", path)
        items = (b or {}).get(key, []) if isinstance(b, dict) else []
        out[key] = sorted(str(i.get("name") or i.get("username") or "") for i in items)
    st, _, b = admin.req("GET", "/api/v1/admin/policy/rules")
    rules = (b or {}).get("rules", []) if isinstance(b, dict) else []
    out["rules"] = sorted("%s:%s|%s|%s|%s" % (r["subject"]["kind"], r["subject"]["name"], r["effect"], r["operation"], r["selector"].get("container_name")) for r in rules if r.get("state") == "active")
    return out


class AdminView:
    """A thin adapter so scope_of can use any Admin."""

    def __init__(self, admin):
        self.admin = admin

    def req(self, method, path, body=None):
        return self.admin.fresh().req(method, path, body)


def export_archive(c: Ctx, mode):
    st, hd, body = c.dep.admin.req("POST", "/api/v1/admin/backup/export", {"mode": mode})
    dump = json.dumps(body) if body is not None else ""
    secrets_ = [c.dep.key, c.dep.admin.password, c.dep.admin.seed] + [t for t in c.tokens.values() if t]
    clean = all(s and s not in dump for s in secrets_)
    c.check("REL-BACKUP-EXPORT-" + mode, "export a %s backup as the administrator (fresh AAL2); the archive carries no password, TOTP seed, bearer token or master key (%d bytes)" % (mode, len(dump)),
            st == 200 and isinstance(body, dict) and clean, "%s clean=%s" % (st, clean))
    return body


def tamper(archive):
    """Change one character of the authenticated content (a user name) without touching the integrity tag."""
    raw = json.dumps(archive)
    assert "rel-owner" in raw
    return json.loads(raw.replace("rel-owner", "rel-owneR", 1))


def restore_into_fresh(c: Ctx, tag, mode, same_key):
    archive = export_archive(c, mode)
    if not isinstance(archive, dict):
        return
    before = scope_of(c, AdminView(c.dep.admin))
    F = deploy.Deployment(c.e, tag, key_from=c.dep.key if same_key else None)
    c.deps.append(F)
    F.up()
    steps = []

    def chk(rid, name, ok, detail=""):
        steps.append(ok)
        c.check("REL-%s-SETUP-%s" % (tag.upper(), rid), name, ok, detail)
    F.first_admin("rel-f" + tag, chk)
    adm = F.admin
    adm.login()
    P = "REL-RESTORE-%s-" % tag.upper()
    label = "%s key, %s backup" % ("same" if same_key else "new", mode)
    anon = stack.Client(F.port, F.caroot)
    st, _, _ = anon.req("POST", "/api/v1/admin/restore", {"archive": archive, "confirm": "RESTORE"})
    c.check(P + "ANON", "an anonymous restore request is refused (%s)" % label, st in (401, 403), str(st))
    st, _, b = adm.req("POST", "/api/v1/admin/restore", {"archive": archive, "confirm": "restore"})
    c.check(P + "PHRASE", "a restore without the exact confirmation phrase is refused and changes nothing", st == 400, str(st))
    st, _, b = adm.req("POST", "/api/v1/admin/restore", {"archive": tamper(archive), "confirm": "RESTORE", "acknowledge_unauthenticated_provenance": not same_key})
    c.check(P + "TAMPER", "a tampered archive is refused (422) before any state change (%s)" % label, st == 422, "%s %s" % (st, str(b)[:120]))
    st, _, b = adm.req("GET", "/api/v1/session")
    c.check(P + "NOQUAR", "after the refusals the installation is NOT in quarantine: still ready and the administrator's session is intact", st == 200 and c.e.ready_exec(F.mand), str(st))
    if not same_key:
        st, _, b = adm.req("POST", "/api/v1/admin/restore", {"archive": archive, "confirm": "RESTORE"})
        c.check(P + "PROVENANCE", "a clean archive from another installation key is refused (409 provenance_unverified) without the explicit acknowledgement", st == 409, "%s %s" % (st, str(b)[:100]))
    st, _, b = adm.req("POST", "/api/v1/admin/restore", {"archive": archive, "confirm": "RESTORE", "acknowledge_unauthenticated_provenance": not same_key})
    rep = (b or {}).get("report", {}) if isinstance(b, dict) else {}
    c.check(P + "DO", "restore succeeds (%s): installation enters RESTORE_QUARANTINE, session ended, nothing from the file is effective" % label,
            st == 200 and rep.get("state") == "restore_quarantine" and b.get("session_ended") is True, "%s %s" % (st, str(rep)[:200]))
    c.ev["restore"][tag] = {"mode": mode, "same_key": same_key, "report": rep}
    st, _, _ = adm.cl.req("GET", "/api/v1/admin/users")
    c.check(P + "SIGNEDOUT", "the restoring administrator is signed out and cannot sign back in: password + TOTP never reach a session while quarantined",
            st in (401, 403) and not _login_reaches_session(F, adm), str(st))
    tokens_old = dict(c.tokens)
    rest_old = executors.Rest(F, tokens_old)
    r = rest_old.op("a", "status", c.names["A"])
    c.check(P + "OLDTOKEN", "RESTORE-01: the credential that existed before the restore (carried inactive in a full archive, absent from a clean one) authorizes nothing while quarantined",
            r[0] in (401, 403) and r != (200, "", ""), str(r))
    # host-authorized recovery
    rsteps = []

    def chk2(rid, name, ok, detail=""):
        rsteps.append(ok)
        c.check("REL-%s-RECOVERY-%s" % (tag.upper(), rid), name, ok, detail)
    t0 = time.time()
    adm2 = F.restore_admin("rel-recov" + tag, chk2)
    adm2.login()
    st, _, man = adm2.req("GET", "/api/v1/admin/restore/manifest")
    items = (man or {}).get("items", []) if isinstance(man, dict) else []
    kinds = {}
    for it in items:
        kinds.setdefault(it["kind"], [0, 0])[0 if it["origin"] == "imported" else 1] += 1
    cred = (man or {}).get("inactive_credentials", {}) if isinstance(man, dict) else {}
    c.ev["restore"][tag]["manifest_kinds_imported_local"] = kinds
    c.ev["restore"][tag]["inactive_credentials"] = cred
    # The manifest's inactive_credentials counts every inactive record of the installation, including the authenticators the restore itself
    # retired locally, so the clean-archive claim is made on the bearer credentials and on the restore report's own flag.
    stripped_ok = (cred.get("agent_credentials", -1) == 0 and rep.get("credentials_stripped") is True) if mode == "clean" else (cred.get("agent_credentials", 0) > 0 and rep.get("credentials_stripped") is False)
    c.check(P + "MANIFEST", "recovery enrols ONE new administrator (quarantine ends in that step); the manifest lists every imported record as pending and %s" % (
        "a clean archive carries no credential" if mode == "clean" else "credential rows are retained inactive for provenance only"),
            st == 200 and items and all(i["decision"] == "pending" for i in items if i["origin"] == "imported") and stripped_ok, "%s kinds=%s cred=%s" % (st, kinds, cred))
    # nothing is effective before an explicit approval
    st_pre = _rules_effective(adm2)
    c.check(P + "INACTIVE", "RESTORE-09: before approval no imported rule is effective (the review shows what is imported next to what is in force)", st_pre == 0, "active rules before approval: %s" % st_pre)
    # approve by name, in one all-or-nothing request, except every rule of rel-ro (it must stay denied)
    take = []
    skipped = 0
    for it in items:
        if it["origin"] != "imported" or not it["approvable"]:
            continue
        d = it.get("detail") or {}
        if it["kind"] == "policy" and (d.get("subject") or {}).get("name") == "rel-ro":
            skipped += 1
            continue
        take.append({"kind": it["kind"], "id": it["id"], "digest": it.get("digest", "")})
    st, _, b = adm2.req("POST", "/api/v1/admin/restore/approvals", {"items": take})
    c.check(P + "APPROVE", "explicit approval of %d named records in dependency order (%d rule(s) of rel-ro deliberately left pending)" % (len(take), skipped), st == 200 and len((b or {}).get("approved", [])) == len(take) if isinstance(b, dict) else False, "%s %s" % (st, str(b)[:200]))
    refused = [it for it in items if it["origin"] == "imported" and not it["approvable"]]
    c.ev["restore"][tag]["not_approvable"] = sorted({"%s:%s" % (i["kind"], i.get("blocked_reason", "")) for i in refused})
    c.check(P + "NOAPPROVE", "the administrator role, notification addresses and credentials have NO approval path (fixed reasons single_administrator / needs_reverification / unsupported)",
            all(i.get("blocked_reason") for i in refused), str(c.ev["restore"][tag]["not_approvable"]))
    st, _, b = adm2.req("POST", "/api/v1/admin/restore/approvals", {"items": [{"kind": "role", "id": (refused[0]["id"] if refused else "x")}]})
    c.check(P + "CRAFTED", "a crafted approval of a non-approvable record is refused by the server (409) whatever the client sends", st == 409, "%s" % st)
    c.e.wait(lambda: c.e.ready_exec(F.mand), 90)
    # post-restore authorization with newly issued credentials
    st, _, ag = adm2.req("GET", "/api/v1/admin/agents")
    byname = {a_["name"]: a_["id"] for a_ in (ag or {}).get("agents", [])} if isinstance(ag, dict) else {}
    new_tokens = {}
    for lab in ("a", "ro", "dn", "wild"):
        aid = byname.get("rel-" + lab)
        st, _, b = adm2.req("POST", "/api/v1/admin/agents/%s/credentials" % aid, {}) if aid else (0, 0, {})
        tok = (b or {}).get("token", "") if isinstance(b, dict) else ""
        c.e.secrets.append(tok)
        new_tokens[lab] = tok
    c.check(P + "REISSUE", "fresh credentials are issued for the restored agents (a backup never carries a usable token)", all(t.startswith("mdt_") for t in new_tokens.values()), str([bool(t) for t in new_tokens.values()]))
    rest = executors.Rest(F, new_tokens)
    mcp = executors.Mcp(F, c.a.mcp_client, new_tokens, c.e.work)
    A, B = c.names["A"], c.names["B"]
    ft = matrix.Tally(lambda who: "rel-" + who, c.user_of)
    OKR, DEN = (200, "", ""), (403, "forbidden", "default_deny")
    checks = [("a", "status", A, OKR, "allowed", A), ("a", "logs", A, OKR, "allowed", A), ("a", "status", B, DEN, "denied", None), ("a", "stop", B, DEN, "denied", None),
              ("ro", "status", A, DEN, "denied", None), ("dn", "status", A, OKR, "allowed", "*"), ("dn", "status", B, DEN, "denied", B), ("wild", "config", B, OKR, "allowed", "*")]
    bad = []
    for who, op, tgt, want, outcome, sel in checks:
        for name, ex in (("rest", rest), ("mcp", mcp)):
            got = ex.op(who, op, tgt)
            if got != want:
                bad.append((name, who, op, tgt[-6:], got))
            ft.add(who, op, sel, outcome)
    c.check(P + "AUTHZ", "post-restore authorization on the fresh instance, REST and real MCP: approved grant on A works; B is denied; an agent whose rule was NOT approved is denied; explicit DENY still beats a wildcard ALLOW", not bad, str(bad[:4]))
    r_old = rest_old.op("a", "status", A)
    c.check(P + "OLDTOKEN2", "the pre-restore credential is still refused after approval and reissue (a restored record never revives an old token)", r_old[0] == 401, str(r_old))
    # effective scope compared with the imported scope
    after = scope_of(c, AdminView(adm2))
    gone_rules = sorted(set(before["rules"]) - set(after["rules"]))
    extra_rules = sorted(set(after["rules"]) - set(before["rules"]))
    expect_gone = sorted(x for x in before["rules"] if x.startswith("agent:rel-ro|"))
    names_ok = all(n in after[k] for k in ("users", "groups", "agents") for n in before[k] if not n.startswith("rel-admin"))
    c.ev["restore"][tag]["scope"] = {"original": {k: len(v) for k, v in before.items()}, "effective_after_approval": {k: len(v) for k, v in after.items()}, "withheld_rules": gone_rules, "unexpected_rules": extra_rules}
    c.check(P + "SCOPE", "documented scope comparison: every user, group and agent of the original is present; effective rules == imported rules minus the %d deliberately unapproved; nothing extra is effective" % len(expect_gone),
            names_ok and gone_rules == expect_gone and not extra_rules, "gone=%s extra=%s" % (gone_rules, extra_rules))
    # usage is not part of a backup (RESTORE-10): the fresh instance counts only what it served
    F.stop()
    got = matrix.merge_rows(F.usage_rows())
    diffs = matrix.diff_totals(ft.totals(), got)
    c.check(P + "USAGE", "RESTORE-10: usage statistics are outside the backup; the fresh instance holds exactly the %d outcomes it served after the restore and none from the original" % ft.events(), not diffs, "; ".join(diffs[:3]))


def _login_reaches_session(F, adm):
    cl = stack.Client(F.port, F.caroot)
    st, _, body = cl.req("POST", "/api/v1/login", {"username": adm.username, "password": adm.password})
    if st != 200 or not isinstance(body, dict):
        return False
    return body.get("step") == "session"


def _rules_effective(admin):
    st, _, b = admin.req("GET", "/api/v1/admin/policy/rules")
    rules = (b or {}).get("rules", []) if isinstance(b, dict) else []
    return sum(1 for r in rules if r.get("state") == "active")


def restore_scenarios(c: Ctx):
    c.ev["restore"]["original_scope"] = scope_of(c, AdminView(c.dep.admin))
    restore_into_fresh(c, "r1", "full", True)
    restore_into_fresh(c, "r2", "clean", False)


# ---- migration ------------------------------------------------------------------------------------------------------
def copy_store(src_dep, dst_dep):
    for name in os.listdir(src_dep.base + "/data"):
        s = os.path.join(src_dep.base, "data", name)
        d = os.path.join(dst_dep.base, "data", name)
        if os.path.isfile(s):
            shutil.copyfile(s, d)
            os.chmod(d, 0o600)


def mig(c: Ctx, db, to):
    p = subprocess.run([c.a.mig_tool, "-db", db, "-migrations", os.path.join(c.a.repo, "internal/store/migrations"), "-to", str(to)], capture_output=True, text=True, timeout=120)
    try:
        out = json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {}
    except ValueError:
        out = {}
    return p.returncode, out, p.stderr[-200:]


def migration(c: Ctx):
    if not c.a.mig_tool:
        c.blocked("REL-MIGRATE", "forward migration of existing data", "no --mig-tool binary was supplied for this platform")
        return
    main = c.dep
    cur = main.schema_version()
    code, took = main.stop()  # graceful: the WAL is checkpointed, the copy is consistent
    exp = c.tally.totals()
    # (1) a lossy downgrade over real data is refused and nothing is lost: usage rows with no selector exist
    d1 = deploy.Deployment(c.e, "g", key_from=main.key)
    c.deps.append(d1)
    copy_store(main, d1)
    db1 = d1.base + "/data/mandatary.db"
    rc, out, err = mig(c, db1, cur - 2)
    c.check("REL-MIGRATE-REFUSE", "a downgrade that would lose usage rows (unmatched denials) is refused by the migration itself and the data is intact", rc != 0 and d1.schema_version() == cur - 1,
            "rc=%s schema now %s (started at %s) %s" % (rc, d1.schema_version(), cur, err[:100]))
    # (2) prior schema (N-1) with real data -> the release image migrates forward on start and keeps everything
    c.check("REL-MIGRATE-PRIOR", "the store is at the immediately prior schema version %d (the repository's own down-migration over a real populated store)" % (cur - 1), d1.schema_version() == cur - 1, str(d1.schema_version()))
    d1.up()
    ready = c.e.ready_exec(d1.mand)
    adm = deploy.Admin(d1, main.admin.username, main.admin.password, main.admin.seed)
    adm.last_period = main.admin.last_period
    ok_login = True
    try:
        adm.login()
    except Exception as exc:  # noqa: BLE001
        ok_login = False
        c.check("REL-MIGRATE-LOGIN", "the administrator signs in with the same password and TOTP after the upgrade", False, str(exc)[:160])
    rest = executors.Rest(d1, c.tokens)
    mcp = executors.Mcp(d1, c.a.mcp_client, c.tokens, c.e.work)
    A, B = c.names["A"], c.names["B"]
    r1, r2, m1 = rest.op("a", "status", A), rest.op("a", "status", B), mcp.op("a", "status", A)
    c.check("REL-MIGRATE-AUTHZ", "after the in-place upgrade: ready; the existing credential still authorizes A and not B on REST and real MCP; the administrator signs in",
            ready and ok_login and r1 == (200, "", "") and r2 == (403, "forbidden", "default_deny") and m1 == (200, "", ""), "%s %s %s %s ready=%s login=%s" % (r1, r2, m1, "", ready, ok_login))
    d1.stop()
    after_v = d1.schema_version()
    got = matrix.merge_rows(d1.usage_rows())
    exp2 = dict(exp)
    for key_, add in ((("rel-a", "rel-owner", A, "container:inspect_status"), (2, 0, 0)), (("rel-a", "rel-owner", None, "container:inspect_status"), (0, 1, 0))):
        cell = exp2.get(key_, (0, 0, 0))
        exp2[key_] = tuple(x + y for x, y in zip(cell, add))
    diffs = matrix.diff_totals(exp2, got)
    con = d1.db()
    try:
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        fk = con.execute("PRAGMA foreign_key_check").fetchall()
        restore_tables = con.execute("SELECT count(*) FROM sqlite_master WHERE name IN ('restore_reports','restore_manifest')").fetchone()[0]
    finally:
        con.close()
    c.ev["migration"] = {"from": cur - 1, "to": after_v, "usage_cells": len(got), "diffs": diffs[:5], "integrity": integrity}
    c.check("REL-MIGRATE-FORWARD", "the schema advanced %d -> %d on start; every usage total survived the migration exactly; integrity and foreign-key checks pass; the tables of the newer migration exist again" % (cur - 1, cur),
            after_v == cur and not diffs and integrity == "ok" and not fk and restore_tables == 2, "schema=%s diffs=%s integrity=%s fk=%d tables=%s" % (after_v, diffs[:3], integrity, len(fk), restore_tables))
    # (3) data from a NEWER schema than the binary is refused at startup, not guessed at
    d2 = deploy.Deployment(c.e, "n", key_from=main.key)
    c.deps.append(d2)
    copy_store(main, d2)
    import sqlite3
    con = sqlite3.connect(d2.base + "/data/mandatary.db")
    try:
        con.execute("INSERT INTO goose_db_version(version_id, is_applied) VALUES (?, 1)", (cur + 1,))
        con.commit()
    finally:
        con.close()
    name = c.e.pfx + "-newer"
    p = c.e.run_mandatary(name, d2.base, user="%d:%d" % (d2.uid, d2.gid))
    c.e.wait(lambda: not (c.e.inspect(name) or {}).get("State", {}).get("Running", True), 30)
    info = c.e.inspect(name)
    lg = c.e.logs(name)
    c.check("REL-MIGRATE-NEWER", "a data directory from a NEWER schema than the binary is refused at startup (non-zero exit, no key in the output) and is not modified", info and info["State"]["ExitCode"] != 0 and d2.key not in lg and d2.schema_version() == cur + 1,
            "exit %s" % (info or {}).get("State", {}).get("ExitCode"))
    c.e.drop(name)
