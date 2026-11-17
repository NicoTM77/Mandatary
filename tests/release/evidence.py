#!/usr/bin/env python3
"""Compact evidence summaries and the verified raw-evidence archive of the P1.20 release report (standard library only).

The raw output of a release run (the full harness JSON, raw browser/gate/driver logs, scan outputs, SBOMs, diagnostics) is bulky
and run-specific, so it is not part of the maintained source tree. It lives in ONE immutable, versioned archive (a tarball with a
complete member manifest, `ARCHIVE.sha256`, held in Git). What Git keeps is small and checkable:

  docs/release/evidence/catalog.json        provenance catalog: tested code, revisions, archive identity and location, digests, dispositions, limits
  docs/release/evidence/ARCHIVE.sha256      the complete manifest of the archive (sha256sum format, one line per member)
  docs/release/evidence/summaries/*.json    compact, deterministic summaries of the raw result documents (every result, the measured values)
  docs/release/evidence/SHA256SUMS          seals the three kinds of file above

Two verification levels exist and are never confused:

  COMPACT (`verify`, and `report.py --check`)   the committed files are consistent with each other: every summary names the archive member
        it was derived from and the SHA-256 of that member, and that digest equals the one in ARCHIVE.sha256. The raw archive is NOT read.
        This is what a fresh clone and pull-request CI can do without credentials.
  FULL    (`stage` + `audit`)                   the archive itself is obtained (a local file, or the draft-release asset through the caller's
        own `gh`), its tarball digest, size, member list and every member digest are verified, and every summary is regenerated from the
        raw member and compared byte for byte. Only this proves that the raw evidence exists and matches.

    evidence.py summarize --raw FILE --member NAME --artifact NAME --out FILE
    evidence.py pack      --root PREFIX=DIR [--root ...] --out TARBALL --manifest ARCHIVE.sha256
    evidence.py stage     --evidence DIR --dest NEWDIR (--tarball FILE | --from-release [--gh "gh"])
    evidence.py audit     --evidence DIR --staged DIR
    evidence.py regenerate --evidence DIR --staged DIR     (rewrite every summary from the staged raw members; then `seal`)
    evidence.py seal      --evidence DIR                   (rewrite SHA256SUMS)
    evidence.py verify    --evidence DIR
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile

SUMMARY_SCHEMA = "mandatary-p120-evidence-summary/1"
CATALOG_SCHEMA = "mandatary-p120-evidence-catalog/1"
MAX_MEMBERS = 4000
MAX_BYTES = 256 << 20  # an archive that expands past this is refused before anything is written
LIST_CAP = 12  # longer lists (per-attempt traces, RSS curves, probes) stay in the archive; the summary records their length
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MEMBER = re.compile(r"^[A-Za-z0-9._@+=-]+(/[A-Za-z0-9._@+=-]+)*$")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(doc):
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def safe_member(name):
    """A member name is a plain relative path of conservative characters: no absolute path, no '..', no empty or dot segment."""
    return bool(MEMBER.match(name)) and all(p not in ("", ".", "..") for p in name.split("/")) and len(name) <= 240


def parse_manifest(text):
    """ARCHIVE.sha256 -> ({member: sha256}, problems). Strict: 64 hex, two spaces, a safe unique name, sorted order."""
    out, problems = {}, []
    names = []
    for n, ln in enumerate(text.splitlines(), 1):
        digest, sep, name = ln.partition("  ")
        if not sep or not HEX64.match(digest) or not safe_member(name):
            problems.append("manifest line %d is malformed" % n)
            continue
        if name in out:
            problems.append("manifest lists %s twice" % name)
        out[name] = digest
        names.append(name)
    if names != sorted(names):
        problems.append("manifest is not in sorted order")
    return out, problems


def render_manifest(members):
    return "".join("%s  %s\n" % (members[n], n) for n in sorted(members))


# --------------------------------------------------------------------------------------------------------------------- summaries


def prune(v):
    """Keep every scalar and small structure; a list longer than LIST_CAP is replaced by its length (the full list is in the archive)."""
    if isinstance(v, dict):
        return {k: prune(x) for k, x in v.items()}
    if isinstance(v, list):
        return [prune(x) for x in v] if len(v) <= LIST_CAP else {"omitted_list_length": len(v)}
    return v


def summarize(raw_path, member, artifact):
    """The compact, deterministic summary of one raw `results` document: the digest of the raw file it came from, its revision, every
    result, and the measured values (the evidence block with long traces cut to their length)."""
    with open(raw_path, "rb") as fh:
        raw = fh.read()
    doc = json.loads(raw)
    results = [{"id": r["id"], "status": r["status"], "detail": r.get("detail", "")} for r in doc.get("results", [])]
    out = {
        "schema": SUMMARY_SCHEMA,
        "artifact": artifact,
        "source": {"member": member, "sha256": sha256_bytes(raw), "bytes": len(raw)},
        "revision": doc.get("source_sha"),
        "results": results,
    }
    for k in ("platform", "image", "pass", "not_pass", "seconds"):
        if k in doc:
            out[k] = doc[k]
    if "evidence" in doc:
        out["evidence"] = prune(doc["evidence"])
    return out


# ------------------------------------------------------------------------------------------------------------------------ archive


SECRET_PATTERNS = (
    ("github token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("github fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
)
SCAN_CAP = 64 << 20


def secret_findings(text):
    """Names of the secret-like patterns in `text` (a deliberately small list of well-known token and key formats; not a substitute for
    keeping secrets out of the evidence in the first place)."""
    return [name for name, rx in SECRET_PATTERNS if rx.search(text)]


def scan_file(path):
    """Findings for one file; a .gz file (such as the raw-runs tarball) is scanned decompressed, up to SCAN_CAP bytes."""
    with open(path, "rb") as fh:
        data = fh.read(SCAN_CAP + 1)
    if path.endswith(".gz"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                data = gz.read(SCAN_CAP + 1)
        except (OSError, EOFError):
            pass
    if len(data) > SCAN_CAP:
        return ["larger than the scan cap"]
    return secret_findings(data.decode("latin-1"))


def pack(roots, out_tar, out_manifest):
    """Deterministic tar.gz of the files under each PREFIX=DIR root (sorted, fixed owner and mtime) plus its member manifest. A tree with
    a symlink, an unsafe name or a secret-like pattern is refused before anything is written."""
    members = {}
    for prefix, root in roots:
        for base, dirs, files in os.walk(root):
            dirs.sort()
            for fn in sorted(files):
                path = os.path.join(base, fn)
                if os.path.islink(path):
                    raise SystemExit("refusing a symlink in the evidence tree: " + path)
                name = prefix + "/" + os.path.relpath(path, root).replace(os.sep, "/")
                if not safe_member(name):
                    raise SystemExit("unsafe member name: " + name)
                members[name] = path
    for name, path in sorted(members.items()):
        found = scan_file(path)
        if found:
            raise SystemExit("refusing to archive %s: %s" % (name, ", ".join(found)))
    digests = {n: sha256_file(p) for n, p in members.items()}
    with open(out_tar, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
                for name in sorted(members):
                    info = tarfile.TarInfo(name)
                    info.size = os.path.getsize(members[name])
                    info.mtime, info.uid, info.gid, info.uname, info.gname, info.mode = 0, 0, 0, "", "", 0o644
                    with open(members[name], "rb") as fh:
                        tf.addfile(info, fh)
    with open(out_manifest, "w") as fh:
        fh.write(render_manifest(digests))
    return digests


def extract(tarball, dest, manifest):
    """Extract a verified archive into the new, empty directory `dest`. Only regular files with safe names that the manifest lists are
    written; any other member kind, a duplicate, an unlisted or a missing member, or an oversized archive is refused. Returns problems."""
    problems = []
    os.makedirs(dest, exist_ok=True)
    if os.listdir(dest):
        return ["the staging directory is not empty: " + dest]
    seen, total = set(), 0
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            for info in tf:
                if len(seen) >= MAX_MEMBERS:
                    return ["the archive has more than %d members" % MAX_MEMBERS]
                if not info.isfile():
                    problems.append("not a regular file: %r" % info.name)
                    continue
                if not safe_member(info.name):
                    problems.append("unsafe member name: %r" % info.name)
                    continue
                if info.name in seen:
                    problems.append("duplicate member: " + info.name)
                    continue
                if info.name not in manifest:
                    problems.append("member not in the manifest: " + info.name)
                    continue
                total += info.size
                if total > MAX_BYTES:
                    return ["the archive expands past %d bytes" % MAX_BYTES]
                seen.add(info.name)
                target = os.path.join(dest, *info.name.split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tf.extractfile(info)
                if src is None:
                    problems.append("unreadable member: %r" % info.name)
                    continue
                with open(target, "wb") as out:
                    while True:
                        chunk = src.read(1 << 20)
                        if not chunk:
                            break
                        out.write(chunk)
    except (tarfile.TarError, OSError, EOFError) as exc:
        return ["the archive cannot be read: %s" % exc.__class__.__name__]
    for name in sorted(set(manifest) - seen):
        problems.append("listed in the manifest but absent from the archive: " + name)
    for name in sorted(seen):
        if sha256_file(os.path.join(dest, *name.split("/"))) != manifest[name]:
            problems.append("digest mismatch: " + name)
    return problems


def release_asset(location, name, gh, runner=subprocess.run):
    """Bytes of one asset of a (draft) release, through the caller's own `gh` (never a credential of this repository). A draft is not
    found by tag, so the releases are listed and matched on tag and draft state."""
    repo, tag = location["repo"], location["tag"]

    def api(*args):
        p = runner(gh + ["api", *args], capture_output=True, timeout=300)
        if p.returncode != 0:
            raise OSError("gh api failed (exit %d)" % p.returncode)
        return p.stdout

    try:
        releases = json.loads(api("repos/%s/releases?per_page=100" % repo).decode())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise OSError("the release list is unavailable: %s" % exc)
    for rel in releases if isinstance(releases, list) else []:
        if rel.get("tag_name") == tag:
            for asset in rel.get("assets", []):
                if asset.get("name") == name:
                    return api("repos/%s/releases/assets/%d" % (repo, asset["id"]), "-H", "Accept: application/octet-stream")
    raise OSError("release %s / asset %s not found in %s" % (tag, name, repo))


def load_catalog(evdir):
    with open(os.path.join(evdir, "catalog.json")) as fh:
        return json.load(fh)


def stage(evdir, dest, tarball=None, gh=None, runner=subprocess.run):
    """Obtain the archive named by the catalog, verify it and extract it into `dest`. Returns (problems, staged_dir)."""
    cat = load_catalog(evdir)
    arch = cat.get("archive") or {}
    with open(os.path.join(evdir, "ARCHIVE.sha256")) as fh:
        manifest, problems = parse_manifest(fh.read())
    if problems:
        return problems, None
    tmp = tempfile.mkdtemp(prefix="evidence-fetch-", dir=os.path.dirname(os.path.abspath(dest)) or ".")
    try:
        if tarball is None:
            loc = arch.get("location") or {}
            if loc.get("kind") != "github-release" or not gh:
                return ["no archive file given and no fetchable location is configured"], None
            try:
                data = release_asset(loc, arch["tarball"], gh, runner)
            except (OSError, subprocess.SubprocessError) as exc:
                return ["the archive is unavailable: %s" % exc], None
            tarball = os.path.join(tmp, arch["tarball"])
            with open(tarball, "wb") as fh:
                fh.write(data)
        elif not os.path.isfile(tarball):
            return ["the archive is unavailable: no such file " + tarball], None
        if os.path.getsize(tarball) != arch.get("tarball_bytes"):
            return ["archive size mismatch: %d bytes, the catalog says %s" % (os.path.getsize(tarball), arch.get("tarball_bytes"))], None
        if sha256_file(tarball) != arch.get("tarball_sha256"):
            return ["archive digest mismatch: the tarball is not the one the catalog names"], None
        problems = extract(tarball, dest, manifest)
        return problems, (None if problems else dest)
    finally:
        for fn in os.listdir(tmp):
            os.remove(os.path.join(tmp, fn))
        os.rmdir(tmp)


# --------------------------------------------------------------------------------------------------------------------- verification


def read_summary(evdir, a):
    with open(os.path.join(evdir, a["file"])) as fh:
        return json.load(fh)


def verify_compact(evdir):
    """COMPACT verification: the catalog, the archive manifest and every summary are consistent with each other. Returns problems (none =
    consistent). It never reads the raw archive and says so in its callers' output."""
    problems = []
    try:
        cat = load_catalog(evdir)
    except (OSError, ValueError) as exc:
        return ["catalog.json is unreadable: %s" % exc.__class__.__name__]
    if cat.get("schema") != CATALOG_SCHEMA:
        problems.append("catalog schema is not " + CATALOG_SCHEMA)
    arch = cat.get("archive") or {}
    for k in ("id", "tarball", "tarball_sha256", "tarball_bytes", "manifest_sha256", "members", "location"):
        if k not in arch:
            problems.append("catalog.archive lacks " + k)
    mpath = os.path.join(evdir, "ARCHIVE.sha256")
    if not os.path.exists(mpath):
        return problems + ["ARCHIVE.sha256 is missing"]
    manifest, mp = parse_manifest(open(mpath).read())
    problems += mp
    if sha256_file(mpath) != arch.get("manifest_sha256"):
        problems.append("ARCHIVE.sha256 is not the manifest the catalog names")
    if len(manifest) != arch.get("members"):
        problems.append("ARCHIVE.sha256 lists %d members, the catalog says %s" % (len(manifest), arch.get("members")))
    if not HEX64.match(str(arch.get("tarball_sha256", ""))):
        problems.append("catalog.archive.tarball_sha256 is not a SHA-256")
    for name, a in sorted((cat.get("artifacts") or {}).items()):
        member = a.get("member")
        if member not in manifest:
            problems.append("%s: its source member is not in ARCHIVE.sha256" % name)
            continue
        path = os.path.join(evdir, a.get("file", ""))
        if not os.path.exists(path):
            problems.append("%s: summary %s is missing" % (name, a.get("file")))
            continue
        try:
            s = read_summary(evdir, a)
        except ValueError:
            problems.append("%s: summary is not JSON" % name)
            continue
        if s.get("schema") != SUMMARY_SCHEMA or s.get("artifact") != name:
            problems.append("%s: summary has the wrong schema or artifact name" % name)
        src = s.get("source") or {}
        if src.get("member") != member:
            problems.append("%s: summary was derived from %s, the catalog names %s" % (name, src.get("member"), member))
        if src.get("sha256") != manifest[member]:
            problems.append("%s: summary source digest differs from ARCHIVE.sha256 (provenance mismatch)" % name)
        want = a.get("revision")
        if not HEX40.match(str(want or "")):
            problems.append("%s: catalog records no full revision" % name)
        elif s.get("revision") not in (None, want):
            problems.append("%s: the raw run is at revision %s, the catalog says %s (revision mismatch)" % (name, s.get("revision"), want))
    for name, d in sorted((cat.get("diagnostics") or {}).items()):
        prefix = d.get("members_prefix", "")
        n = sum(1 for m in manifest if m.startswith(prefix))
        if not prefix or n != d.get("members"):
            problems.append("diagnostics %s: ARCHIVE.sha256 holds %d members under %r, the catalog says %s" % (name, n, prefix, d.get("members")))
    if arch.get("supersedes"):
        problems += verify_supersedes(evdir, arch["supersedes"], manifest)
    return problems


def verify_supersedes(evdir, sup, manifest):
    """A new evidence version never rewrites an older one: its manifest must contain EVERY member of the superseded archive with the
    identical SHA-256, which the committed manifest of the older archive makes provable without reading either archive. Returns problems."""
    problems = []
    for k in ("id", "manifest", "manifest_sha256", "tarball", "tarball_sha256", "tarball_bytes", "members"):
        if k not in sup:
            problems.append("catalog.archive.supersedes lacks " + k)
    if problems:
        return problems
    fname = sup["manifest"]
    if os.path.basename(fname) != fname or not fname.startswith("ARCHIVE") or not fname.endswith(".sha256") or fname == "ARCHIVE.sha256":
        return ["the superseded archive's manifest must be a plain ARCHIVE*.sha256 file name other than ARCHIVE.sha256: %r" % fname]
    path = os.path.join(evdir, fname)
    if not os.path.exists(path):
        return ["the superseded archive's manifest %s is missing" % fname]
    if sha256_file(path) != sup["manifest_sha256"]:
        problems.append("%s is not the manifest of the superseded archive the catalog names (digest mismatch)" % fname)
    with open(path) as fh:
        old, mp = parse_manifest(fh.read())
    problems += mp
    if len(old) != sup["members"]:
        problems.append("%s lists %d members, the catalog says %s" % (fname, len(old), sup["members"]))
    for name, digest in sorted(old.items()):
        if manifest.get(name) != digest:
            problems.append("superseded member %s is %s in the new archive (a new version must keep every older member byte for byte)" % (name, "missing" if name not in manifest else "different"))
    return problems


def seal(evdir):
    """(Re)write SHA256SUMS over every file of the evidence directory (the maintainer's step after a regeneration)."""
    names = []
    for root, _, files in os.walk(evdir):
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), evdir).replace(os.sep, "/")
            if rel != "SHA256SUMS":
                names.append(rel)
    with open(os.path.join(evdir, "SHA256SUMS"), "w") as fh:
        fh.write("".join("%s  %s\n" % (sha256_file(os.path.join(evdir, n)), n) for n in sorted(names)))


def regenerate(evdir, staged):
    """LOCAL REGENERATION: rewrite every summary the catalog names from the raw members of a staged archive (the digests come from the raw
    files, not from the old summaries). The caller then seals and regenerates the report. Returns the artifact names written."""
    cat = load_catalog(evdir)
    done = []
    for name, a in sorted((cat.get("artifacts") or {}).items()):
        raw = os.path.join(staged, *a["member"].split("/"))
        os.makedirs(os.path.dirname(os.path.join(evdir, a["file"])), exist_ok=True)
        with open(os.path.join(evdir, a["file"]), "w") as fh:
            fh.write(canonical(summarize(raw, a["member"], name)))
        done.append(name)
    return done


def audit_archive(evdir, staged):
    """FULL audit of a staged archive: every manifest member exists with its digest and nothing else is there, and every committed
    summary is regenerated from its raw member byte for byte. Returns (problems, counts)."""
    cat = load_catalog(evdir)
    manifest, problems = parse_manifest(open(os.path.join(evdir, "ARCHIVE.sha256")).read())
    on_disk = set()
    for base, _, files in os.walk(staged):
        for fn in files:
            on_disk.add(os.path.relpath(os.path.join(base, fn), staged).replace(os.sep, "/"))
    for name in sorted(set(manifest) - on_disk):
        problems.append("missing from the staged archive: " + name)
    for name in sorted(on_disk - set(manifest)):
        problems.append("not in the manifest: " + name)
    checked = 0
    for name in sorted(set(manifest) & on_disk):
        checked += 1
        if sha256_file(os.path.join(staged, *name.split("/"))) != manifest[name]:
            problems.append("digest mismatch: " + name)
    regenerated = 0
    for name, a in sorted((cat.get("artifacts") or {}).items()):
        raw = os.path.join(staged, *a["member"].split("/"))
        if not os.path.exists(raw):
            continue
        try:
            fresh = canonical(summarize(raw, a["member"], name))
        except (ValueError, KeyError):
            problems.append("%s: the raw member is not a results document" % name)
            continue
        if fresh != open(os.path.join(evdir, a["file"])).read():
            problems.append("%s: the committed summary is not what the raw member produces" % name)
        else:
            regenerated += 1
    return problems, {"members_verified": checked, "summaries_regenerated": regenerated}


# -------------------------------------------------------------------------------------------------------------------------- CLI


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("summarize")
    s.add_argument("--raw", required=True)
    s.add_argument("--member", required=True)
    s.add_argument("--artifact", required=True)
    s.add_argument("--out", required=True)
    s = sp.add_parser("pack")
    s.add_argument("--root", action="append", required=True, help="PREFIX=DIR")
    s.add_argument("--out", required=True)
    s.add_argument("--manifest", required=True)
    s = sp.add_parser("stage")
    s.add_argument("--evidence", required=True)
    s.add_argument("--dest", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--tarball")
    g.add_argument("--from-release", action="store_true")
    s.add_argument("--gh", default="gh", help="the gh command (shell-split), e.g. 'gh'")
    s = sp.add_parser("audit")
    s.add_argument("--evidence", required=True)
    s.add_argument("--staged", required=True)
    s = sp.add_parser("verify")
    s.add_argument("--evidence", required=True)
    s = sp.add_parser("regenerate")
    s.add_argument("--evidence", required=True)
    s.add_argument("--staged", required=True)
    s = sp.add_parser("seal")
    s.add_argument("--evidence", required=True)
    a = ap.parse_args(argv)

    if a.cmd == "regenerate":
        names = regenerate(a.evidence, a.staged)
        print("regenerated %d summaries from the staged raw members: %s (now run `seal`, then report.py)" % (len(names), ", ".join(names)))
        return 0
    if a.cmd == "seal":
        seal(a.evidence)
        print("sealed", a.evidence)
        return 0

    if a.cmd == "summarize":
        with open(a.out, "w") as fh:
            fh.write(canonical(summarize(a.raw, a.member, a.artifact)))
        print("wrote", a.out)
        return 0
    if a.cmd == "pack":
        roots = []
        for r in a.root:
            prefix, _, d = r.partition("=")
            if not prefix or not d or not safe_member(prefix):
                raise SystemExit("--root needs PREFIX=DIR with a safe prefix")
            roots.append((prefix, d))
        digests = pack(roots, a.out, a.manifest)
        print("packed %d members: %s sha256 %s (%d bytes)" % (len(digests), a.out, sha256_file(a.out), os.path.getsize(a.out)))
        return 0
    if a.cmd == "stage":
        problems, staged = stage(a.evidence, a.dest, tarball=a.tarball, gh=shlex.split(a.gh) if a.from_release else None)
        if problems:
            for p in problems:
                print("STAGE FAILED: " + p, file=sys.stderr)
            return 1
        print("staged and verified the archive (tarball digest, size, every member digest) in", staged)
        return 0
    if a.cmd == "audit":
        problems, counts = audit_archive(a.evidence, a.staged)
        if problems:
            for p in problems[:20]:
                print("AUDIT FAILED: " + p, file=sys.stderr)
            return 1
        print("FULL ARCHIVE AUDIT PASSED: %(members_verified)d members verified against ARCHIVE.sha256, %(summaries_regenerated)d summaries regenerated from the raw members" % counts)
        return 0
    problems = verify_compact(a.evidence)
    if problems:
        for p in problems[:20]:
            print("COMPACT VERIFICATION FAILED: " + p, file=sys.stderr)
        return 1
    print("compact verification passed (summaries are bound to ARCHIVE.sha256; the raw archive was NOT read)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
