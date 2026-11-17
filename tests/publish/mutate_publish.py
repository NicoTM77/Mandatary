"""Mutation check of scripts/publish_dev_image.py against tests/publish/test_publish.py (a maintainer tool, not run in CI).
usage: python3 -I tests/publish/mutate_publish.py REPO_ROOT NEW_EMPTY_WORKDIR
Every mutant must make the test suite FAIL; a surviving mutant is printed."""
import os
import shutil
import subprocess
import sys

repo, work = sys.argv[1], sys.argv[2]
src = open(os.path.join(repo, "scripts", "publish_dev_image.py")).read()
MUTANTS = [
    ("gate accepts pull_request", 'if env.get("GITHUB_EVENT_NAME") != "push":', 'if False:'),
    ("gate accepts any ref", 'if env.get("GITHUB_REF") != "refs/heads/main":', 'if False:'),
    ("gate accepts any repository", 'if env.get("GITHUB_REPOSITORY") != REPOSITORY:', 'if False:'),
    ("gate ignores pr refs", 'if env.get("GITHUB_BASE_REF") or env.get("GITHUB_HEAD_REF"):', 'if False:'),
    ("gate ignores needs results", 'if result != "success":', 'if False:'),
    ("a required job is dropped", 'REQUIRED_JOBS = ("baseline", "negative-control", "storage-arm64", "image", "security")', 'REQUIRED_JOBS = ("baseline", "negative-control", "image", "security")'),
    ("skipped counts as success", 'if result != "success":', 'if result not in ("success", "skipped"):'),
    ("config digest not compared", 'if (doc.get("config") or {}).get("digest") != config_digest:', 'if False:'),
    ("served bytes not compared to the pushed digest", 'if got != digest:', 'if False:'),
    ("a wrapped index with several images accepted", 'if len(images) != 1:', 'if False:'),
    ("child platform unchecked", 'if (plat.get("os"), plat.get("architecture")) != ("linux", arch) or not DIGEST.match(str(e.get("digest", ""))):', 'if False:'),
    ("child bytes not compared", 'if got != digest:\n                raise Refuse("the registry served a manifest whose digest %s is not the listed %s"', 'if False:\n                raise Refuse("the registry served a manifest whose digest %s is not the listed %s"'),
    ("child must be a plain manifest", 'if doc.get("mediaType") not in MANIFEST_TYPES or "manifests" in doc:', 'if False:'),
    ("ancestor check dropped", 'if not ancestor(git, rev, sha):', 'if False:'),
    ("repeat run republishes", 'if rev == sha:', 'if False:'),
    ("dev re-read dropped", 'if again is not None and again[0] != (cur[0] if cur else None):', 'if False:'),
    ("archive sha not checked", 'if sha256_file(tar) != rec["tar_sha256"]:', 'if False:'),
    ("recorded config not compared", 'if facts["config_digest"] != rec["config_digest"]:', 'if False:'),
    ("revision label not checked", 'if facts["labels"].get(REVISION_LABEL) != sha:', 'if False:'),
    ("source label not checked", 'if facts["labels"].get(SOURCE_LABEL) != source:', 'if False:'),
    ("arch not checked", 'if facts["os"] != "linux" or facts["architecture"] != arch:', 'if False:'),
    ("index platforms not checked", 'if seen.get(("linux", a)) != staged[a]:', 'if False:'),
    ("index revision annotation not checked", 'if (doc.get("annotations") or {}).get(ANN_REVISION) != sha:', 'if False:'),
    ("index size not checked", 'if not isinstance(entries, list) or len(entries) != len(ARCHES):', 'if False:'),
    ("token on the command line", '"--password-stdin"], input=token.encode())', '"--password", token], input=token.encode())'),
    ("unknown dev revision tolerated", 'if not rev or not HEX40.match(rev):', 'if False:'),
    ("unreadable dev treated as absent", 'if "not found" in low or "manifest unknown" in low or "404" in low or "name unknown" in low:', 'if True:'),
    ("logout dropped", 'docker(["logout", "ghcr.io"])', 'pass'),
    ("login before verification", 'records = {a: load_record(tested, a, sha, source) for a in ARCHES}', 'records = {}\n    for a in ARCHES:\n        records[a] = load_record(tested, a, sha, source) if a == "amd64" else None\n    docker(["login"])'),
    ("push failure ignored", 'if p.returncode != 0:\n            raise Refuse("docker push failed for %s" % arch)', 'if False:\n            pass'),
    ("create failure ignored", 'if self.docker(args).returncode != 0:', 'if False:'),
    ("token file mode", 'os.chmod(cfg_dir, 0o700)', 'os.chmod(cfg_dir, 0o777)'),
]
survivors = []
for name, old, new in MUTANTS:
    if old not in src:
        print("PATTERN MISSING:", name)
        survivors.append(name + " (pattern missing)")
        continue
    d = os.path.join(work, "m%02d" % MUTANTS.index((name, old, new)))
    os.makedirs(os.path.join(d, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(d, "tests", "publish"), exist_ok=True)
    with open(os.path.join(d, "scripts", "publish_dev_image.py"), "w") as fh:
        fh.write(src.replace(old, new, 1))
    shutil.copy(os.path.join(repo, "tests", "publish", "test_publish.py"), os.path.join(d, "tests", "publish", "test_publish.py"))
    p = subprocess.run([sys.executable, "-I", os.path.join(d, "tests", "publish", "test_publish.py")], capture_output=True, text=True)
    killed = p.returncode != 0
    print("%-8s %s" % ("KILLED" if killed else "SURVIVED", name))
    if not killed:
        survivors.append(name)
print("survivors:", survivors)
