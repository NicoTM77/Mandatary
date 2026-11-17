"""Mutation check of .github/workflows/ci.yml wiring against tests/publish/test_workflow.py (a maintainer tool, not run in CI).
usage: python3 -I tests/publish/mutate_workflow.py REPO_ROOT NEW_EMPTY_WORKDIR"""
import os
import shutil
import subprocess
import sys

repo, work = sys.argv[1], sys.argv[2]
wf = open(os.path.join(repo, ".github", "workflows", "ci.yml")).read()
GUARD = "if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
MUTANTS = [
    ("security result not required", " && needs.security.result == 'success'", ""),
    ("image result not required", " && needs.image.result == 'success'", ""),
    ("arm64 storage result not required", " && needs.storage-arm64.result == 'success'", ""),
    ("baseline result not required", " && needs.baseline.result == 'success'", ""),
    ("branch not required", " && github.ref == 'refs/heads/main' && github.repository", " && github.repository"),
    ("event not required", "github.event_name == 'push' && github.ref == 'refs/heads/main' && github.repository", "github.ref == 'refs/heads/main' && github.repository"),
    ("repository not required", " && github.repository == 'NicoTM77/Mandatary'", ""),
    ("pull_request allowed", "if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && github.repository", "if: ${{ github.event_name != 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.repository"),
    ("or-branch added", "needs.security.result == 'success' }}", "needs.security.result == 'success' || github.event_name == 'workflow_dispatch' }}"),
    ("always() added", "needs.security.result == 'success' }}", "needs.security.result == 'success' && always() }}"),
    ("needs drops storage-arm64", "needs: [baseline, negative-control, storage-arm64, image, security]", "needs: [baseline, negative-control, image, security]"),
    ("needs drops image", "needs: [baseline, negative-control, storage-arm64, image, security]", "needs: [baseline, negative-control, storage-arm64, security]"),
    ("workflow-wide packages write", "permissions:\n  contents: read\nconcurrency:", "permissions:\n  contents: read\n  packages: write\nconcurrency:"),
    ("pull_request_target trigger", "on:\n  pull_request:\n", "on:\n  pull_request_target:\n  pull_request:\n"),
    ("tag trigger", "    branches: [main]\n", "    branches: [main]\n    tags: ['v*']\n"),
    ("publish cancels in progress", "      group: publish-dev-image\n      cancel-in-progress: false", "      group: publish-dev-image\n      cancel-in-progress: true"),
    ("CI group shared by main pushes", "format('main-{0}', github.sha) || github.ref", "github.ref || github.ref"),
    ("record step made main-only", "- name: Record the tested image (every run; handed to the publish job only for a push to main)\n        run: |", "- name: Record the tested image (every run; handed to the publish job only for a push to main)\n        if: ${{ github.event_name == 'push' }}\n        run: |"),
    ("record step handed a token", "- name: Record the tested image (every run; handed to the publish job only for a push to main)\n        run: |", "- name: Record the tested image (every run; handed to the publish job only for a push to main)\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n        run: |"),
    ("artifact upload unguarded", "- uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4\n        " + GUARD, "- uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4\n        if: ${{ success() }}"),
    ("fixture registry in the workflow", 'publish --tested "$RUNNER_TEMP/promote"', 'publish --tested "$RUNNER_TEMP/promote" --fixture-registry ghcr.io/x/y'),
    ("token in the image job", "      TRIVY_IMAGE: ghcr.io", "      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n      TRIVY_IMAGE: ghcr.io"),
    ("an unpinned action", "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0", "actions/download-artifact@v4"),
    ("credentials persisted in publish checkout", "persist-credentials: false\n          fetch-depth: 0", "persist-credentials: true\n          fetch-depth: 0"),
    ("publish before gate step", "python3 scripts/publish_dev_image.py gate", "echo skipped-gate"),
    ("shallow history", "          fetch-depth: 0\n", ""),
    ("security needs changed", "needs: [baseline, negative-control, image]", "needs: [baseline, negative-control]"),
    ("contents write on publish", "      contents: read\n      packages: write", "      contents: write\n      packages: write"),
]
survivors = []
for i, (name, old, new) in enumerate(MUTANTS):
    if old not in wf:
        print("PATTERN MISSING:", name)
        survivors.append(name + " (pattern missing)")
        continue
    d = os.path.join(work, "w%02d" % i)
    for sub in (".github/workflows", "scripts", "tests/publish"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    with open(os.path.join(d, ".github", "workflows", "ci.yml"), "w") as fh:
        fh.write(wf.replace(old, new, 1))
    shutil.copy(os.path.join(repo, "scripts", "publish_dev_image.py"), os.path.join(d, "scripts"))
    shutil.copy(os.path.join(repo, "tests", "publish", "test_workflow.py"), os.path.join(d, "tests", "publish"))
    p = subprocess.run([sys.executable, "-I", os.path.join(d, "tests", "publish", "test_workflow.py")], capture_output=True, text=True)
    killed = p.returncode != 0
    print("%-8s %s" % ("KILLED" if killed else "SURVIVED", name))
    if not killed:
        survivors.append(name)
print("survivors:", survivors)
