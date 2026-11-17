# CI image publication: `ghcr.io/nicotm77/mandatary:dev`

CI publishes ONE development tag, `ghcr.io/nicotm77/mandatary:dev`, after a successful push to `main`. The tag is an **OCI image index** that
holds exactly two platform manifests, `linux/amd64` and `linux/arm64`, and they are the images that the CI acceptance jobs just tested, not a
rebuild. Nothing else is published: no `latest`, no `stable`, no version tag. This is a development convenience; it is **not** a release,
not a C5 release and not a deployment, and it makes no support, NIST, FIPS or compatibility claim.

`scripts/publish_dev_image.py` implements it, `.github/workflows/ci.yml` (job `publish`) wires it, and `tests/publish/` pins it.

## When it runs, and when it never does

The `publish` job runs for **one** combination only: the `push` event on `refs/heads/main` of `NicoTM77/Mandatary`, and only when the
results of **every other job of the workflow** for that exact commit are `success`: Baseline (both Go versions), Negative control (both),
Storage (linux/arm64), Image (linux/amd64 and linux/arm64, one matrix job) and Security. A failed, cancelled, skipped or missing result keeps
the job from running; `needs` lists every job, and a test fails if a job is ever added to the workflow without being added to `needs`.

It never runs, never authenticates to a registry and never holds a package permission for: a pull request (same repository or a fork),
`pull_request_target` (the workflow has no such trigger), a push to another branch, a tag, a manual (`workflow_dispatch`) or a scheduled run.
A pull request run is never converted into a publishing run: the event is part of the job condition, and `scripts/publish_dev_image.py gate`
re-checks the event, ref, repository, absence of a pull-request ref and every needed result at the start of the job (defence in depth).

| Mechanism | Detail |
| --- | --- |
| Permissions | The workflow default stays `contents: read`. Only the `publish` job adds `packages: write` (and `contents: read`). The Image jobs, which produce the artifact, have no package permission. |
| Credential | The workflow's own `GITHUB_TOKEN`. No new PAT, no repository or organisation setting changed. It reaches `docker login --password-stdin` on stdin only, in a private temporary Docker config (mode 0700) that is logged out and removed at the end; it is never on a command line or in a log. |
| Actions | All pinned by commit (`actions/download-artifact` v4.3.0 is the one added here). The logic uses the runner's `docker` and `python3`, no third-party action. |
| Concurrency | Publication only: group `publish-dev-image`, `cancel-in-progress: false` (a running publication is never cancelled half-way, a newer waiting one replaces an older waiting one). Verification is **not** cancelled to serialize it: every push to `main` has its own CI group (per commit), pull requests keep one run per ref. |
| Budget | `timeout-minutes: 20`. |

## What is promoted, and how the tested image is bound to the published one

1. The Image job (both architectures, native runners) runs its whole acceptance and the Trivy gate against `mandatary-ci:<arch>`. **Only
   after every one of those steps succeeded, and only on a push to `main`**, `publish_dev_image.py record` runs `docker save` on that image,
   reads the **config digest from the saved archive itself** (the SHA-256 of the image config, which also carries the labels) together with
   its OS, architecture and labels, requires `org.opencontainers.image.revision` to be this commit and `org.opencontainers.image.source` to be
   `https://github.com/NicoTM77/Mandatary`, and uploads the archive and its record as the artifact `tested-image-<arch>` (retention one day).
2. The `publish` job downloads both artifacts and, **before any registry call**, re-verifies each: archive SHA-256 equals the record, the
   archive's own config digest equals the record, OS/architecture, revision and source labels. Any mismatch refuses the run with no login and
   no registry access.
3. It logs in, reads the current `dev` tag and applies the freshness rule (below), then `docker load`s each archive and pushes it under a
   per-commit **staging tag** `build-<commit>-<arch>`. It accepts the pushed object only if the registry serves bytes whose digest is the
   pushed digest and its image manifest's **config digest is the tested one**: the published image has the tested config, hence the tested
   labels, and (through the manifest) the same layers' content. (A daemon with the containerd image store pushes a one-platform index, with an
   attestation beside the image at most; the image manifest inside it is what is promoted, and any other shape is refused.)
4. Only when **both** platforms are staged and verified, one `docker buildx imagetools create` writes `dev` as an index of exactly those two
   image manifests, annotated with the revision and the source. The result is read back: an index of exactly two entries, `linux/amd64` and
   `linux/arm64`, whose digests are the staged ones, revision annotation equal to the commit. A failure at any step before the create leaves
   `dev` as it was; the two platforms are never pushed onto the same tag one after the other.

The staging tags (`build-<40 hex commit>-amd64` and `-arm64`) are an implementation detail needed to hand the pushed manifests to
`imagetools create`; they are per-commit and never moved. They are not release tags. They remain visible in the package, because deleting
a package version needs a permission this workflow does not have and must not be given.

### Freshness: a stale run never overwrites a newer `dev`

`dev` carries the revision it was built from (index annotation `org.opencontainers.image.revision`). A run publishes only if that revision is
an ancestor of (or equal to) its own commit (`git merge-base --is-ancestor`, full history is fetched). A run whose commit is older, or on a
history that cannot be ordered, does not overwrite it (older: skipped as not a failure; unorderable or no revision annotation: refused so a
human decides). A repeat run of the same commit only verifies and stops. `dev` is read again right before it is written. Publication jobs are
serialized by the concurrency group above, so two publications do not interleave.

## Verification that exists

* `tests/publish/test_publish.py` (41 tests, hermetic: a fake registry that stores manifests like the real one): the gate for every event, ref,
  repository and needed result; the saved-image facts for both archive layouts; the order of effects (nothing touches a registry before the
  archives are verified, `dev` is written once and last, after both platforms); every failure path (push, load, login, digest, config, shape,
  index create, read-back) leaves `dev` untouched; stale, repeated and concurrently moved `dev`; the token only on stdin. A mutation check
  (`tests/publish/mutate_publish.py`, a maintainer tool that is not run in CI) kills all 32 mutants of the script.
* `tests/publish/test_workflow.py` (20 tests): the `publish` job condition is **evaluated** by a small GitHub-expression evaluator for
  pull request, `pull_request_target`, manual, branch, tag, fork and lookalike-repository scenarios and for every failed, cancelled, skipped or
  missing needed result; needs, permissions, that no other job has a package permission or the token, that the tested image is kept only for
  a push to `main`, the concurrency settings, the step order and pinned actions. A mutation check
  (`tests/publish/mutate_workflow.py`) kills all 27 mutations of the workflow wiring.
* `scripts/ci-budget.test.mjs` pins that pull requests run these tests and that the pull-request report check is the compact one only.
* **Dry run against a real daemon and a real registry software** (not GHCR): on the isolated test VM (Docker 29.9.3, buildx 0.39, containerd
  image store) with a throwaway local `registry:2` on 127.0.0.1, task-scoped and removed afterwards, the script was run end to end with small
  amd64 and arm64 images built for two real commits: first publication (OCI index, exactly linux/amd64 + linux/arm64, revision and source
  annotations), repeat run (skipped), newer commit (published), and the older commit after the newer one (skipped, `dev` byte-identical). This
  run found and fixed the containerd-store push shape described above. It proves the command sequence and parsing, not GHCR. The driver is
  `tests/publish/dryrun_local_registry.sh` (a maintainer tool; it needs an isolated, disposable Docker host and a local `registry:2`, never a
  production daemon); the log of the run (SHA-256 `4c1cfa30721be3e57e45642fb22d371592013bb7c8bcf7e581105030f7fd587e`) is attached to the
  Kanban card, not committed.

## What has NOT been executed

* **No registry publication has happened** and nothing was pushed to `ghcr.io`: a pull request cannot publish, and this card does not merge.
  The first real publication happens only when the owner merges and the `main` run succeeds.
* The behaviour of **GHCR** itself (authentication with `GITHUB_TOKEN`, package creation and repository association, visibility, the
  `imagetools` calls against it, the hosted runner's Docker version and image store) is not verified by anything here. After the first `main`
  run, read the registry; a green workflow is not evidence:

  ```bash
  docker buildx imagetools inspect --raw ghcr.io/nicotm77/mandatary:dev      # index: exactly linux/amd64 and linux/arm64, revision annotation
  docker buildx imagetools inspect ghcr.io/nicotm77/mandatary:dev            # platforms, digests
  # each platform manifest: config digest must equal the `config_digest` recorded in the run's tested-image artifact (1 day) or the job summary
  ```

  and check in the repository's package list that the package `mandatary` is linked to `NicoTM77/Mandatary` (the image carries
  `org.opencontainers.image.source`; visibility and access are the owner's decision and are not changed by CI).
* A permission failure (for example, packages writes being disabled for the workflow token, or the package belonging to another owner) fails
  the job; it is a blocker for the owner to resolve in the repository settings, never a reason to use another credential.

## Honest limits

* The saved image is re-pushed, so the registry digests of its manifests are not those of the tested daemon (layers are compressed by the push);
  the binding is the config digest (labels, layer diff IDs), checked after the push.
* `docker save`/`load` and the push run on a hosted runner of one architecture for both platforms; no code of the foreign platform is executed.
* Build attestations/SBOM are not attached to the published index (the Trivy gate and SBOM are evidence artifacts of the Image job).
* Staging tags accumulate (one pair per published commit) and cannot be removed by this workflow.
