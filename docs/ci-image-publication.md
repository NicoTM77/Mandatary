# CI image publication: `ghcr.io/nicotm77/mandatary:dev`

CI publishes ONE development tag, `ghcr.io/nicotm77/mandatary:dev`, after a successful push to `main`. The tag is an **OCI image index**, annotated
with the revision and the source, that holds exactly two **OCI image manifests**, `linux/amd64` and `linux/arm64`, and they are the images that the
CI acceptance jobs just tested (same config digest, hence same labels and layer content), not a rebuild. Nothing else is published: no `latest`, no `stable`, no version tag. This is a development convenience; it is **not** a release,
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
| Concurrency | Publication only: group `publish-dev-image`, `cancel-in-progress: false` (a running publication is never cancelled half-way). GitHub keeps only **one pending** job per group and cancels the **earlier-queued** pending one **whatever its commit**: an older main commit whose CI finishes later can therefore cancel the newest commit's pending publication, and `dev` then stays one commit behind until the next push to `main` (or until that run is re-run by a maintainer). This costs freshness only; it can never put an older image on `dev`, because the freshness guard below, not the concurrency group, decides what may be written. Verification is **not** cancelled to serialize it: every push to `main` has its own CI group (per commit), pull requests keep one run per ref. |
| Budget | `timeout-minutes: 20`. |

## What is promoted, and how the tested image is bound to the published one

1. The Image job (both architectures, native runners) runs its whole acceptance and the Trivy gate against `mandatary-ci:<arch>`. **Only
   after every one of those steps succeeded**, on every run (so a pull request proves the path on both CPUs, with no credential),
   `publish_dev_image.py record` runs `docker save` on that image, reads the **config digest from the saved archive itself** (the SHA-256 of
   the image config, which also carries the labels) together with its OS, architecture and labels, and requires
   `org.opencontainers.image.revision` to be this commit and `org.opencontainers.image.source` to be `https://github.com/NicoTM77/Mandatary`.
   **Only for a push to `main`** is the archive with its record uploaded as the artifact `tested-image-<arch>` (retention one day).
2. The `publish` job downloads both artifacts and, **before any registry call**, re-verifies each: archive SHA-256 equals the record, the
   archive's own config digest equals the record, OS/architecture, revision and source labels. Any mismatch refuses the run with no login and
   no registry access.
3. It logs in, reads the current `dev` tag and applies the freshness rule (below), then `docker load`s each archive and pushes it under a
   per-commit **staging tag** `build-<commit>-<arch>`. It accepts the pushed object only if the registry serves bytes whose digest is the
   pushed digest and its image manifest's **config digest is the tested one**: the published image has the tested config, hence the tested
   labels, and (through the manifest) the same layers' content. (A daemon with the containerd image store pushes a one-platform index, with an
   attestation beside the image at most; the image manifest inside it is what is promoted, and any other shape is refused.)
   **OCI conversion (finding F-C5-1).** A hosted runner's classic image store pushes **Docker v2** manifests, and a Docker manifest list cannot carry the
   annotations: that is how the first publication went wrong. So a pushed Docker v2 image manifest is converted to OCI before anything is written to
   `dev`: `oci_manifest_bytes` builds the OCI manifest from it (media type of the manifest, of the config and of every layer; the config blob and the
   layer blobs, their digests and sizes are untouched, so **the config digest, the tested image's identity, does not change**) and refuses what it cannot
   convert without loss (another config than the tested one, an unknown or foreign layer type, `urls`, any field it does not know). `HttpRegistry` writes
   it under the staging tag `build-<commit>-<arch>-oci` with one registry API call (the docker CLI cannot put a manifest it did not build); the registry's
   token handshake is followed, the credential goes only to the token endpoint of the same host as HTTP basic authentication, no redirect is followed, and
   the registry's reported digest must be the SHA-256 of the bytes sent. The manifest is then read back through the docker CLI and must hold the tested
   config and the pushed layers. A manifest that is already OCI is used as it is. Every failure here leaves `dev` as it was.
4. Only when **both** platforms are staged and verified as OCI manifests holding the tested config, one `docker buildx imagetools create` writes `dev`
   as an index of exactly those two manifests, annotated with the revision and the source. Immediately before it, `create_index` reads both staged
   manifests again and **refuses to write** unless they are OCI image manifests with the tested config (a Docker v2 child would make the create write an
   unannotated Docker list or fail). The result is then read back, independently of the create's exit status: media type `OCI image index`, exactly two
   entries, `linux/amd64` and `linux/arm64`, whose digests are the staged ones and whose descriptors are OCI manifests, the revision annotation equal to the
   commit **and** the source annotation, and each child, read from the registry, holding the tested config of its platform.

   **Before and after a possible write.** A failure at any step **before** the create (verification of the archives, login, push, conversion, the
   pre-write check) leaves `dev` as it was; the two platforms are never pushed onto the same tag one after the other. The create **is** the write, and
   neither of its outcomes proves the state of `dev`: a create that exits 0 can have written something the read-back refuses (an index without an
   annotation), in which case the run fails and `dev` **has been changed**; a create that reports failure can have been taken by the registry before the
   client failed. So after a failed create the run reads `dev` again and says what it serves ("unchanged" or "HAS CHANGED", or that it could not be read
   and the state is not known). A generic command failure is never a guarantee that nothing was written, and an exit status alone is never taken for a
   verified publication.

The staging tags (`build-<40 hex commit>-amd64` and `-arm64`, and, when a pushed Docker v2 manifest was converted, `build-<40 hex commit>-amd64-oci`
and `-arm64-oci`, which are the manifests `dev` lists) are an implementation detail needed to hand the pushed manifests to
`imagetools create`; they are per-commit and never moved. They are not release tags. They remain visible in the package, because deleting
a package version needs a permission this workflow does not have and must not be given.

### Freshness: a stale run never overwrites a newer `dev`

`dev` carries the revision it was built from (index annotation `org.opencontainers.image.revision`). A run publishes only if that revision is
an ancestor of (or equal to) its own commit (`git merge-base --is-ancestor`, full history is fetched). The outcomes are exactly these:
`dev` revision is an ancestor of this commit: publish. `dev` is not an ancestor of this commit, which covers both an **older** commit and
a **diverged** history (a revision that is neither older nor newer): the run is **skipped** (reported as skipped, not as a failure) and
`dev` is left byte-identical; nothing asks a human to decide. The run is **refused** (no write, the job fails) only when the order cannot
be evaluated at all (`merge-base` fails for another reason, for example an unknown commit or missing history) or `dev` carries no
revision annotation or an unreadable one: an ordinary run **never** overwrites an existing tag that has no revision annotation, whatever else it
looks like. A repeat run of the same commit only verifies (media type, annotations, children, tested config) and stops. `dev` is read again right
before it is written. Publication jobs are serialized by the concurrency group above, so two publications do not interleave. This read and the write
are **not atomic**: a registry tag write cannot be made conditional on what the tag holds (the OCI distribution API has no compare-and-swap for tags),
so a writer outside this job, or a job outside the concurrency group, could still change `dev` between the read and the create. The read-back after the
write detects the resulting state; nothing here prevents it.

### One-time recovery of the unannotated `dev` tag (finding F-C5-1)

The first publication left `dev` as an unannotated Docker manifest list (digest
`sha256:0c8894070085f72c9709f191cfcc7c0998ff3950c39aa4b5887df4bff6d0486e`, two Docker v2 children, the config-verified images of revision
`666ee9ce16d80440a9969c72b653975e84ba8ced`), and the rule above makes every ordinary run refuse it. The owner approved the replacement of **that
manifest and nothing else**. `KNOWN_BAD_DEV` in `publish_dev_image.py` is the whole exception, and it is deliberately narrow:

* It is handed to `publish` by the command line for the real image only (`ghcr.io/nicotm77/mandatary`, tag `dev`); a `--fixture-registry` run, another
  repository or another tag never gets it. Without it, `publish` behaves exactly as described above.
* It applies only while `dev` serves a manifest whose SHA-256 **is** the recorded digest. Any other unannotated manifest, a different digest, a
  malformed annotation: refused, nothing written, the run is red and reports the digest it found. An annotated `dev` is judged by the ordinary rules
  (the exception changes nothing for it).
* The freshness order still applies: the run's commit must descend from the recorded revision (or the run is skipped, `dev` untouched), and an order
  that cannot be evaluated refuses.
* The exception is checked **again right before the create**, after both platforms are staged: if `dev` is no longer exactly that manifest (replaced,
  annotated, deleted), the run is refused and nothing is written. This narrows the race window; it does not close it (no compare-and-swap, above).
* The old raw index (and with it both child descriptors) is written to the job log before the replacement, and the job summary names the replaced
  digest. The raw manifests and the config blobs were read anonymously and read-only before this code was written and are kept as fixtures
  (`tests/publish/fixtures/c5-old-dev/`, whose digest chain a test checks down to the revision labels) and as evidence on the C5 card. The old
  manifest becomes untagged in the package; its children stay (they are the staging tags' manifests). GHCR may eventually remove untagged versions, so the
  fixtures, not the registry, are the durable record.
* The result is verified like any publication: the read-back requires the OCI index media type, both annotations and the tested config in each child,
  and `recovered` is reported only after it passed. A recovery whose read-back fails is red and leaves `dev` as the create wrote it; the exception is
  then spent (the digest no longer matches).
* It does not persist as a bypass: once the manifest is gone the exception can never match again. The constant is dead code after the first
  successful recovery and should be deleted in a later change.

**When it runs.** There is no separate switch: the first run of the `publish` job on `main` after the owner merges this change performs the replacement
(and publishes that commit), through the job's existing `GITHUB_TOKEN` and `packages: write` permission, no other credential, no manual registry
operation. If that run is refused, red or skipped, no recovery has happened (unless its log says otherwise) and nothing may be done to `dev` by hand: the
owner decides. Read the registry before believing a green run (below).

## Verification that exists

* `tests/publish/test_publish.py` (81 tests, hermetic: a fake registry that stores manifests like the real one, plus a loopback HTTP registry for
  the API client): the gate for every event, ref, repository and needed result; the saved-image facts for both archive layouts; the order of effects
  (nothing touches a registry before the archives are verified, `dev` is written once and last, after both platforms); every failure path BEFORE the
  create (push, load, login, digest, config, shape, conversion, the pre-write check) leaves `dev` untouched, whereas a failure of the READ-BACK after a
  create that exited 0, and a create that reports failure after the registry took the write, leave `dev` as written (asserted, see below); stale,
  repeated and concurrently moved `dev`; the token only on stdin and only to the token endpoint. A mutation check (`tests/publish/mutate_publish.py`,
  a maintainer tool that is not run in CI) kills all 65 mutants of the script.
* **F-C5-1 regressions, adapted to the corrected publication** (`IndexPublication`, `OciConversion`, `RecoveryTests`, `HttpRegistryTests` in
  `test_publish.py`; the fake registry models the platform manifests' media type, the blobs a registry holds, and the behaviour of `imagetools create`):
  * An annotated OCI index of OCI platform manifests is published and verified (positive control, with no conversion), and so is the same index built
    from **Docker v2** platform manifests, as the hosted runner pushes them, in every `imagetools create` behaviour: the children are converted, keep
    the tested config digest and the layer blobs, and the registry calls happen in the asserted order, the create last.
  * The conversion is a pure function with a golden digest over the real manifests the hosted runner pushed (15 layers each, kept as fixtures), and it
    refuses every shape it cannot convert without loss.
  * Refused **before** the write, with `dev` byte-identical: a registry that refuses the OCI manifest, reports another digest or stores other bytes; a
    conversion that changes the config; a staged child that is not OCI (the conversion removed), whatever the buildx would then do.
  * Refused **after** the write by the read-back alone: a create that exits 0 but drops the revision (or the source) annotation, and a create that
    writes an unannotated Docker manifest list (the pre-write check removed): the post-write state is asserted (dev replaced, no annotation). A create
    that reports failure after the registry took the write says `dev` HAS CHANGED; one that cannot be read back says the state is unknown.
  * An ordinary run refuses the real unannotated dev before any push, conversion or create, for the same and for a newer commit.
  * Recovery: the recorded digest chain, ordinary refusal, replacement of exactly the recorded manifest with the old index logged, a mismatched digest
    and other unannotated manifests refused, a `dev` that changes during staging not replaced, the repository and tag binding, no effect on an annotated
    `dev`, the freshness order kept, a failed read-back leaving no bypass, and the command line offering it to the real image only.
  * `HttpRegistry` over real HTTP against a loopback server: the token handshake, where the credential goes (the token endpoint only; never to another
    host, never in a URL or on the manifest request), no redirect followed, the digest the registry reports checked.
  These tests prove that the corrected code produces and verifies the intended publication against a **fake** registry and a fake classic store. They do
  not prove the behaviour of GHCR or of a hosted runner.
* `tests/publish/test_workflow.py` (20 tests): the `publish` job condition is **evaluated** by a small GitHub-expression evaluator for
  pull request, `pull_request_target`, manual, branch, tag, fork and lookalike-repository scenarios and for every failed, cancelled, skipped or
  missing needed result; needs, permissions, that no other job has a package permission or the token, that the tested image is kept only for
  a push to `main`, the concurrency settings, the step order and pinned actions. A mutation check
  (`tests/publish/mutate_workflow.py`) kills all 28 mutations of the workflow wiring.
* `scripts/ci-budget.test.mjs` pins that pull requests run these tests and that the pull-request report check is the compact one only.
* **Dry run against a real daemon and a real registry software** (not GHCR): on the isolated test VM (Docker 29.9.3, buildx 0.39, containerd
  image store) with a throwaway local `registry:2` on 127.0.0.1, task-scoped and removed afterwards, the script was run end to end with small
  amd64 and arm64 images built for two real commits: first publication (OCI index, exactly linux/amd64 + linux/arm64, revision and source
  annotations), repeat run (skipped), newer commit (published), and the older commit after the newer one (skipped, `dev` byte-identical). This
  run found and fixed the containerd-store push shape described above. It proves the command sequence and parsing, not GHCR. The driver is
  `tests/publish/dryrun_local_registry.sh` (a maintainer tool; it needs an isolated, disposable Docker host and a local `registry:2`, never a
  production daemon); the log of the run (SHA-256 `4c1cfa30721be3e57e45642fb22d371592013bb7c8bcf7e581105030f7fd587e`) is a supplemental
  asset, `p120-publish-dryrun-v1.log`, of the same evidence-only draft release as the evidence archive (it is not a member of the archive
  and not listed in `ARCHIVE.sha256`), not committed.
* **Dry run of the OCI conversion and the recovery against a real registry** (`tests/publish/dryrun_conversion_local_registry.py`, same isolation as
  above: the test VM, a throwaway `registry:2` on 127.0.0.1, task-scoped, removed afterwards): real builds, `docker save`/`load`/`push`, real
  `buildx imagetools inspect`/`create`, and every HTTP call of `HttpRegistry`. The daemon there pushes OCI manifests, so the script rewrites each pushed
  image manifest to its Docker v2 form, as a classic store would; that part is a simulation. It shows the first publication (Docker v2 children
  converted, `dev` an annotated OCI index of the tested images, the pushed Docker manifests kept), the state the first main run left (a real unannotated
  Docker manifest list written by `imagetools create`), the refusal of an ordinary run and of a recovery for another digest, and the recovery of
  exactly that manifest with a read-back. It does not exercise GHCR, `GITHUB_TOKEN` or a hosted runner.

## What has NOT been executed, and the first real publication (finding F-C5-1, OPEN)

* **The first publication failed.** The `main` run 44093111109 at `666ee9c` (job `Publish dev image (main only)`) staged both tested images, `imagetools create`
  wrote `dev`, and the read-back refused: "the dev index revision annotation is not 666ee9c...". Read anonymously and read-only (C5 run 528, and again
  while writing these tests), `ghcr.io/nicotm77/mandatary:dev` is a **Docker manifest list** (`application/vnd.docker.distribution.manifest.list.v2+json`,
  digest `sha256:0c889407...`) of two Docker v2 platform manifests with **no annotations**. Both entries are the tested images (their config digests are
  the tested ones), so this is not an integrity problem; but the tag is not the annotated OCI index this document describes, and because it carries no
  revision annotation every later run **refuses before writing** until the owner decides what to do with it (CI cannot delete package versions). This
  record is kept as evidence (the raw manifests are fixtures, see above). **The code now converts the children to OCI before writing, verifies the
  result, and carries the one-time recovery above; none of it has run against GHCR.** No registry write, deletion or replacement has been made by
  anyone for this finding: the registry still holds the unannotated list until a run of the corrected `publish` job on `main` replaces it. Closing the
  finding needs that run **and** an independent read of the registry (the commands below), not a green workflow.
* What a real GHCR may still do differently from every test here, and what the first corrected run therefore proves: that the registry's token
  endpoint accepts the job's `GITHUB_TOKEN` (the challenge format, `Bearer realm="https://ghcr.io/token",service="ghcr.io"`, was read anonymously; the
  credential exchange was not), that a manifest `PUT` under the staging tag is accepted and linked to the package, that `imagetools create` over the
  converted children writes the annotated OCI index, and what a classic-store runner really pushes. A failure of any of these is red before `dev` is
  written, except the create itself.
* The behaviour of **GHCR** itself (authentication with `GITHUB_TOKEN`, package creation and repository association, visibility, the
  `imagetools` calls against it, the hosted runner's Docker version and image store) is not verified by anything here. After the first `main`
  run, read the registry; a green workflow is not evidence:

  ```bash
  docker buildx imagetools inspect --raw ghcr.io/nicotm77/mandatary:dev      # mediaType application/vnd.oci.image.index.v1+json, exactly linux/amd64 and linux/arm64
                                                                              # (OCI manifests), annotations: revision = the commit, source = the repository
  docker buildx imagetools inspect ghcr.io/nicotm77/mandatary:dev            # platforms, digests
  # each platform manifest (inspect --raw REPO@DIGEST): mediaType application/vnd.oci.image.manifest.v1+json; its config digest must equal the
  # `config_digest` recorded in the run's tested-image artifact (1 day) or the job summary; after the one-time recovery the digest of `dev` must no longer
  # be sha256:0c889407...
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
