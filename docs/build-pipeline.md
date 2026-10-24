# Build, publish and promote

The broader lifecycle below remains an implementation contract. Hermes and Camofox have separate manual-only verification and publishing workflows on native GitHub-hosted ARM64/AMD64 runners. Camofox shares its acceptance steps between both paths and resolves upstream `ghcr.io/jo-inc/camofox-browser:latest` once per run. Each publisher grants package write access only to publishing jobs, tests and reads back each pushed image, then validates the multiarchitecture index before promoting `stable`. Check actual Actions/registry results; no scheduled jobs or production deployments are configured, and SBOM/signing/comprehensive scanning remain future work.

## Proposed lifecycle

```text
upstream release / base digest / dependency advisory
  -> update proposal
  -> review
  -> build + image-specific tests + scan
  -> candidate image in GHCR, identified by immutable digest
  -> disposable-state acceptance test
  -> explicitly approved production pin change
```

## Repository and registry layout

One repository with independent image targets. Proposed packages:

- `ghcr.io/home-containers/hermes`
- `ghcr.io/home-containers/camofox-browser`
- `ghcr.io/home-containers/plex`

Hermes and Camofox have manual implementation paths; Plex remains design-only. Confirm actual package availability after a publishing run. Verify upstream licensing and redistribution terms before publishing each target, particularly images containing proprietary software.

A public source repo does not itself establish a package's visibility. Verify each GHCR package's intended visibility and an anonymous pull before advertising public access. Public deployment images should not require the production host to retain a publishing credential.

## Events and approvals

- Initially manual target selection and reviewed changes only.
- Add a daily update check after the first target works. It should open a proposal for changed release pins or dependency fixes, not deploy to production.
- A dependency advisory can require rebuilding even when application source is unchanged. Conversely, rebuilding with unchanged fixed inputs is not evidence of a security update.
- Scheduled/manual security refreshes must intentionally refresh relevant package resolution or caches. Merely setting `--pull` does not invalidate every cached package-install layer or override a digest pin.
- Pull requests run validation without registry write access. Never combine untrusted PR code with publishing credentials or `pull_request_target` execution of that code.
- Only reviewed default-branch commits or authorized manual runs may publish.
- Production promotion is separate from successful publication. It changes a deployed digest only after approval and a rollback check.

## Runner and workflow requirements

- Ephemeral GitHub-hosted runners; no production host as a self-hosted runner.
- Native ARM64 for ARM64 targets where available; add AMD64 only when required and tested. Inspect the base manifest first rather than assuming all publishers support the same architectures.
- Pin third-party Actions to reviewed full commit SHAs, using automated PRs to update them.
- Default token permissions: `contents: read`. Grant `packages: write` only to the publishing job. Add signing/attestation permissions only when those steps are implemented.
- Authenticate to GHCR with that job's `GITHUB_TOKEN`; do not add a personal account token as a repository secret.
- No production credentials or live state in builds/tests. Do not mount host sockets or SSH keys.
- Bound timeouts, concurrency, artifact retention and build-cache usage. Recheck runner availability and billing before enabling additional platforms or expensive browser compilation.

## Candidate outputs

For each image/platform, publish or attach:

1. The built digest and immutable revision/commit tag. Rebuilding the same commit against moving package repos must create a distinct build identifier; never silently overwrite an allegedly immutable tag.
2. Upstream release and base digest, source commit and resolved override/package inventory.
3. SBOM, provenance and scan results. Verify any promised signing/attestation artifact exists rather than merely enabling a workflow flag.
4. Actual smoke/regression test results and known exceptions.

Use a clearly non-production candidate channel if a mutable convenience tag is needed. Do not silently move a production `stable` or `latest` tag.

## Acceptance gates

- Base image identity, architecture and startup metadata are correct.
- Fixed dependency is present in the environment that executes it.
- Ordinary startup does not overwrite or revert the override.
- Image-specific health, functionality, signal handling and writable-volume behavior pass with disposable state.
- No accidental secret or production configuration appears in layers, logs or build context.
- Registry readback matches the intended image and digest.

A scan pass is not a guarantee of safety; failed or unavailable tests must remain visible. Never replace real test results with expected output.
