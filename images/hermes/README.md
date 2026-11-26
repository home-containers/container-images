# Hermes security overlay

This image uses the digest-pinned upstream Hermes v0.23.4 image and refreshes its Debian 13 (`trixie`) packages using noninteractive `apt-get upgrade --with-new-pkgs`. This permits new dependencies without removing installed packages or changing Debian releases. The resulting Debian package inventory is recorded under `/usr/local/share/hermes-overlay/`.

Hermes, its managed Python and npm, the virtual environment, and the upstream dependency locks are inherited untouched. We don't reinstall `brotlicffi` or explicitly install `libbrotli1`; the image must pass the existing Debian, Python, and Node Brotli checks without either override. APT only updates Debian-managed components.

## Build inputs

- `BASE_IMAGE` defaults to the reviewed v0.23.4 multiarchitecture digest.
- Both workflows use the immutable reference in the Dockerfile. Updating the upstream release requires updating that reference and the publisher’s release tag and version label.
- A closed `.dockerignore` sends only the Dockerfile and required build/check scripts, not runtime state or credentials.
- Moving Debian repositories mean refreshed APT contents can differ between builds. The captured inventory records what was installed; a base digest alone does not make APT updates reproducible.

## Verification: GitHub-hosted runners only

Do **not** build this image locally or on the production NixOS host. The manual-only workflow `.github/workflows/hermes-verify.yml` uses native ARM64 and AMD64 GitHub-hosted runners and has read-only repository permissions. It does not publish images.

Run from GitHub's Actions tab, or dispatch remotely:

```sh
gh workflow run hermes-verify.yml --repo home-containers/container-images
```

It runs:

- Unit tests for the read-only inventory and verification checks.
- A fresh upstream pull and uncached derived-image build.
- Upstream Hermes file inventory and startup-metadata/environment inheritance checks.
- Decoder and PM checks in a network-disabled disposable container.
- The normal upstream s6 startup with empty tmpfs state, no network and dashboard disabled.
- Checks that the inherited dependencies pass verification after startup, the CLI runs, UID 10000 can write state, and shutdown does not require SIGKILL.

Tests never mount production profiles, access provider credentials or reconnect the live Slack bot. The checks are targeted regression/patch checks, **not a comprehensive vulnerability scan or clearance of every bundled component**. Existing runtime dependency generations need a separate disposable-state migration test before deployment to an existing installation.

## Publish: authorized manual runs only

The separate `.github/workflows/hermes-publish.yml` workflow is dispatched manually from `main`. It repeats the same native ARM64/AMD64 tests, uses only job-scoped `GITHUB_TOKEN` credentials, and pushes the **exact tested images**. Each image is pulled back and its image ID and decoder checks verified before assembling the multiarchitecture index.

```sh
gh workflow run hermes-publish.yml --repo home-containers/container-images --ref main
```

Outputs:

- `ghcr.io/home-containers/hermes:build-<run-id>-<attempt>` — unique build identifier; APT can change even for the same source commit.
- `ghcr.io/home-containers/hermes:v0.23.4` — upstream-version tag for the tested overlay.
- `ghcr.io/home-containers/hermes:stable` — optional convenience tag promoted only after both native builds/tests and index validation pass.
- `ghcr.io/home-containers/hermes@sha256:<digest>` — immutable deployment reference, recorded in the Actions summary.

Per-architecture build tags are retained for traceability. Publishing is not production deployment. Registry authentication/readback is verified by CI; public visibility and anonymous pulls must be checked separately. A newly created GHCR package can require a one-time **Package settings → Change visibility → Public** action by the account owner. No SBOM, signing, provenance attestation or comprehensive scan is claimed by this workflow.

## Size and cache caveat

The original upstream layers remain part of the image. Replacing the environment or deleting an old cached package in a later layer cannot erase bytes from its parent layers. Build tools already present upstream are not removed indiscriminately because PM lazy extras can depend on them. No size reduction or complete removal of historical parent-layer bytes is promised.

## References

- [Upstream Dockerfile on main](https://github.com/NousResearch/hermes-agent/blob/main/Dockerfile) — design reference; the chosen image's bundled source governs that build.
- [Hermes Docker ownership and dependency model](https://hermes-agent.nousresearch.com/docs/user-guide/docker)
- [Python 3.14.9 security release](https://www.python.org/downloads/release/python-3149/)
- [Python release listing](https://www.python.org/downloads/)
- [Debian Brotli advisory tracking](https://security-tracker.debian.org/tracker/CVE-2026-111497)
- [Python Brotli advisory](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)
