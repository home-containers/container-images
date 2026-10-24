# Hermes security overlay

Debian-derived image based on **`nousresearch/hermes-agent:stable`**. The Dockerfile, lock-coherent override helper, read-only image checks and manual GitHub Actions verification/publication workflows are implemented. Consult actual Actions and registry results before treating a revision as verified or published. No production deployment is configured.

## What changes

1. Verify that the base is Debian 13 (`trixie`), the distribution used by the reviewed stable image.
2. Run `apt-get update` and noninteractive `apt-get upgrade --with-new-pkgs`. This allows new dependency packages but is not a distribution upgrade and does not authorize package removals.
3. Ensure `libbrotli1` includes Debian's security backport, at least **`1.1.0-2+deb13u1`**. Verify both its Debian package version and the decoder's new error marker.
4. Change the selected application dependency to **`brotlicffi==1.2.1.0`**, the fixed Python release for CVE-2026-111497. Do not downgrade a newer upstream pin.
5. Refresh `uv.lock` through Hermes PM, rejecting unrelated package-entry changes. The root project's own changed dependency metadata is expected.
6. Replace **only the Brotli wheel in the existing `.venv`**, using bundled uv with `--no-deps`, `--require-hashes`, `--only-binary=:all:` and a package-scoped reinstall. This is an explicit downstream build-time exception because PM has no public API for a hash-enforced one-package in-place replacement. Update only the static Brotli dependency declaration and the PM selection stamp; preserve the shipped extras.
7. Verify fixed decoders, HTTPX decoding, Node's patch marker and PM lock consistency. Compare SHA-256 inventories against the published base: application code, frontends, launchers, managed runtime files and unrelated installed dependencies must remain unchanged. Only the reviewed Brotli paths, dependency manifest/lock/declaration, selection facts and disposable caches/bytecode are excluded.

**No upstream application rebuild:** the Dockerfile consumes the published `nousresearch/hermes-agent:stable` image. It does not fetch upstream `main`, recreate `.venv`, rebuild frontends or invoke the upstream assembler. A changed image layout or an override requiring broader changes must fail for review, not silently expand the build.

### The release-age policy

Upstream's dependency resolver normally requires releases to be three days old. The October 22 Brotli security release was younger than that when this overlay was prepared on October 24. The overlay adds **only `brotlicffi = false`** to the package-specific age exceptions, alongside upstream's existing certifi exception. The global three-day gate stays enabled, the Brotli version is exact, and the resolved artifacts remain hash-locked. This is a deliberate downstream exception for the reviewed security fix, not a blanket freshness-policy bypass.

## Python: update security patches, not the minor version blindly

APT refreshes Debian's separate system Python. It does not replace Hermes's PM-managed interpreter.

The reviewed stable image already contains **CPython 3.14.9**, released October 21, 2026 as an expedited security release. It is the current patch release in the supported 3.14 series as of October 24. Python 3.15.1 also exists, but changing the application to a new minor series is not required for this fix and would change native-wheel/ABI compatibility.

This overlay retains the managed interpreter and enforces a **3.14.9 minimum**. An older base fails closed; it does not silently swap in an incompatible distro interpreter. Revisit the minimum and PM runtime artifacts when a later 3.14 security release is available. No claim is made that this static minimum automatically tracks future advisories.

**Latest is not vulnerability-free.** CPython's open [issue #160040](https://github.com/python/cpython/issues/160040) tracks additional compromised-intermediate-key distrust. No newer released 3.14 patch was found on October 24, and switching to 3.15.1 is not an evidenced fix. Certificate-store updates and the exact verified TLS chain matter; this does not establish that every described platform-specific scenario affects this Debian image. The reviewed base already pins `certifi==2026.10.19` and PM uv 0.13.5; the interpreter version alone would not prove those trust-store/tool updates. This overlay is not a clearance of the outstanding TLS issue.

## What stays upstream-owned

- s6 entrypoint, command routing, root initialization and the subsequent privilege drop.
- The existing Python runtime/tool-artifact lock, Node runtime and frontend bundles.
- Persistent profile/configuration ownership and the `/opt/data` volume contract.

The Python dependency manifest and lock deliberately diverge for the security override. The original copies, their lock hash and the derived build report are retained under `/usr/local/share/hermes-overlay/`; the APT inventory is there as `dpkg-packages.tsv`.

## Build inputs

- `BASE_IMAGE` defaults to `nousresearch/hermes-agent:stable`, as requested.
- The verification workflow resolves that tag to a digest and passes the immutable reference into the build. A new run may intentionally resolve a newer stable image.
- `BROTLICFFI_VERSION` defaults to `1.2.1.0`; another exact fixed version requires review. Unsupported upstream manifest layouts, unrelated lock changes and newer pins that would be downgraded fail the build.
- A closed `.dockerignore` sends only the Dockerfile and required build/check scripts, not runtime state or credentials.
- Moving Debian repositories mean refreshed APT contents can differ between builds. The captured inventory records what was installed; a base digest alone does not make APT updates reproducible.

## Verification: GitHub-hosted runners only

Do **not** build this image locally or on the production NixOS host. The manual-only workflow `.github/workflows/hermes-verify.yml` uses native ARM64 and AMD64 GitHub-hosted runners and has read-only repository permissions. It does not publish images.

Run from GitHub's Actions tab, or dispatch remotely:

```sh
gh workflow run hermes-verify.yml --repo home-containers/container-images
```

It runs:

- Pure manifest-override unit tests.
- A fresh upstream pull and uncached derived-image build.
- Startup-metadata/environment inheritance checks.
- Decoder and PM checks in a network-disabled disposable container.
- The normal upstream s6 startup with empty tmpfs state, no network and dashboard disabled.
- Checks that the override survives startup, the CLI runs, UID 10000 can write state, and shutdown does not require SIGKILL.

Tests never mount production profiles, access provider credentials or reconnect the live Slack bot. The checks are targeted regression/patch checks, **not a comprehensive vulnerability scan or clearance of every bundled component**. Existing runtime dependency generations need a separate disposable-state migration test before deployment to an existing installation.

## Publish: authorized manual runs only

The separate `.github/workflows/hermes-publish.yml` workflow is dispatched manually from `main`. It repeats the same native ARM64/AMD64 tests, uses only job-scoped `GITHUB_TOKEN` credentials, and pushes the **exact tested images**. Each image is pulled back and its image ID and decoder checks verified before assembling the multiarchitecture index.

```sh
gh workflow run hermes-publish.yml --repo home-containers/container-images --ref main
```

Outputs:

- `ghcr.io/home-containers/hermes:build-<run-id>-<attempt>` — unique build identifier; APT can change even for the same source commit.
- `ghcr.io/home-containers/hermes:stable` — convenience tag promoted only after both native builds/tests and index validation pass.
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
