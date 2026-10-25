# Camofox security overlay

A thin derivative of **`ghcr.io/jo-inc/camofox-browser:latest`**. CI resolves that requested tag once to an immutable multiarchitecture digest and supplies the same input to both native jobs. This does not rebuild Camofox, run `npm ci`, compile the browser, or import the historical local source-build/slimming recipe.

Implementation, native acceptance, publication and production deployment are distinct milestones. Inspect the exact Actions run and source revision for test evidence. No schedules or automatic deployments are configured.

## Narrow overrides

- **Debian:** require trixie, refresh APT indexes and upgrade installed distro packages. Keep Python's interpreter and standard library under APT ownership; no pip overwrite or transplanted standalone interpreter. Enforce `policy.json` package floors using Debian version comparison.
- **Node:** retain the compatible 22.x major. Replace only the executable, if needed, from a digest-resolved official `node:22.23.4-trixie-slim` donor. Preserve a newer compatible patched inherited executable instead of downgrading. Do not copy the donor's entire `/usr/local`, replace npm, or rebuild native addons to hide incompatibility.
- **Brotli:** check Debian's shared library, Node's bundled decoder, installed Python bindings where present, and browser patch evidence separately. Do not add absent optional bindings. An unexpected vulnerable binding requires an ownership-aware fix rather than a blanket pip mutation.
- **Browser:** retain at least Camoufox `152.0.4-beta.30`; the published base's older browser must not silently replace the existing deployment's beta.30. Where needed, install only the publisher's architecture-specific prebuilt archive using the URL and SHA-256 recorded in `policy.json`. Validate before extraction; do not compile the browser or downgrade a newer compatible inherited release.
- **VNC compatibility:** install the distro runtime packages required by the shipped upstream plugin: `x11vnc`, `novnc`, `python3-websockify`, `net-tools`, `procps`. Enable it only at runtime through upstream's `ENABLE_VNC=1`. No application-source/configuration patch, password or private deployment configuration is baked in.

The application tree, `node_modules`, native addons, plugin code and configuration remain unchanged. CI compares file hashes, modes and symlink targets, rejects missing representative coverage and detects additions/deletions. Browser and Node overrides are explicit exceptions outside `/app`. Entrypoint, CMD, user, working directory, environment and declared volumes remain inherited.

## Security floors and limitations

Initial policy: Node 22.23.4 or newer compatible 22.x; Debian `libbrotli1 >= 1.1.0-2+deb13u1`; Debian `python3.13 >= 3.13.5-2+deb13u5` with matching standard-library packages. An older upstream version string can include a distro backport.

`BrotliDecoderErrorString(-17)` must return exactly `_ERROR_FORMAT_BLOCK_SWITCH`; Node's corresponding constant must equal -17. These checks support a targeted patch assessment, not universal vulnerability clearance. A browser marker is not a browser-wide security audit. Debian still lists open Python 3.13 issues: its supported updates do not fix every upstream advisory. Comprehensive vendored-binary scanning, SBOM generation and signing are not claimed.

Unsupported distro/Node-major changes, unexpected vulnerable bindings and unrecognizable browser releases must fail visibly instead of silently broadening the overlay.

## Workflows and tests

- `.github/workflows/camofox-verify.yml`: manual-only, read-only, no registry writes.
- `.github/workflows/camofox-publish.yml`: separate manual-only, main-branch publisher; package write permissions only on publishing jobs.
- `.github/actions/camofox-accept/action.yml`: shared native acceptance used by both workflows, preventing test drift.

Build only on GitHub-hosted native `ubuntu-24.04-arm` and `ubuntu-24.04` runners, never locally or on the production host.

Local tests without containers:

```sh
python3 -I -m unittest discover -s images/camofox/tests -p 'test_*.py' -v
```

After source review, dispatch verification:

```sh
gh workflow run camofox-verify.yml --repo home-containers/container-images --ref main
```

Acceptance covers helper regressions, immutable inputs, inherited startup metadata, application/dependency preservation, security floors/decoders, native SQLite, actual controlled-page browser navigation, API authentication, cookie/localStorage persistence across restart, noVNC and a real RFB handshake, writable disposable state and orderly shutdown. Brotli update acceptance relies on package versions and patch evidence, not a browser compressed-page rendering test or exploit-containment test. A green `/health` alone is not acceptance evidence.

Runtime tests generate ephemeral credentials and use synthetic profiles on an isolated network. They do not use production cookies, keys, identities or host configuration.

## Publication and deployment

Intended package: `ghcr.io/home-containers/camofox-browser`. A checked-in recipe does not prove this image exists or is public. The separate publisher repeats native acceptance, pushes the exact tested images, pulls them back and checks identity/security, then validates the combined index before promoting `stable`.

Tags are `build-<run-id>-<attempt>` plus a recorded digest. After failure, dispatch afresh or rerun **all** jobs; never mix architecture outputs from different attempts. Verify anonymous registry access separately. Production replacement, state migration and restart need separate authorization.

## Primary references

- Publisher: https://github.com/jo-inc/camofox-browser/blob/master/.github/workflows/docker.yml
- Upstream Dockerfile (context only): https://github.com/jo-inc/camofox-browser/blob/master/Dockerfile.ci
- Node advisory: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
- Debian Brotli: https://security-tracker.debian.org/tracker/source-package/brotli
- Debian Python: https://security-tracker.debian.org/tracker/source-package/python3.13

Keep publisher provenance alongside browser URLs and hashes in `policy.json` when updating the lock.
