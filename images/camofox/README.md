# Camofox upstream-recipe build

Build the unmodified **Camofox v1.18.1 application source** at commit
`39c82094013480b373df6600d44c7f036f58356e` using a reviewed adaptation of
that release's `Dockerfile.ci`. This is an explicitly approved exception to
this repository's default upstream-image overlay policy. Hermes is unchanged.

The previous image-overlay implementation retained upstream's beta.28 browser
layer and added beta.30 in another layer. This recipe installs beta.30 once,
following the build-argument workaround described in upstream issue #14575.
It does not compile Firefox/Camoufox or track application `main`.

Implementation, native acceptance, publication and production deployment are
separate milestones. A changed recipe is not proof of a tested or published
image. No schedules or automatic production deployments are configured.

## Reviewed changes relative to upstream

- **Base/runtime:** use official `node:22.23.4-trixie-slim`, resolved to a
  multiarchitecture digest once per run. Do not transplant a Node executable
  into an already-built application image.
- **Browser:** install publisher-built Camoufox `152.0.4-beta.30` directly,
  using the per-architecture URLs, SHA-256 values and identical-artifact mirror
  in `policy.json`. Validate the archive before extraction and remove temporary
  downloads in the same layer. There is no inherited browser replacement.
- **Debian:** update supported trixie packages and retain APT ownership of Python
  and its matching standard library. Keep security floors for Python and
  `libbrotli1`; do not add absent optional Python Brotli bindings.
- **Native dependencies:** run `npm ci --omit=dev` using the exact upstream
  lockfile. Install and purge `build-essential` in the same build step so the
  compiler installation does not remain in a lower image layer. Route npm's
  download cache to `/var/cache/camofox-npm` and delete it in that same step;
  retain installed dependencies and their native runtime addons.
- **Package recommendations:** use `--no-install-recommends` for direct APT
  installations. Apply the same policy to unmodified upstream plugin hooks
  through a build-step-only `APT_CONFIG`, removed on success or failure.
  Explicitly install `xauth` so `xvfb-run` authentication remains available;
  retain the named fonts, graphics libraries, plugins and VNC stack. This
  policy does not change runtime APT defaults or startup environment.
- **VNC:** include `x11vnc`, `novnc`, `python3-websockify`, `net-tools` and `procps`
  for the upstream plugin. Enable only at runtime using `ENABLE_VNC=1`; bake in
  no passwords, profiles or private configuration.
- **Application/startup:** leave upstream application files, manifests, plugin
  configuration, Node entrypoint and server command unchanged. Installed native
  addons are built/resolved by upstream's normal locked installation rather
  than copied from another application image.

Retain upstream's per-architecture yt-dlp integrity checks. Do not substitute a
new application revision, remove required fonts or strip browser features as
an unreviewed size optimization.

## Security floors and limitations

Policy requires compatible Node 22.x at least 22.23.4, Debian
`libbrotli1 >= 1.1.0-2+deb13u1`, and Debian
`python3.13 >= 3.13.5-2+deb13u5` with matching standard-library packages.
Security backports can retain older-looking upstream version strings.

Exact runtime patch-marker checks supplement package metadata:
`BrotliDecoderErrorString(-17)` must return `_ERROR_FORMAT_BLOCK_SWITCH`, and
Node's corresponding constant must equal -17. Browser patch evidence is
checked separately. These are targeted checks, not full vulnerability
clearance. Debian Python can still have open upstream advisories; comprehensive
vendored-binary scanning, SBOM generation and signing are not claimed.

Brotli update acceptance does **not** require a compressed-page browser fixture
or an exploit-containment test. Ordinary navigation remains mandatory.

## Workflows and tests

- `.github/workflows/camofox-verify.yml`: manual-only verification, no registry writes.
- `.github/workflows/camofox-publish.yml`: separate manual-only main-guarded publisher.
- `.github/actions/camofox-accept/action.yml`: shared native acceptance for both paths.

Build only on GitHub-hosted native ARM64 and AMD64 runners, never locally or on
the production host. Local helper tests do not invoke Docker:

```sh
python3 -B -I -m unittest discover -s images/camofox/tests -p 'test_*.py' -v
```

Acceptance checks immutable source and Node inputs, installed application
source content/modes/symlinks, startup metadata, security floors, native SQLite,
authentication, real browser navigation, cookie/localStorage persistence across
restart and container recreation, noVNC HTML plus actual WebSocket RFB, clean
exits and verified resource cleanup. A green `/health` alone is insufficient.

Runtime tests use disposable credentials and synthetic state. The fixture uses
an internal network; a supplementary bridge permits loopback port publication
and also permits app egress. Do not describe the app as internet-isolated.

## Image size and publication

Measure compressed registry layers and unpacked native layer sizes separately;
Docker's containerd store can retain both. Replacing the recipe is expected to
remove browser-duplication and retained-compiler costs, but actual savings must
come from the native build output, not estimates alone.

Package identity remains `ghcr.io/home-containers/camofox-browser`. Publication
repeats native acceptance, pushes the exact tested images, pulls them back,
checks identity/security, then verifies the combined index before promoting
`stable`. Build tags include run ID and attempt. Never combine architecture
outputs across attempts; verify anonymous access separately.

Publication and the NixOS deployment pin are separate approvals. Existing
published images and the running services stay unchanged until those steps
are explicitly authorized.

## Primary references

- Upstream issue: https://github.com/jo-inc/camofox-browser/issues/14575
- Recipe baseline: https://github.com/jo-inc/camofox-browser/blob/39c82094013480b373df6600d44c7f036f58356e/Dockerfile.ci
- Publisher: https://github.com/jo-inc/camofox-browser/blob/master/.github/workflows/docker.yml
- Node advisory: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
- Debian Brotli: https://security-tracker.debian.org/tracker/source-package/brotli
- Debian Python: https://security-tracker.debian.org/tracker/source-package/python3.13
