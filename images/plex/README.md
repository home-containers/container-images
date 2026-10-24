# Plex image

Status: proposed target; confirm the publisher, release channel, platform and required hardware before adding a recipe. No Dockerfile, build or patched image is enabled yet.

## Base choice

Prefer the publisher already supported for the intended deployment. The official Plex source is `plexinc/pms-docker`, but do not assume it is interchangeable with a third-party Plex image or available for every desired architecture.

Keep Plex's own release/update mechanism separate from distribution-package fixes. A generic distro upgrade does not patch the proprietary Plex Media Server binary or every bundled media component.

## Compatibility and redistribution

- Review the publisher's license and redistribution terms before publishing a derived image.
- Preserve startup, privilege handling, application paths, volumes and networking expectations.
- Do not replace bundled codec/transcoder libraries indiscriminately or mix incompatible GPU userspace/driver stacks.
- Verify the intended target platform before choosing runner architecture.
- Never include a Plex claim token, account token, media library or production database in source, build context or CI artifacts.

## Required tests

- Startup/version and server health with an empty disposable configuration.
- Clean shutdown and writable configuration behavior.
- Software playback/transcoding tests using redistributable synthetic fixtures where feasible.
- Hardware transcoding is a separate acceptance check on compatible equipment. A standard cloud runner cannot be assumed to validate the deployment's GPU or driver compatibility.

Reference: [official Plex Docker repository](https://github.com/plexinc/pms-docker).
