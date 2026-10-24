# Hermes image

Status: proposed target; no Dockerfile, build or patched image is enabled yet.

## Source and ownership

Use a verified stable release of the publisher's `nousresearch/hermes-agent` image, pinned by digest. Do not follow the application development branch automatically.

The initial design is an image overlay, not a fork of Hermes core. Keep persistent runtime profiles and credentials out of the build context.

## Special considerations

- Hermes has its own Python environment and dependency-management/startup behavior. Inspect the selected release before deciding how an override is installed.
- Updating a distro shared library does not necessarily update a Python Brotli wheel.
- Verify that normal startup and dependency synchronization preserve the selected fix. A successful one-off installer invocation is not acceptance.
- Inspect all Node executable copies as well as the Python environment and distro libraries; a fixed main Node binary does not clear the rest of the image.
- Preserve the publisher's initialization and privilege-drop contract rather than bypassing its entrypoint.

## Required tests

- CLI/version invocation and the normal startup path with disposable state.
- Dependency inventory and targeted advisory regression/patch checks.
- No environment repair or synchronization silently restores a vulnerable pin.
- Expected runtime UID, state-volume writes, health and clean shutdown.
- No messaging credentials or production provider calls in CI. A live Slack reconnect is a deployment acceptance check, not something a clean image CI run can claim.

Reference: [Hermes Docker documentation](https://hermes-agent.nousresearch.com/docs/user-guide/docker).
