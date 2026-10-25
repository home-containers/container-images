# Dependency override policy

## Base-image contract: overlays, not upstream rebuilds

Every target must start `FROM` its official upstream image and apply only the necessary downstream modifications. For Hermes, the requested base is `nousresearch/hermes-agent:stable`; a build argument may resolve that image to its digest without changing this contract.

Upstream Dockerfiles are context for understanding the shipped image, not build recipes to copy, follow from `main`, or execute in place of consuming the published image. Preserve the application and runtime already shipped in the base. Do not recreate the full application environment, invoke an upstream application/image assembler, or rebuild frontend/application artifacts as a routine dependency override. If a fix genuinely cannot be applied safely without that work, explain the limitation and obtain explicit approval for the exception first.

This remains the default for Hermes, Plex and future targets. **Approved Camofox exception:** build upstream v1.18.1 source at `39c82094013480b373df6600d44c7f036f58356e` using a lightly updated `Dockerfile.ci`, an official digest-pinned Node base and the publisher's beta.30 browser artifact installed once. Preserve upstream application files and its lockfile; use its normal `npm ci` native-addon build. This avoids retaining beta.28 beneath a replacement browser. It does not authorize following application `main`, compiling the browser, or rebuilding Hermes. Dependency overrides must still respect the application's lock/startup ownership.

## First identify the code being executed

Package names and scanner findings are leads, not an inventory of executed code. An OS shared library, a statically linked runtime, a native Python wheel and a browser can each contain independent copies of the same vulnerable library.

For example, updating Debian's Brotli library does not automatically patch a Python wheel that bundles Brotli. Likewise, an older runtime-reported Brotli version may include a security backport. Check the maintainer advisory, package provenance, patch evidence and actual executable/library path.

Do not claim an entire image is fixed from one package's version check.

## Preferred order

1. Adopt a fixed upstream release image.
2. Update specific supported distro packages from the same distribution suite.
3. Use a supported application dependency/runtime override.
4. Carry a minimal upstream patch or replacement artifact, with review and regression tests.
5. Fork application source only when the fix actually requires source changes.

Do not mix Debian/Ubuntu release suites or introduce arbitrary third-party repositories to obtain one newer library. Do not copy shared libraries from another distribution or force incompatible ABI replacements.

## Distribution packages

- Detect the actual distribution and package manager per image. There is no universal `apt upgrade` layer.
- Prefer an explicit fixed-package list. Resolve compatible dependency updates rather than blindly forcing one package version.
- Run package-index refresh and installation in the same build layer; remove downloaded indexes and temporary files in that layer.
- Review any proposed removal, newly installed dependency, config-file replacement or service-start side effect.
- Verify distro security backports rather than comparing only the upstream-looking version number.
- A pinned base does not freeze moving package repositories. Record the resolved package inventory; use exact versions and an appropriate snapshot when stronger reproducibility is required.
- OS updates are useful but do not patch statically linked or vendored application libraries.

## Python and Node packages

- Locate the interpreter/environment or module tree actually used by the application.
- Identify the owner of its dependency constraints, lockfile and startup synchronization.
- Do not blindly run global `pip install --upgrade` or `npm audit fix --force` over the application.
- Keep overrides coherent with the managed environment. Exercise normal startup to prove the old version is not restored.
- Preserve the upstream manifests as provenance. Any deliberate local divergence must be documented, not disguised as an untouched lockfile.
- Confirm native wheels/binaries exist for every enabled architecture or use a reviewed build stage. Keep compilers and caches out of the final image where practical.
- For a runtime replacement, inspect every runtime executable that can still be selected by PATH, launchers or subprocesses.

## Startup compatibility

Preserve the upstream entrypoint, command, initialization system, healthcheck, signal handling, volumes and effective startup user unless the change is intentional and tested. Some images require a root initialization phase before dropping privileges; replacing that phase with a generic non-root `USER` can break them.

Temporarily switching to root for a build step is not permission to leave an originally non-root application running as root. Match upstream behavior deliberately.

## Required record for every override

- Component and exact environment/path being changed.
- Advisory or upstream issue, reason for the change and affected execution path.
- Original and replacement versions, fixed minimum or patch commit.
- Artifact source, checksum/digest, architectures and license considerations.
- Manifest/lockfile/runtime implications and any accepted upstream divergence.
- Regression test and observed build/test results.
- Owner and review/removal condition: normally the first upstream release that passes the same checks without the override.

## Verification

Combine a current vulnerability scan with targeted checks and a real startup smoke test. Scanners may miss bundled code or misinterpret backports. Version strings alone are not sufficient when patches were backported.

Block newly introduced relevant high/critical findings. Existing exceptions need a documented rationale, scope, expiry/review date and compensating controls; never silently suppress an entire scanner class.

Do not run exploit payloads against production. Exercise targeted regression tests in disposable, isolated containers. Do not import a suspected supply-chain package just to discover its version.

## Disk usage

An overlay retains the parent image's layers even if files are replaced or deleted in a later layer. Minimize package caches and build tools, but do not promise that cleaning the overlay removes bytes from the upstream layers. The deployment host still needs room for the new image, temporary extraction and the retained rollback image.
