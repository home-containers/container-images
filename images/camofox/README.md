# Camofox image

Status: proposed target; select and verify the exact upstream server repository/image before adding a recipe. No Dockerfile, build or patched image is enabled yet.

## Track three separate components

1. The Camofox HTTP server and its application dependencies.
2. Every Node runtime or system shared library shipped by the base image.
3. The separately packaged Camoufox browser and its embedded native libraries.

An updated server or Node version does not prove that the browser is updated. A newer browser does not fix a vulnerable curl/system library in the same image.

## Overlay policy

- Pin the server image/release and browser artifact separately, with architecture and checksums recorded.
- Prefer upstream browser binaries instead of taking on a complete browser build unless a required fix is unavailable.
- Verify license/redistribution terms for the selected artifacts.
- Preserve the original initialization, display/VNC and browser-launch behavior where those features are used.
- Do not bake cookies, browsing history, user identities or persistent browser profiles into the image.

## Required tests

- HTTP service health and browser startup.
- Create a disposable browser profile; navigate to a controlled page and verify its content.
- Headless/display behavior and VNC health if that target promises them.
- Browser, Node and system-library patch evidence independently.
- Writable state-volume behavior and clean shutdown with no production browser state.

The exact publisher and base digest are intentionally unresolved until verified; do not invent a registry image from a local image ID.
