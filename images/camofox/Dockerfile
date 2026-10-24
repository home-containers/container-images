# syntax=docker/dockerfile:1
# CI resolves both upstream inputs to immutable, platform-appropriate digests.
ARG BASE_IMAGE=ghcr.io/jo-inc/camofox-browser:latest
ARG NODE_IMAGE=node:22.23.4-trixie-slim
FROM ${NODE_IMAGE} AS node-runtime
FROM ${BASE_IMAGE}

# Keep APT-owned Python + stdlib and shared Brotli together under Debian ownership.
# Intentional runtime addition: support the inherited VNC plugin when ENABLE_VNC=1.
# No app config or inherited image startup/environment metadata is changed here.
RUN set -eu; \
    test "$(id -u)" = 0; \
    . /etc/os-release; \
    test "$ID" = debian; test "$VERSION_CODENAME" = trixie; \
    test "$(dpkg-query -W -f='${db:Status-Status}' dpkg)" = installed; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        x11vnc novnc python3-websockify net-tools procps; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

COPY build_overlay.py policy.json /usr/local/share/camofox-overlay/
COPY tests/verify_image.py /usr/local/share/camofox-overlay/verify_image.py
# Only the donor executable is visible; do not transplant npm or /usr/local trees.
RUN --mount=from=node-runtime,source=/usr/local/bin/node,target=/tmp/camofox-node,ro \
    python3 -B -I -S /usr/local/share/camofox-overlay/build_overlay.py \
        --apply --node-candidate /tmp/camofox-node \
        --policy /usr/local/share/camofox-overlay/policy.json \
    && python3 -B -I /usr/local/share/camofox-overlay/verify_image.py
