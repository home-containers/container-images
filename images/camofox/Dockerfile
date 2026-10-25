# Lightly patched jo-inc/camofox-browser Dockerfile.ci, v1.18.1.
# Source: 39c82094013480b373df6600d44c7f036f58356e
# Build context is the verified upstream checkout; CI stages .container-images/.

ARG NODE_IMAGE=node:22.23.4-trixie-slim
FROM ${NODE_IMAGE}

ARG TARGETARCH
ARG YT_DLP_VERSION=2026.08.19
ARG YT_DLP_SHA256_AMD64=58162f9bfdc27458ea47bfcb311cf47028f17d8154a8bf7d689861d46399230a
ARG YT_DLP_SHA256_ARM64=b16e4dab368a816cd05d477d698a605a6ae87ccee1c8ffd38fa21d7254141fcc

# Install dependencies for Camoufox (Firefox-based)
RUN set -eu; \
    . /etc/os-release; \
    test "$ID" = debian; test "$VERSION_CODENAME" = trixie; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # Firefox dependencies
    libgtk-3-0 \
    libdbus-glib-1-2 \
    libxt6 \
    libasound2 \
    libx11-xcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    # Mesa OpenGL/EGL for WebGL support (software rendering via llvmpipe)
    # `libegl1-mesa` was dropped in Debian trixie.
    libegl1 \
    libgl1-mesa-dri \
    libgbm1 \
    # Xvfb virtual display
    xvfb \
    xauth \
    # Fonts
    fonts-liberation \
    fonts-noto-color-emoji \
    fontconfig \
    # Utils
    ca-certificates \
    curl \
    unzip \
    # Keep APT-owned Python and shared Brotli patched together.
    python3 \
    libbrotli1 \
    # Runtime dependencies for the upstream optional VNC plugin.
    x11vnc \
    novnc \
    python3-websockify \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY .container-images/ /usr/local/share/camofox-build/
# Download beta.30 once, verify the per-architecture policy hash before safe
# extraction, and remove the archive in this RUN (including mirror fallback).
RUN python3 -B -I -S /usr/local/share/camofox-build/build_overlay.py \
      --install-browser --arch "${TARGETARCH}" \
      --policy /usr/local/share/camofox-build/policy.json

WORKDIR /app

COPY package.json package-lock.json ./
# npm ci runs the postinstall hook, which needs postinstall.js and its one lib/ import.
COPY postinstall.js ./
COPY lib/camoufox-download.js ./lib/
COPY scripts/ ./scripts/
# Build tools are needed when better-sqlite3 has no native prebuild for the target.
# Trixie's glibc also supports the upstream arm64 prebuild at runtime.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential \
    && npm ci --omit=dev --cache /var/cache/camofox-npm \
    && rm -rf /var/cache/camofox-npm \
    && apt-get purge -y --auto-remove build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY server.js ./
COPY camofox.config.json ./
COPY lib/ ./lib/
# lib/cookies.js re-exports mcp/lib/cookies.mjs for persistence support.
COPY mcp/ ./mcp/
COPY plugins/ ./plugins/
COPY scripts/ ./scripts/

# Install default plugin dependencies. yt-dlp is pinned per target architecture
# and verified by the YouTube plugin hook.
# Note: sh is used explicitly (./scripts/) because COPY from Windows
# does not preserve +x permission bits in Docker build contexts.
# Scope recommendation suppression to this build step, including upstream hooks.
# Do not modify upstream plugin sources or leave an APT policy at runtime.
RUN set -eu; \
    export APT_CONFIG=/usr/local/share/camofox-build/apt-no-recommends.conf; \
    test ! -e "$APT_CONFIG"; \
    trap 'rm -f "$APT_CONFIG"' EXIT; \
    printf 'APT::Install-Recommends "false";\nBinary::apt-get::APT::Install-Recommends "false";\n' > "$APT_CONFIG"; \
    case "${TARGETARCH}" in \
      amd64) export YT_DLP_ASSET=yt-dlp_linux YT_DLP_SHA256="${YT_DLP_SHA256_AMD64}" ;; \
      arm64) export YT_DLP_ASSET=yt-dlp_linux_aarch64 YT_DLP_SHA256="${YT_DLP_SHA256_ARM64}" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    sh scripts/install-plugin-deps.sh

# Fail closed on distro package floors, exact Brotli patch markers, and the
# native SQLite addon without requiring inherited-image overlay evidence.
RUN python3 -B -I /usr/local/share/camofox-build/verify_image.py

ENV NODE_ENV=production
ENV CAMOFOX_PORT=9377

EXPOSE 9377

CMD ["sh", "-c", "node --max-old-space-size=${MAX_OLD_SPACE_SIZE:-128} server.js"]
