# Derived image: preserve upstream's s6 entrypoint, command and privilege drop.
# CI can override this with the resolved stable digest for an exact build input.
ARG BASE_IMAGE=nousresearch/hermes-agent:stable
FROM ${BASE_IMAGE}

ARG BASE_IMAGE
ARG BROTLICFFI_VERSION=1.2.1.0

LABEL org.opencontainers.image.source="https://github.com/home-containers/container-images" \
      org.opencontainers.image.title="Hermes security overlay" \
      org.opencontainers.image.description="Derived from upstream stable; refreshed Debian packages and a lock-coherent Brotli fix"

# Upstream needs root at startup for s6 initialization, then drops to hermes.
USER 0:0
WORKDIR /opt/hermes

RUN set -eu; \
    . /etc/os-release; \
    test "$ID" = debian; \
    test "$VERSION_CODENAME" = trixie; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get -o Acquire::Retries=3 update; \
    apt-get -o Acquire::Retries=3 -o Dpkg::Options::=--force-confold \
        upgrade -y --with-new-pkgs; \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends libbrotli1; \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libbrotli1)" ge '1.1.0-2+deb13u1'; \
    test -z "$(dpkg --audit)"; \
    mkdir -p /usr/local/share/hermes-overlay; \
    dpkg-query -W -f='${Package}\t${Version}\n' > /usr/local/share/hermes-overlay/dpkg-packages.tsv; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

COPY --chmod=0644 build_overlay.py tests/verify_image.py /usr/local/share/hermes-overlay/

# Debian Python is refreshed by APT above. Hermes uses a separate PM-owned
# interpreter: retain its reviewed 3.14.9+ runtime, do not replace it with a
# mismatched apt interpreter. An older base fails closed and needs a reviewed
# PM runtime-pin update rather than a blind major/minor Python upgrade.
# Replace only the Brotli wheel in the inherited environment. Keep the lock,
# dependency declaration and PM selection coherent without rebuilding Hermes,
# frontends, launchers, the interpreter, or the complete virtual environment.
RUN set -eu; \
    export HERMES_HOME=/var/tmp/hermes-overlay-build-home; \
    /usr/local/bin/python3 -B -I -S /usr/local/share/hermes-overlay/build_overlay.py \
        --brotlicffi-version "$BROTLICFFI_VERSION" --base-image "$BASE_IMAGE"; \
    /opt/hermes/.venv/bin/python -I /usr/local/share/hermes-overlay/verify_image.py; \
    rm -rf /var/tmp/hermes-overlay-build-home
