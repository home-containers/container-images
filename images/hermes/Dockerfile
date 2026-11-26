# Derived image: preserve upstream's s6 entrypoint, command and privilege drop.
# Upstream v0.23.4 multiarchitecture image (amd64 and arm64).
ARG BASE_IMAGE=nousresearch/hermes-agent@sha256:ef0650d523ee1b5ab32c779acabc446d9936869a9932591553688a62bcf0c42f
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.source="https://github.com/home-containers/container-images" \
      org.opencontainers.image.title="Hermes security overlay" \
      org.opencontainers.image.description="Digest-pinned upstream Hermes with refreshed Debian packages"

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
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libbrotli1)" ge '1.1.0-2+deb13u1'; \
    test -z "$(dpkg --audit)"; \
    mkdir -p /usr/local/share/hermes-overlay; \
    dpkg-query -W -f='${Package}\t${Version}\n' > /usr/local/share/hermes-overlay/dpkg-packages.tsv; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

COPY --chmod=0644 tests/verify_image.py /usr/local/share/hermes-overlay/
RUN /opt/hermes/.venv/bin/python -B -I /usr/local/share/hermes-overlay/verify_image.py
