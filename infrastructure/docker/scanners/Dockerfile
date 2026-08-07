# Prebuilt scanner CLIs for Security Portal.
# Downloads GitHub release binaries (avoids go install / CGO / libpcap compile failures).
FROM debian:bookworm-slim

ARG TARGETARCH=amd64
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      unzip \
      libpcap0.8 \
      python3 \
      python3-pip \
      ruby \
      ruby-dev \
      build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/install

# Pinned release versions (override with --build-arg if needed)
ARG NAABU_VER=2.6.1
ARG NUCLEI_VER=3.11.0
ARG DNSX_VER=1.3.0
ARG FFUF_VER=2.2.1
ARG GOWITNESS_VER=3.1.1
ARG FEROX_VER=2.13.1
ARG WHATWEB_VER=v0.5.5

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) PD_ARCH=amd64; FEROX_ARCH=x86_64; FFUF_ARCH=amd64; GOWIT_ARCH=amd64 ;; \
      arm64) PD_ARCH=arm64; FEROX_ARCH=aarch64; FFUF_ARCH=arm64; GOWIT_ARCH=arm64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    mkdir -p /opt/scanners/bin /opt/scanners/wordlists /opt/scanners/nuclei-templates /opt/scanners/pylib; \
    \
    curl -fsSL -o naabu.zip \
      "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VER}/naabu_${NAABU_VER}_linux_${PD_ARCH}.zip"; \
    unzip -j -o naabu.zip naabu -d /opt/scanners/bin; \
    \
    curl -fsSL -o nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${PD_ARCH}.zip"; \
    unzip -j -o nuclei.zip nuclei -d /opt/scanners/bin; \
    \
    curl -fsSL -o dnsx.zip \
      "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VER}/dnsx_${DNSX_VER}_linux_${PD_ARCH}.zip"; \
    unzip -j -o dnsx.zip dnsx -d /opt/scanners/bin; \
    \
    curl -fsSL -o ffuf.tar.gz \
      "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_${FFUF_ARCH}.tar.gz"; \
    tar -xzf ffuf.tar.gz -C /opt/scanners/bin ffuf; \
    \
    curl -fsSL -o gowitness \
      "https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VER}/gowitness-${GOWITNESS_VER}-linux-${GOWIT_ARCH}"; \
    install -m 0755 gowitness /opt/scanners/bin/gowitness; \
    \
    curl -fsSL -o ferox.zip \
      "https://github.com/epi052/feroxbuster/releases/download/v${FEROX_VER}/${FEROX_ARCH}-linux-feroxbuster.zip"; \
    unzip -j -o ferox.zip feroxbuster -d /opt/scanners/bin; \
    \
    chmod +x /opt/scanners/bin/*; \
    rm -rf /tmp/install/*

# wafw00f — ship module + wrapper so PYTHONPATH=/opt/scanners/pylib works on the shared volume
RUN pip3 install --no-cache-dir --break-system-packages wafw00f \
 && SITE="$(python3 -c 'import site; print(site.getsitepackages()[0])')" \
 && cp -a "$SITE"/wafw00f /opt/scanners/pylib/ \
 && cp -a "$SITE"/wafw00f-*.dist-info /opt/scanners/pylib/ 2>/dev/null || true \
 && printf '%s\n' '#!/bin/sh' \
      'DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"' \
      'export PYTHONPATH="${DIR}/pylib:${PYTHONPATH:-}"' \
      'exec python3 -m wafw00f "$@"' > /opt/scanners/bin/wafw00f \
 && chmod +x /opt/scanners/bin/wafw00f

# WhatWeb — not on RubyGems; install from GitHub + vendor gems onto the share volume
RUN set -eux; \
    curl -fsSL -o whatweb.tgz \
      "https://github.com/urbanadventurer/WhatWeb/archive/refs/tags/${WHATWEB_VER}.tar.gz"; \
    mkdir -p /opt/scanners/whatweb /opt/scanners/gems; \
    tar -xzf whatweb.tgz -C /opt/scanners/whatweb --strip-components=1; \
    gem install --no-document --install-dir /opt/scanners/gems addressable json ipaddr; \
    printf '%s\n' '#!/bin/sh' \
      'ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"' \
      'export GEM_HOME="$ROOT/gems"' \
      'export GEM_PATH="$ROOT/gems"' \
      'exec ruby "$ROOT/whatweb/whatweb" "$@"' > /opt/scanners/bin/whatweb; \
    chmod +x /opt/scanners/bin/whatweb /opt/scanners/whatweb/whatweb; \
    rm -f whatweb.tgz; \
    apt-get purge -y --auto-remove build-essential ruby-dev || true; \
    rm -rf /var/lib/apt/lists/* /root/.cache /tmp/*

# Default wordlist used by ExternalToolRunner when present
RUN printf '%s\n' \
      admin login api graphql swagger .env .git backup config dashboard portal \
      actuator health metrics swagger-ui robots.txt sitemap.xml wp-admin \
      phpinfo.php server-status id_rsa \
    > /opt/scanners/wordlists/common.txt

ENV PATH="/opt/scanners/bin:${PATH}"
ENV PYTHONPATH="/opt/scanners/pylib:${PYTHONPATH}"
ENV SCANNER_TOOLS_PATH=/opt/scanners/bin

COPY infrastructure/docker/scanners/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/scanners/bin/*

VOLUME ["/shared"]
ENTRYPOINT ["/entrypoint.sh"]
