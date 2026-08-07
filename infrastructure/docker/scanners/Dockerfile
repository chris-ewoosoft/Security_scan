# Multi-stage image that builds security scanner CLIs into /opt/scanners/bin
# Used by scripts/install-scanners.sh and docker-compose "scanners" service.

FROM golang:1.22-bookworm AS go-tools
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap-dev gcc g++ make git ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
ENV CGO_ENABLED=1
WORKDIR /src
# Install ProjectDiscovery + ffuf + gowitness via go
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest
RUN go install -v github.com/sensepost/gowitness@latest

FROM rust:1-bookworm AS rust-tools
RUN cargo install feroxbuster --locked

FROM python:3.12-slim-bookworm AS py-tools
RUN pip install --no-cache-dir wafw00f \
 && mkdir -p /out/bin /out/pylib \
 && SITE=$(python3 -c "import site; print(site.getsitepackages()[0])") \
 && cp -a "$SITE"/wafw00f /out/pylib/ \
 && cp -a "$SITE"/wafw00f-*.dist-info /out/pylib/ 2>/dev/null || true \
 && printf '%s\n' '#!/usr/bin/env bash' \
      'DIR="$(cd "$(dirname "$0")/.." && pwd)"' \
      'export PYTHONPATH="${DIR}/pylib:${PYTHONPATH:-}"' \
      'exec python3 -m wafw00f "$@"' > /out/bin/wafw00f \
 && chmod +x /out/bin/wafw00f

FROM ruby:3.3-slim-bookworm AS ruby-tools
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
 && gem install whatweb --no-document \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /out/bin \
 && WHATWEB_BIN=$(find /usr/local/bundle /usr/local/bin -type f -name whatweb 2>/dev/null | head -1) \
 && if [ -n "$WHATWEB_BIN" ]; then cp "$WHATWEB_BIN" /out/bin/whatweb; \
    else printf '%s\n' '#!/usr/bin/env bash' 'exec ruby -S whatweb "$@"' > /out/bin/whatweb; fi \
 && chmod +x /out/bin/whatweb

FROM debian:bookworm-slim AS final
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libpcap0.8 curl unzip python3 ruby \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/scanners/bin /opt/scanners/wordlists /opt/scanners/nuclei-templates /opt/scanners/pylib

COPY --from=go-tools /go/bin/naabu /opt/scanners/bin/naabu
COPY --from=go-tools /go/bin/nuclei /opt/scanners/bin/nuclei
COPY --from=go-tools /go/bin/dnsx /opt/scanners/bin/dnsx
COPY --from=go-tools /go/bin/ffuf /opt/scanners/bin/ffuf
COPY --from=go-tools /go/bin/gowitness /opt/scanners/bin/gowitness
COPY --from=rust-tools /usr/local/cargo/bin/feroxbuster /opt/scanners/bin/feroxbuster
COPY --from=py-tools /out/bin/wafw00f /opt/scanners/bin/wafw00f
COPY --from=py-tools /out/pylib/ /opt/scanners/pylib/
COPY --from=ruby-tools /usr/local/bundle /usr/local/bundle
COPY --from=ruby-tools /out/bin/whatweb /opt/scanners/bin/whatweb

RUN printf '%s\n' \
      admin login api graphql swagger .env .git backup config dashboard portal \
      actuator health metrics swagger-ui robots.txt sitemap.xml wp-admin \
      phpinfo.php server-status id_rsa \
    > /opt/scanners/wordlists/common.txt

ENV PATH="/opt/scanners/bin:${PATH}"
ENV PYTHONPATH="/opt/scanners/pylib:${PYTHONPATH}"
ENV GEM_HOME="/usr/local/bundle"
ENV BUNDLE_PATH="/usr/local/bundle"
ENV SCANNER_TOOLS_PATH=/opt/scanners/bin

COPY infrastructure/docker/scanners/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/scanners/bin/*
ENTRYPOINT ["/entrypoint.sh"]
