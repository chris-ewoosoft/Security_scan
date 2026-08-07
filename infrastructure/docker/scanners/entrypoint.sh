#!/usr/bin/env bash
set -euo pipefail

DEST="${SCANNER_SHARE_DIR:-/shared}"
SRC="/opt/scanners"

echo "[scanners] syncing tools from ${SRC} -> ${DEST}"
mkdir -p "${DEST}/bin" "${DEST}/wordlists" "${DEST}/pylib" "${DEST}/nuclei-templates" "${DEST}/whatweb" "${DEST}/gems"

if [[ -d "${SRC}/bin" ]]; then
  cp -a "${SRC}/bin/." "${DEST}/bin/"
fi
if [[ -d "${SRC}/wordlists" ]]; then
  cp -a "${SRC}/wordlists/." "${DEST}/wordlists/"
fi
if [[ -d "${SRC}/pylib" ]]; then
  cp -a "${SRC}/pylib/." "${DEST}/pylib/"
fi
if [[ -d "${SRC}/whatweb" ]]; then
  cp -a "${SRC}/whatweb/." "${DEST}/whatweb/"
fi
if [[ -d "${SRC}/gems" ]]; then
  cp -a "${SRC}/gems/." "${DEST}/gems/"
fi

# Pre-fetch nuclei templates when network allows (best-effort)
if command -v nuclei >/dev/null 2>&1; then
  echo "[scanners] updating nuclei templates..."
  nuclei -update-templates -ud "${DEST}/nuclei-templates" >/tmp/nuclei-update.log 2>&1 \
    || echo "[scanners] nuclei template update skipped (see /tmp/nuclei-update.log)"
fi

echo "[scanners] installed binaries:"
ls -la "${DEST}/bin" || true

if [[ "${SCANNERS_ONESHOT:-0}" == "1" ]]; then
  echo "[scanners] oneshot complete"
  exit 0
fi

echo "[scanners] idle — volume ready for API (SCANNER_TOOLS_PATH=${DEST}/bin)"
exec sleep infinity
