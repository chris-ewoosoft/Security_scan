#!/usr/bin/env bash
# Build scanner CLI image and publish binaries for local / Docker API use.
# Usage:
#   ./scripts/install-scanners.sh           # extract to ./tools/scanners
#   ./scripts/install-scanners.sh --compose # also start compose scanners service
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/tools/scanners"
IMAGE="${SCANNERS_IMAGE:-securityportal-scanners:latest}"
MODE="${1:-}"

mkdir -p "${OUT}"

echo "==> Building scanners image (${IMAGE})"
docker build -t "${IMAGE}" -f "${ROOT}/infrastructure/docker/scanners/Dockerfile" "${ROOT}"

echo "==> Extracting binaries to ${OUT}"
CID="$(docker create -e SCANNERS_ONESHOT=1 -e SCANNER_SHARE_DIR=/shared "${IMAGE}")"
cleanup() { docker rm -f "${CID}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker start -a "${CID}" || true
docker cp "${CID}:/opt/scanners/bin" "${OUT}/"
docker cp "${CID}:/opt/scanners/wordlists" "${OUT}/" 2>/dev/null || mkdir -p "${OUT}/wordlists"
docker cp "${CID}:/opt/scanners/pylib" "${OUT}/" 2>/dev/null || true
docker cp "${CID}:/opt/scanners/whatweb" "${OUT}/" 2>/dev/null || true
docker cp "${CID}:/opt/scanners/gems" "${OUT}/" 2>/dev/null || true

# Make sure scripts are executable on host (Linux/macOS/Git Bash)
find "${OUT}/bin" -type f -exec chmod +x {} \; 2>/dev/null || true
# Replace broken self-symlinks (e.g. wafw00f -> wafw00f) if extraction raced
# Always rewrite wafw00f wrapper (avoids broken self-symlinks / python -m without __main__)
printf '%s\n' '#!/bin/sh' \
  'DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"' \
  'export PYTHONPATH="${DIR}/pylib:${PYTHONPATH:-}"' \
  'if [ -x "${DIR}/pylib/bin/wafw00f" ]; then exec "${DIR}/pylib/bin/wafw00f" "$@"; fi' \
  'exec python3 - "$@" <<'"'"'PY'"'" \
  'import sys' \
  'from wafw00f.main import main' \
  'sys.argv = ["wafw00f", *sys.argv[1:]]' \
  'raise SystemExit(main())' \
  'PY' > "${OUT}/bin/wafw00f"
chmod +x "${OUT}/bin/wafw00f"
chmod +x "${OUT}/pylib/bin/wafw00f" 2>/dev/null || true

echo "==> Tools installed:"
ls -la "${OUT}/bin" || true

cat > "${OUT}/env.sh" <<EOF
# Source this before \`dotnet run\` so ExternalToolRunner finds CLIs:
#   source tools/scanners/env.sh
export SCANNER_TOOLS_PATH="$(cd "${OUT}/bin" && pwd)"
export PATH="\${SCANNER_TOOLS_PATH}:\${PATH}"
export PYTHONPATH="$(cd "${OUT}/pylib" 2>/dev/null && pwd):\${PYTHONPATH:-}"
export NUCLEI_TEMPLATES_PATH="$(cd "${OUT}/nuclei-templates" 2>/dev/null && pwd || echo "")"
EOF

echo
echo "Local API:"
echo "  source tools/scanners/env.sh"
echo "  cd src/services/SecurityPortal.API && dotnet run"
echo
echo "Docker Compose:"
echo "  docker compose up -d --build scanners api nginx"

if [[ "${MODE}" == "--compose" ]]; then
  echo "==> Starting compose scanners + recreating api"
  (cd "${ROOT}" && docker compose up -d --build scanners && docker compose up -d --force-recreate api)
fi

echo "Done."
