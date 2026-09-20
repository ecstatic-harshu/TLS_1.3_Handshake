#!/usr/bin/env bash
#
# One-shot setup + launch for the Quantum-Safe Proxy live demo.
#
# What it does:
#   1. Vendors liboqs / liboqs-python (pinned commits) if missing —
#      the repo tracks them as submodule references without a
#      .gitmodules file, so they arrive as empty folders.
#   2. Builds the pqtls-middleware Docker image (compiles liboqs +
#      ML-KEM-768 / ML-DSA-65 bindings). First run only; slow (can be
#      5-15 minutes). Cached afterwards.
#   3. Launches dashboard/server.py, which starts the demo backend,
#      starts the proxy container, and serves the browser UI.
#
# Usage:
#   ./setup.sh
#
# Stop everything with Ctrl+C — the dashboard cleans up the backend
# process and the proxy container on exit.

set -euo pipefail

cd "$(dirname "$0")"

LIBOQS_COMMIT="5a1a854b0dc9f2141bdc771c555ee60c37950183"
LIBOQS_PYTHON_COMMIT="35eceb69d2b363cb0421085cf1ae1c682dee1acc"
IMAGE_TAG="pqtls-middleware:1.0.0"

echo "=========================================="
echo " Quantum-Safe Proxy — Demo Setup"
echo "=========================================="

# =====================================
# 1. PRE-FLIGHT CHECKS
# =====================================

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is required. Install Docker Desktop and re-run."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running. Start Docker Desktop and re-run."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required to run the dashboard."
  exit 1
fi

# =====================================
# 2. VENDOR liboqs / liboqs-python
# =====================================

vendor_repo() {
  local dir="$1"
  local url="$2"
  local commit="$3"

  if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    echo "==> $dir already present, skipping clone"
    return
  fi

  echo "==> Vendoring $dir (pinned commit ${commit:0:10})..."
  rm -rf "$dir"
  git clone --quiet "$url" "$dir"
  (cd "$dir" && git checkout --quiet "$commit")
}

vendor_repo "liboqs" "https://github.com/open-quantum-safe/liboqs.git" "$LIBOQS_COMMIT"
vendor_repo "liboqs-python" "https://github.com/open-quantum-safe/liboqs-python.git" "$LIBOQS_PYTHON_COMMIT"

# =====================================
# 3. BUILD DOCKER IMAGE
# =====================================

echo "==> Building $IMAGE_TAG (compiles liboqs — first run can take 5-15 minutes)..."
docker build -t "$IMAGE_TAG" .

# =====================================
# 4. LAUNCH DASHBOARD
# =====================================

echo "==> Launching live demo dashboard..."
echo ""

exec python3 -m dashboard.server
