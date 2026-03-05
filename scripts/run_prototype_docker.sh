#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IMAGE_NAME="pmmap-prototype:latest"
DATA_JSON="${REPO_ROOT}/data/raw/cyber_czech/cz.muni.csirt.IPFlowEntry/data.json"

if [ ! -f "${DATA_JSON}" ]; then
  echo "DATA_JSON ${DATA_JSON} neexistuje. Spusť nejdřív scripts/fetch_cyber_czech.sh."
  exit 1
fi

echo "[prototype] Build Docker image (Python 3.10 + torch)..."
docker build -f "${REPO_ROOT}/Dockerfile.prototype" -t "${IMAGE_NAME}" "${REPO_ROOT}"

echo "[prototype] Running correctness_evaluation v kontejneru..."
docker run --rm \
  -v "${REPO_ROOT}/data/raw/cyber_czech:/app/data/raw/cyber_czech:ro" \
  -v "${REPO_ROOT}/data/prototype/link-prediction:/app/link-prediction" \
  -v "${REPO_ROOT}/scripts:/app/scripts:ro" \
  "${IMAGE_NAME}" \
  python /app/scripts/prototype_runner.py --data-json /app/data/raw/cyber_czech/cz.muni.csirt.IPFlowEntry/data.json --mode correctness

echo "[prototype] Hotovo. Výsledky jsou v data/prototype/link-prediction/correctness/ (na hostu)."
