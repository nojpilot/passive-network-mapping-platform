#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${REPO_ROOT}/data/raw/cyber_czech"
ARCHIVE="${TARGET_DIR}/cz.muni.csirt.IPFlowEntry.tgz"
URL="https://zenodo.org/record/3746129/files/cz.muni.csirt.IPFlowEntry.tgz?download=1"

mkdir -p "${TARGET_DIR}"

if [ ! -f "${ARCHIVE}" ]; then
  echo "[fetch] Stahuji Cyber Czech IPFlow dataset → ${ARCHIVE}"
  curl -L "${URL}" -o "${ARCHIVE}"
else
  echo "[fetch] Archiv už existuje: ${ARCHIVE}"
fi

if [ ! -d "${TARGET_DIR}/cz.muni.csirt.IPFlowEntry" ]; then
  echo "[fetch] Rozbaluji archiv..."
  tar -xzf "${ARCHIVE}" -C "${TARGET_DIR}"
fi

if [ -f "${TARGET_DIR}/cz.muni.csirt.IPFlowEntry/data.json.gz" ] && [ ! -f "${TARGET_DIR}/cz.muni.csirt.IPFlowEntry/data.json" ]; then
  echo "[fetch] Rozbaluji data.json.gz..."
  gunzip -kf "${TARGET_DIR}/cz.muni.csirt.IPFlowEntry/data.json.gz"
fi

echo "[fetch] Připravený soubor: ${TARGET_DIR}/cz.muni.csirt.IPFlowEntry/data.json"
