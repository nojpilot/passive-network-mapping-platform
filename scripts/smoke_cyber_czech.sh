#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW_JSON="${REPO_ROOT}/data/raw/cyber_czech/cz.muni.csirt.IPFlowEntry/data.json"
FETCH_SCRIPT="${REPO_ROOT}/scripts/fetch_cyber_czech.sh"

if [ ! -f "${RAW_JSON}" ]; then
  echo "[smoke] Cyber Czech dataset nenalezen, spouštím fetch skript..."
  "${FETCH_SCRIPT}"
fi

if [ ! -f "${RAW_JSON}" ]; then
  echo "[smoke] Data stále chybí (${RAW_JSON}), ukončuji."
  exit 1
fi

RUN_DIR="${REPO_ROOT}/data/run/cyber_czech"
NORM_DIR="${RUN_DIR}/normalized"
INV_DIR="${RUN_DIR}/inventory"
ENRICH_DIR="${RUN_DIR}/enriched"
GRAPH_DIR="${RUN_DIR}/graph"
CRIT_DIR="${RUN_DIR}/criticality"
EXPORT_DIR="${RUN_DIR}/report"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python"
fi

echo "[smoke] normalize → inventory → enrich → analyze → criticality → export"
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" normalize --input "$(dirname "${RAW_JSON}")" --output "${NORM_DIR}"
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" inventory --flows "${NORM_DIR}" --output "${INV_DIR}"
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" enrich --flows "${NORM_DIR}" --output "${ENRICH_DIR}" --cpe-map "${REPO_ROOT}/data/cpe_map.sample.yaml"
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" analyze --flows "${NORM_DIR}" --output "${GRAPH_DIR}" --hosts "${INV_DIR}/hosts.jsonl" --enriched-hosts "${ENRICH_DIR}/enriched_hosts.jsonl"
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" criticality --graph "${GRAPH_DIR}" --output "${CRIT_DIR}" --hosts "${ENRICH_DIR}/enriched_hosts.jsonl" --dump-input "${CRIT_DIR}/criticality_input.json"
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" export --hosts "${INV_DIR}/hosts.jsonl" --graph "${GRAPH_DIR}/graph.json" --criticality "${CRIT_DIR}/criticality.jsonl" --output "${EXPORT_DIR}" --title "Cyber Czech Report" --pdf --enriched "${ENRICH_DIR}/enriched_hosts.jsonl"

if [ "${RUN_PROTOTYPE:-0}" = "1" ]; then
  echo "[smoke] Spouštím prototyp (docker) nad Cyber Czech..."
  if command -v docker >/dev/null 2>&1; then
    "${REPO_ROOT}/scripts/run_prototype_docker.sh"
  else
    echo "[smoke] Docker není k dispozici, prototyp se nespustil."
  fi
else
  echo "[smoke] Prototyp přeskočen (nastav RUN_PROTOTYPE=1 pro spuštění)."
fi

echo "[smoke] Hotovo."
echo "  Flows:      ${NORM_DIR}/flows.jsonl"
echo "  Hosts:      ${INV_DIR}/hosts.jsonl"
echo "  Enriched:   ${ENRICH_DIR}/enriched_hosts.jsonl"
echo "  Graph:      ${GRAPH_DIR}/graph.json"
echo "  Criticality:${CRIT_DIR}/criticality_top.json"
echo "  Report:     ${EXPORT_DIR}/report.{md,pdf}"
