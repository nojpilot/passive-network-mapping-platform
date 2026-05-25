#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT
INPUT_CSV="${REPO_ROOT}/data/cesnet-idle-os-traffic/merged_tls.csv"
RUN_DIR="${REPO_ROOT}/data/run/cesnet"
NORM_DIR="${RUN_DIR}/normalized"
INV_DIR="${RUN_DIR}/inventory"
ENR_DIR="${RUN_DIR}/enriched"
GRAPH_DIR="${RUN_DIR}/graph"
CRIT_DIR="${RUN_DIR}/criticality"
EXPORT_DIR="${RUN_DIR}/report"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python"
fi

if [ ! -f "${INPUT_CSV}" ]; then
  echo "[cesnet] Missing ${INPUT_CSV}"
  exit 1
fi

mkdir -p "${NORM_DIR}"

echo "[cesnet] Generating flows.jsonl from ${INPUT_CSV} (synthetic IPs, preserved JA3/SNI)..."
"${PYTHON_BIN}" - <<'PY'
import csv, json, itertools, os
repo = os.environ.get("REPO_ROOT") or os.getcwd()
input_csv = os.path.join(repo, "data", "cesnet-idle-os-traffic", "merged_tls.csv")
out_path = os.path.join(repo, "data", "run", "cesnet", "normalized", "flows.jsonl")
src_ips = (f"10.20.{i//250}.{i%250+1}" for i in itertools.count(0))
dst_base = {}

records = []
with open(input_csv, newline='', encoding='utf-8') as fh:
    reader = csv.DictReader(fh)
    for i, row in enumerate(reader):
        if i >= 2000:  # larger sample for the report
            break
        sni = row.get('string TLS_SNI') or row.get('TLS_SNI') or ''
        ja3 = row.get('bytes TLS_JA3') or row.get('TLS_JA3') or ''
        src_ip = next(src_ips)
        if sni not in dst_base:
            dst_base[sni] = f"198.51.100.{len(dst_base)%250+1}"
        dst_ip = dst_base[sni]
        rec = {
            "ts": 1729772000.0 + i,
            "src_ip": src_ip,
            "src_port": 40000 + (i % 20000),
            "dst_ip": dst_ip,
            "dst_port": 443,
            "proto": "tcp",
            "bytes": 50000,
            "pkts": 50,
        }
        if ja3:
            rec["ja3"] = ja3
        if sni:
            rec["sni"] = sni
        records.append(rec)

os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w", encoding="utf-8") as fw:
    for r in records:
        fw.write(json.dumps(r) + "\n")
print(f"[cesnet] wrote {len(records)} flows -> {out_path}")
PY

echo "[cesnet] inventory..."
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" inventory --flows "${NORM_DIR}" --output "${INV_DIR}"

echo "[cesnet] enrich..."
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" enrich --flows "${NORM_DIR}" --output "${ENR_DIR}" --cpe-map "${REPO_ROOT}/data/cpe_map.sample.yaml"

echo "[cesnet] analyze..."
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" analyze --flows "${NORM_DIR}" --output "${GRAPH_DIR}" --hosts "${INV_DIR}/hosts.jsonl" --enriched-hosts "${ENR_DIR}/enriched_hosts.jsonl"

echo "[cesnet] criticality..."
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" criticality --graph "${GRAPH_DIR}" --output "${CRIT_DIR}" --hosts "${ENR_DIR}/enriched_hosts.jsonl" --dump-input "${CRIT_DIR}/criticality_input.json"

echo "[cesnet] export..."
"${PYTHON_BIN}" "${REPO_ROOT}/main.py" export --hosts "${INV_DIR}/hosts.jsonl" --graph "${GRAPH_DIR}/graph.json" --criticality "${CRIT_DIR}/criticality.jsonl" --output "${EXPORT_DIR}" --title "Cesnet TLS Report" --pdf --enriched "${ENR_DIR}/enriched_hosts.jsonl"

if [ "${RUN_PROTOTYPE:-0}" = "1" ]; then
  echo "[cesnet] Running prototype (docker)..."
  if command -v docker >/dev/null 2>&1; then
    "${REPO_ROOT}/scripts/run_prototype_docker.sh"
  else
    echo "[cesnet] Docker is not available, prototype was not started."
  fi
else
  echo "[cesnet] Prototype skipped. Set RUN_PROTOTYPE=1 to run it."
fi

echo "[cesnet] Done. Outputs are in ${RUN_DIR}"
