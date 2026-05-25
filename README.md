# Passive Network Mapping Platform

Python prototype for a bachelor thesis on passive network mapping. The tool
turns passive flow records and traffic-derived metadata into explicit,
inspectable artifacts: normalized flows, host inventory, fingerprint
enrichment, a communication graph, criticality ranking, and a Markdown/PDF
report.

The implementation is intentionally stage-based. Each command can be run
independently against artifacts produced by earlier stages, which makes the
workflow easier to inspect, reproduce, and debug.

## Repository Policy

This repository is code-first. It keeps source code and small sample inputs in
version control, while large datasets and generated outputs are expected to be
placed locally.

Tracked sample inputs:

- `data/flows_demo.csv`
- `data/cpe_map.sample.yaml`
- `data/nmap-services/nmap-services`

Ignored local data and outputs include:

- `data/raw/**`
- `data/run/**`
- `data/prototype/**`
- packet captures such as `*.pcap` and `*.pcapng`
- archives such as `*.zip`, `*.tgz`, and `*.tar.gz`

If you want to reproduce the larger demos, place or download the required data
into the expected local paths first.

## Requirements

Runtime requirements:

- Python 3.10 or newer
- packages from `requirements.txt`

Optional external tools:

- `pandoc` for PDF report generation
- `zeek` for PCAP preprocessing
- `nfdump` for NetFlow/IPFIX preprocessing
- `p0f` for optional passive OS fingerprinting
- Docker for the optional link-prediction prototype wrapper

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

## Pipeline Stages

The CLI entry point is `main.py`.

| Stage | Command | Main output |
| --- | --- | --- |
| Ingest | `ingest` | Zeek/nfdump preprocessing outputs |
| Normalize | `normalize` | `flows.jsonl` |
| Inventory | `inventory` | `hosts.jsonl` |
| Enrich | `enrich` | `enriched_hosts.jsonl` |
| Analyze | `analyze` | `graph.json`, `edges.jsonl` |
| Criticality | `criticality` | `criticality.jsonl`, `criticality_top.json` |
| Export | `export` | `summary.json`, `host_metrics.jsonl`, `report.md`, optional `report.pdf` |

## Thesis Evaluation Scenario

The thesis evaluation uses the CESNET TLS dataset at this local path:

```text
data/cesnet-idle-os-traffic/merged_tls.csv
```

After placing the dataset locally, run:

```bash
scripts/smoke_cesnet.sh
```

The script creates:

- `data/run/cesnet/normalized/flows.jsonl`
- `data/run/cesnet/inventory/hosts.jsonl`
- `data/run/cesnet/enriched/enriched_hosts.jsonl`
- `data/run/cesnet/graph/graph.json`
- `data/run/cesnet/criticality/criticality.jsonl`
- `data/run/cesnet/report/summary.json`
- `data/run/cesnet/report/report.md`
- `data/run/cesnet/report/report.pdf` if `pandoc` is available

## Cyber Czech Demo

Download the Cyber Czech IPFlow dataset:

```bash
scripts/fetch_cyber_czech.sh
```

Run the end-to-end workflow:

```bash
scripts/smoke_cyber_czech.sh
```

The script creates outputs under `data/run/cyber_czech/`, including normalized
flows, inventory, enrichment, graph, criticality, and report artifacts.

## Manual CLI Example

The bundled `data/flows_demo.csv` can be used for a small local run:

```bash
mkdir -p data/run/demo/input
cp data/flows_demo.csv data/run/demo/input/flows_demo.csv

python main.py normalize --input data/run/demo/input --output data/run/demo/normalized
python main.py inventory --flows data/run/demo/normalized --output data/run/demo/inventory
python main.py enrich --flows data/run/demo/normalized --output data/run/demo/enriched --cpe-map data/cpe_map.sample.yaml
python main.py analyze \
  --flows data/run/demo/normalized \
  --output data/run/demo/graph \
  --hosts data/run/demo/inventory/hosts.jsonl \
  --enriched-hosts data/run/demo/enriched/enriched_hosts.jsonl
python main.py criticality \
  --graph data/run/demo/graph \
  --output data/run/demo/criticality \
  --hosts data/run/demo/enriched/enriched_hosts.jsonl
python main.py export \
  --hosts data/run/demo/inventory/hosts.jsonl \
  --graph data/run/demo/graph/graph.json \
  --criticality data/run/demo/criticality/criticality.jsonl \
  --enriched data/run/demo/enriched/enriched_hosts.jsonl \
  --output data/run/demo/report
```

## Optional Integrations

### CPE Mapping

The `enrich` command accepts an optional fingerprint-to-CPE mapping:

```bash
python main.py enrich \
  --flows data/run/demo/normalized \
  --output data/run/demo/enriched \
  --cpe-map data/cpe_map.sample.yaml
```

If no mapping is provided, the enrichment output is still generated, but the
`cpe` field remains absent or empty.

### External Criticality Tool

The `criticality` command can delegate ranking to an external command that
reads JSON from standard input and returns JSON on standard output:

```bash
python main.py criticality \
  --graph data/run/demo/graph \
  --output data/run/demo/criticality \
  --external-cmd "python scripts/external_criticality_stub.py" \
  --dump-input data/run/demo/criticality/criticality_input.json
```

See `README_external_criticality.md` for the expected payload and response
formats.

### Report Figures

The export step can include a figure manifest:

```bash
python main.py export \
  --hosts data/run/notebook/inventory/hosts.jsonl \
  --graph data/run/notebook/graph/graph.json \
  --criticality data/run/notebook/criticality/criticality.jsonl \
  --output data/run/notebook/report \
  --pdf \
  --figures-manifest data/run/notebook/report/figures_manifest.json
```

If no manifest is supplied, the exporter attempts to generate report figures
automatically when `matplotlib` is available.

## Jupyter Workflow

The notebooks provide an interactive view of the same artifact-oriented
pipeline:

1. `notebooks/00_structure.ipynb` - repository and artifact overview
2. `notebooks/01_normalize.ipynb` - flow normalization
3. `notebooks/02_inventory.ipynb` - host and service inventory
4. `notebooks/03_enrich.ipynb` - fingerprint and CPE enrichment
5. `notebooks/04_analyze_graph.ipynb` - dependency graph analysis
6. `notebooks/05_criticality_export.ipynb` - criticality and export
7. `notebooks/06_report_dashboard.ipynb` - chart and report dashboard

The notebook controls are UI-first: buttons run individual stages, preview
buttons inspect artifacts, and Top-N controls adjust displayed tables and
figures.

## Link-Prediction Prototype

The original link-prediction prototype referenced by the thesis is a large
external artifact and is not part of a clean clone of this repository. The
integration notes are in `README_prototype_integration.md`.

After placing the prototype under `data/prototype/link-prediction`, either run
it locally with Python 3.10/3.11:

```bash
PYTHONPATH=data/prototype/link-prediction \
  python scripts/prototype_runner.py \
  --data-json data/raw/cyber_czech/cz.muni.csirt.IPFlowEntry/data.json \
  --mode correctness
```

or use the Docker wrapper:

```bash
scripts/run_prototype_docker.sh
```

## Tests

Run the local unit and smoke-style tests:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

For changes touching evaluation, graph analysis, enrichment, criticality,
reporting, or figures, also run:

```bash
scripts/smoke_cesnet.sh
```

## Electronic Appendix

This repository is prepared as the electronic appendix for the bachelor thesis.
The submitted archive should contain the source code, README documentation,
configuration files, helper scripts, tests, small sample inputs, selected
generated reports or figures, and licensing information.

Large external datasets and third-party artifacts are not necessarily included
in a clean repository snapshot. The documentation and scripts describe the
expected local paths for those inputs.

Public repository:

```text
https://github.com/nojpilot/passive-network-mapping-platform
```

## License

The source code of this prototype is distributed under the MIT License. See
`LICENSE`.

Third-party datasets, external prototypes, and other imported artifacts may have
their own licensing terms. Relevant notes are included with the corresponding
integration documentation.
