# Passive Network Mapping Platform

Python prototype for a bachelor thesis on passive network mapping. The tool
turns passive flow records and traffic-derived metadata into explicit,
inspectable artifacts: normalized flows, host inventory, fingerprint
enrichment, a communication graph, criticality ranking, and a Markdown/PDF
report.

The implementation is intentionally stage-based. Each command can be run
independently against artifacts produced by earlier stages, which makes the
workflow easier to inspect, reproduce, and debug.

Graph edges represent observed client-to-service communications. They are
useful evidence of operational relationships, but they do not by themselves
prove a causal functional dependency.

## Repository Policy

This repository is code-first. It keeps source code and small sample inputs in
version control, while large datasets and generated outputs are expected to be
placed locally.

Tracked sample inputs:

- `data/flows_demo.csv`
- `data/cpe_map.sample.yaml`
- `data/iana-service-names-port-numbers.csv`

Ignored local data and outputs include:

- `data/raw/**`
- `data/run/**`
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

A standard Zeek installation supplies the base connection and protocol logs,
but JA3/JA3S and HASSH fields are added by separate Zeek packages or scripts.
Install and load the relevant packages in the Zeek site policy before expecting
those fingerprints from a raw PCAP. Custom scripts can also be supplied with
repeated `--zeek-script` options. Without them, the pipeline still consumes
`conn.log`, DNS, TLS SNI, and base SSH metadata, but the corresponding
fingerprint fields remain empty.

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

For the exact direct dependency versions used by the recorded Python 3.12
evaluation run:

```bash
python -m pip install -r requirements-evaluation.txt
```

Notebook users can additionally install `requirements-notebook.txt`.

## Pipeline Stages

The CLI entry point is `main.py`.

| Stage | Command | Main output |
| --- | --- | --- |
| Complete workflow | `run` | all stage outputs plus `run_manifest.json` |
| Ingest | `ingest` | Zeek/nfdump preprocessing outputs |
| Normalize | `normalize` | `flows.jsonl` |
| Inventory | `inventory` | `hosts.jsonl` |
| Enrich | `enrich` | `enriched_hosts.jsonl` |
| Analyze | `analyze` | `graph.json`, `edges.jsonl` |
| Criticality | `criticality` | `criticality.jsonl`, `criticality_top.json` |
| Export | `export` | `summary.json`, `host_metrics.jsonl`, `report.md`, optional `report.pdf` |

## One-Command Workflow

Use `run` with exactly one input mode: preprocessed input, normalized flows, or
raw PCAP/NetFlow:

```bash
python main.py run \
  --input data/flows_demo.csv \
  --output data/run/demo \
  --include-cidrs 10.0.0.0/8
```

Raw input example:

```bash
python main.py run \
  --pcap capture.pcap \
  --netflow nfcapd.202607280000 \
  --output data/run/production \
  --include-cidrs 192.0.2.0/24 \
  --drop-outside
```

The workflow writes `run_manifest.json` with source hashes, parameters,
dependency and external-tool information, stage timings, output counts, and
failure details. Individual stage commands remain available for inspection and
debugging.

When `--drop-outside` is selected, a communication is retained when at least
one endpoint belongs to the monitored ranges. Each normalized flow records the
scope status of both endpoints. Explicit `--exclude-cidrs` are stronger:
records touching an excluded range are always omitted and counted separately
in `normalization_stats.json`.

The one-command workflow resolves omitted scope options from `config.yaml` and
records the effective CIDRs in its manifest. `--drop-outside` requires at least
one effective include range; this avoids a silently ineffective boundary
filter.

## Thesis Evaluation Scenario

The thesis evaluation uses **CESNET Idle OS Traffic, version 1**:

```text
https://doi.org/10.5281/zenodo.15004766
```

Place the original downloaded archive at:

```text
data/cesnet-idle-os-traffic.zip
```

After placing the dataset locally, run:

```bash
python scripts/run_cesnet.py
```

The script creates:

- `data/run/cesnet/prepared/flows.jsonl`
- `data/run/cesnet/prepared/cesnet_ground_truth.jsonl`
- `data/run/cesnet/prepared/cesnet_preparation_manifest.json`
- `data/run/cesnet/normalized/flows.jsonl`
- `data/run/cesnet/normalized/normalization_stats.json`
- `data/run/cesnet/inventory/hosts.jsonl`
- `data/run/cesnet/enriched/enriched_hosts.jsonl`
- `data/run/cesnet/graph/graph.json`
- `data/run/cesnet/graph/analysis_stats.json`
- `data/run/cesnet/enriched/enrichment_manifest.json`
- `data/run/cesnet/criticality/criticality.jsonl`
- `data/run/cesnet/report/summary.json`
- `data/run/cesnet/report/report.md`
- `data/run/cesnet/report/report.pdf` if `pandoc` is available
- `data/run/cesnet/run_manifest.json`
- `data/run/cesnet/fingerprint_validation.json`

The preparation step streams `merged_tls.csv` directly from the ZIP, so the
2.37 GB archive does not need to be duplicated by extraction. An extracted
table can still be selected with `--input path/to/merged_tls.csv`. The adapter
writes its immutable output and labelled sidecar under `prepared/`; the
one-command workflow validates and scope-annotates those flows into
`normalized/`. Keeping both files preserves a verifiable preparation-to-run
hash chain. The source table contains labelled TLS observations, not complete
network flows. JA3 and SNI are retained as flow evidence, while OS labels, TLS
version, and ALPN are saved in the ground-truth sidecar. Addresses, ports,
timestamps, byte counts, and packet counts in the generated flow fixture are
explicitly synthetic. The generated preparation manifest records the dataset
DOI, licence, archive hash, selected ZIP member, row selection, output hashes,
and these limitations.

The compact Debian `flows.csv` member included by the appendix builder is an
unchanged upstream reference, not an input accepted by the generic CSV adapter.
Use the accompanying PCAP with Zeek to exercise the raw-input path.

After the pipeline run, `scripts/evaluate_cesnet_fingerprints.py` compares
client-side OS-CPE hypotheses with the retained CESNET OS-family labels. It
reports both coverage and an any-hypothesis label-match rate on covered rows;
the latter is explicitly not presented as hypothesis-level precision.
Application CPEs are not misreported as OS predictions.

## Known-Topology Correctness Scenario

The small tracked scenario validates endpoint direction, boundary scope,
service discovery, observed communication edges, and criticality against
explicit expected results:

```bash
python scripts/validate_ground_truth.py
```

Its machine-readable verdict is written to
`data/run/ground_truth/ground_truth_validation.json`. Unlike the CESNET
fixture, this scenario tests semantic correctness rather than scale.

## Manual CLI Example

The bundled `data/flows_demo.csv` can be used for a small local run:

```bash
python main.py run \
  --input data/flows_demo.csv \
  --output data/run/demo \
  --cpe-map data/cpe_map.sample.yaml
```

The equivalent explicit stage-by-stage workflow is:

```bash
mkdir -p data/run/demo-input
cp data/flows_demo.csv data/run/demo-input/flows_demo.csv
python main.py normalize --input data/run/demo-input --output data/run/demo/normalized
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
`cpe` field remains absent or empty. SNI is hostname/service evidence and is
never converted directly into a host CPE. Fingerprint-to-CPE results are
reported as hypotheses with endpoint role, confidence, mapping provenance, and
mapping-file SHA-256.

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
formats. The bundled script is a degree-only transport example, not a second
implementation of the built-in score. Organization-specific weights or YAML
rules can be implemented by an external command; the CLI does not itself
provide a `--rules` option. External execution has a configurable timeout and
fails the stage if the command, JSON contract, identifier set, or score values
are invalid; it never silently substitutes the built-in method. The built-in
scorer records whether betweenness was exact, deterministically sampled, or
skipped according to its graph-work estimate.

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
automatically when `matplotlib` is available. The figure set includes a
filtered communication map showing leading service destinations and a bounded
sample of their observed clients.

## Jupyter Workflow

The notebooks provide an interactive view of the same artifact-oriented
pipeline:

1. `notebooks/00_structure.ipynb` - repository and artifact overview
2. `notebooks/01_normalize.ipynb` - flow normalization
3. `notebooks/02_inventory.ipynb` - host and service inventory
4. `notebooks/03_enrich.ipynb` - fingerprint and CPE enrichment
5. `notebooks/04_analyze_graph.ipynb` - observed communication graph analysis
6. `notebooks/05_criticality_export.ipynb` - criticality and export
7. `notebooks/06_report_dashboard.ipynb` - chart and report dashboard

The notebook controls are UI-first: buttons run individual stages, preview
buttons inspect artifacts, and Top-N controls adjust displayed tables and
figures.

## Tests

Run the local unit and integration-style tests:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

For changes touching evaluation, graph analysis, enrichment, criticality,
reporting, or figures, also run:

```bash
python scripts/validate_ground_truth.py
python scripts/run_cesnet.py --no-pdf
```

The second command requires the local CESNET ZIP described above.

## Electronic Appendix

The appendix builder packages recorded outputs; it does not rerun the
evaluation. Build the deterministic archive after placing the verified
upstream dataset ZIP at `data/cesnet-idle-os-traffic.zip` and generating the
three output directories `data/run/ground_truth`, `data/run/cesnet`, and
`data/run/zeek_debian10` with the commands documented in this README:

```bash
python scripts/build_submission_archive.py
```

The archive is written to
`data/run/submission/passive-network-mapping-platform-appendix.zip`. It
contains the source, tests, notebooks, documentation, configuration, the
complete recorded machine-readable tabular-CESNET, controlled-correctness,
and raw-PCAP pipeline chains, the report figures, the complete unchanged
`merged_tls.csv` member used by the evaluation, and the compact Debian 10
PCAP used by the recorded Zeek integration run with its upstream metadata
and reference flows. The selected PCAP is about 2.16 MB and its reference
contains both TLS and DNS evidence. `APPENDIX_MANIFEST.json` records every
included file's size and SHA-256 hash.

The builder verifies the original CESNET archive checksum before extracting
only those small members. It deliberately excludes the complete 2.37 GB
third-party archive: the remaining captures are not consumed by the recorded
evaluation and remain available from the dataset DOI.

After extracting the submitted appendix, its packaged CESNET evaluation can be
rerun without downloading the full upstream archive:

```bash
python scripts/run_cesnet.py \
  --input data/evaluation/cesnet/merged_tls.csv \
  --no-pdf
```

On a system with Zeek and p0f installed, the packaged raw-PCAP scenario can
be rerun with:

```bash
python main.py run \
  --pcap data/evaluation/cesnet/debian10_traffic_sample.pcap \
  --output data/run/zeek_debian10 \
  --include-cidrs 10.0.2.0/24 \
  --include-cidrs fe80::/10 \
  --drop-outside \
  --zeek-bin /opt/zeek/bin/zeek \
  --p0f-bin /usr/sbin/p0f \
  --no-pdf
```

Use the corresponding executable paths for a different installation.

Public repository:

```text
https://github.com/nojpilot/passive-network-mapping-platform
```

## License

The source code of this prototype is distributed under the MIT License. See
`LICENSE`.

Third-party datasets and imported artifacts may have their own licensing terms.
Relevant notes are included in `THIRD_PARTY_NOTICES.md` and in the generated
appendix dataset notice.
