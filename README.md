# Passive Network Mapping Platform

## Rychlý start (Cyber Czech demo)

1. Stáhni dataset Cyber Czech (NetFlow/IPFIX):
   ```
   scripts/fetch_cyber_czech.sh
   ```
2. Spusť end-to-end pipeline:
   ```
   scripts/smoke_cyber_czech.sh
   ```
   Výstupy:
   - `data/run/cyber_czech/normalized/flows.jsonl`
   - `data/run/cyber_czech/inventory/hosts.jsonl`
   - `data/run/cyber_czech/enriched/enriched_hosts.jsonl`
   - `data/run/cyber_czech/graph/graph.json`
   - `data/run/cyber_czech/criticality/criticality_top.json`

## Externí nástroje a integrace

- **CPE mapování**: enrich přijme `--cpe-map path/to/cpe_map.yaml` (vzor `data/cpe_map.sample.yaml`). Pokud mapu nedáš, pole `cpe` zůstane prázdné.
- **Kritičnost**: příkaz `criticality` má flag `--external-cmd "tool ..."`, kterému pošle JSON payload (viz `README_external_criticality.md`); případně použij stub `scripts/external_criticality_stub.py` pro ověření.
- **Dump vstupu**: `--dump-input path.json` uloží payload pro externí nástroj.

## Interaktivní Jupyter report (grafy + PDF)

- Otevři `notebooks/06_report_dashboard.ipynb`.
- Notebook zobrazí tlačítka:
  - `Generate Charts`: vytvoří PNG grafy v `data/run/notebook/report/assets/`
  - `Export Report`: vygeneruje `summary.json`, `report.md` a volitelně `report.pdf`
  - `Generate + Export`: obojí jedním klikem
- Seznam obrázků se ukládá do `data/run/notebook/report/figures_manifest.json` a export ho vloží do reportu.
- CLI export podporuje stejný manifest:
  ```
  python main.py export \
    --hosts data/run/notebook/inventory/hosts.jsonl \
    --graph data/run/notebook/graph/graph.json \
    --criticality data/run/notebook/criticality/criticality.jsonl \
    --output data/run/notebook/report \
    --pdf \
    --figures-manifest data/run/notebook/report/figures_manifest.json
  ```

## Interaktivní notebook controls

- Notebooky `01-05` jsou připravené jako UI-first workflow:
  - tlačítko pro spuštění kroku,
  - tlačítko pro preview,
  - `Top-N` dropdown pro tabulky/grafy.
- Kódové buňky mají metadata pro skrytí zdroje (`source_hidden`), takže v notebooku vidíš primárně ovládací panel a výstupy.

## Notebook workflow (doporučene poradi)

1. `notebooks/00_structure.ipynb` - orientace, co kam patri.
2. `notebooks/01_normalize.ipynb` - normalizace flow.
3. `notebooks/02_inventory.ipynb` - inventar hostu/sluzeb.
4. `notebooks/03_enrich.ipynb` - fingerprinty/CPE.
5. `notebooks/04_analyze_graph.ipynb` - graf zavislosti.
6. `notebooks/05_criticality_export.ipynb` - kriticnost + report + grafy.
7. `notebooks/06_report_dashboard.ipynb` - interaktivni tlacitka pro rychlou regeneraci reportu.

## Prototyp link-prediction (bakalářka)

Pro původní kód z Zenodo 10548434 (MIT):

- **Lokální Python 3.10/3.11**: nainstaluj závislosti z `data/prototype/link-prediction/requirements.txt` a spusť wrapper:
  ```
  PYTHONPATH=data/prototype/link-prediction \
    python scripts/prototype_runner.py \
    --data-json data/raw/cyber_czech/cz.muni.csirt.IPFlowEntry/data.json \
    --mode correctness
  ```
- **Docker varianta** (pokud máš jen Python 3.13 na hostu):
  ```
  scripts/run_prototype_docker.sh
  ```
  Postaví image z `Dockerfile.prototype` (Python 3.10 + torch) a spustí correctness_evaluation v kontejneru. Výstupy se uloží do `data/prototype/link-prediction/correctness/`.
