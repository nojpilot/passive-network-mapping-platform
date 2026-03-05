## Integrace prototypu z bakalářky (link-prediction, Zenodo 10548434)

Zdroj: https://zenodo.org/records/10548434 (MIT licencované doplňky k článku Identifikace závislostí pomocí link prediction).

Repozitář už obsahuje rozbalený kód v `data/prototype/link-prediction`.

### Požadavky

- Python ≤ 3.11 (PyTorch/torch_geometric zatím nepodporují 3.13)
- Závislosti z `data/prototype/link-prediction/requirements.txt` (torch, torch_geometric, scikit-learn, networkx, numpy, matplotlib, scipy).

Příklad instalace v odděleném venv (pokud máš python3.10/3.11 k dispozici):
```
python3.10 -m venv data/prototype/.venv
source data/prototype/.venv/bin/activate
pip install -r data/prototype/link-prediction/requirements.txt
```

### Běh prototypu na Cyber Czech datech

Použij wrapper `scripts/prototype_runner.py`, který jen volá původní kód (nic nepřepisujeme):
```
# připraví BT1-6 split a spustí correctness_evaluation()
PYTHONPATH=data/prototype/link-prediction \
  data/prototype/.venv/bin/python scripts/prototype_runner.py \
  --data-json data/raw/cyber_czech/cz.muni.csirt.IPFlowEntry/data.json \
  --mode correctness
```

Výstupy zůstanou v `data/prototype/link-prediction/correctness/` (txt+PDF) a dalších složkách prototypu.

#### Varianta Docker (když nechceš řešit Python na hostu)

```
# vyžaduje docker a stažený Cyber Czech dataset
scripts/run_prototype_docker.sh
```

Image se postaví z `Dockerfile.prototype` (Python 3.10 + torch) a spustí correctness_evaluation uvnitř kontejneru, výstupy se promítnou do `data/prototype/link-prediction`.

### Napojení na naši pipeline

- Pro kritičnost můžeš využít `main.py criticality --external-cmd` a posílat mu JSON payload (viz `README_external_criticality.md`). Pokud přidáš vlastní wrapper nad prototypem, stačí, aby četl stdin JSON a vracel JSON se skóre.
- Pro úplné převzetí metody link prediction by bylo potřeba do wrapperu doplnit inference části z prototypu (train_model → RandomForest → predikce závislostí). Kvůli závislosti na PyTorch to tady nespouštíme, ale kód je k dispozici v `data/prototype/link-prediction`.

### Poznámka pro závěrečnou práci

Použitý kód je z výše uvedené bakalářské práce / NOMS 2024 materiálů (MIT licence, autoři Sadlek/Husák/Čeleda). Při využití uveď citaci dle README v prototypu. My jsme kód jen zabalili a přidali wrapper, původní implementaci neměníme.
