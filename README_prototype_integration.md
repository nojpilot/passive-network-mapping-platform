# Link-Prediction Prototype Integration

This note documents how the project can call the external link-prediction prototype
used for dependency discovery experiments.

Source artifact: https://zenodo.org/records/10548434

The prototype source is not versioned in this repository. The repository is kept
code-first and does not include large third-party research artifacts or generated
outputs. If you need to run the prototype, download it locally and place it under:

```text
data/prototype/link-prediction
```

## Requirements

- Python 3.10 or 3.11. The prototype depends on PyTorch and torch-geometric,
  which are not suitable for the Python 3.13 environment used by the main project.
- Dependencies from `data/prototype/link-prediction/requirements.txt`.

Example isolated environment:

```bash
python3.10 -m venv data/prototype/.venv
source data/prototype/.venv/bin/activate
pip install -r data/prototype/link-prediction/requirements.txt
```

## Running the Prototype on Cyber Czech Data

Use `scripts/prototype_runner.py`. The wrapper prepares the expected input split
and calls the original prototype code without modifying it:

```bash
PYTHONPATH=data/prototype/link-prediction \
  data/prototype/.venv/bin/python scripts/prototype_runner.py \
  --data-json data/raw/cyber_czech/cz.muni.csirt.IPFlowEntry/data.json \
  --mode correctness
```

The prototype writes its outputs into its own directories, for example:

```text
data/prototype/link-prediction/correctness/
```

## Docker Variant

If you do not want to install the prototype dependencies on the host, use:

```bash
scripts/run_prototype_docker.sh
```

The script builds `Dockerfile.prototype` with Python 3.10 and the required ML
dependencies. Outputs are mounted back into `data/prototype/link-prediction`.

## Relationship to This Pipeline

The main passive mapping pipeline does not require the prototype. It remains an
optional integration point for experiments that compare graph-based dependency
prediction with the deterministic pipeline outputs.

For node criticality, `main.py criticality --external-cmd` can send a JSON graph
payload to any external tool. See `README_external_criticality.md` for the exact
interface. A custom wrapper around the prototype only needs to read JSON from
stdin and return JSON scores on stdout.

Full reuse of the link-prediction method would require adding an inference
wrapper around the prototype training and prediction code. That is intentionally
kept outside the core CLI because it brings a separate PyTorch-based dependency
stack.

## Thesis Note

The prototype comes from the referenced thesis and NOMS 2024 materials. When it
is used for experiments, cite the original source according to its README. This
repository only provides a wrapper and does not modify the original
implementation.
