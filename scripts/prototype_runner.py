#!/usr/bin/env python
"""
Wrapper nad prototypem (link-prediction) z https://zenodo.org/records/10548434.

Čte původní Cyber Czech data.json, připraví per-team vstupy a spustí correctness evaluation
(tj. původní kód bez úprav). Vyžaduje Python ≤3.11 a závislosti z
data/prototype/link-prediction/requirements.txt (PyTorch/torch_geometric).
"""

from __future__ import annotations

import argparse
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
PROTO_ROOT = os.path.join(REPO_ROOT, "data", "prototype", "link-prediction")

sys.path.insert(0, PROTO_ROOT)


def main():
    parser = argparse.ArgumentParser(description="Spusť Python prototyp (link-prediction) z bakalářky.")
    parser.add_argument(
        "--data-json",
        default=os.path.join(REPO_ROOT, "data", "raw", "cyber_czech", "cz.muni.csirt.IPFlowEntry", "data.json"),
        help="Cesta k původnímu data.json z Cyber Czech (bidirectional flows).",
    )
    parser.add_argument(
        "--mode",
        choices=["prepare", "correctness"],
        default="correctness",
        help="prepare = jen vytvoř split pro BT1-6; correctness = spustí correctness_evaluation().",
    )
    args = parser.parse_args()

    try:
        from data_acquisition import create_files_for_blue_teams
        from evaluation import correctness_evaluation
    except Exception as exc:
        sys.stderr.write(
            f"Nelze importovat prototyp. Ujisti se, že běžíš s Pythonem ≤3.11 a máš nainstalované "
            f"závislosti z {os.path.join(PROTO_ROOT, 'requirements.txt')} (torch/torch_geometric atd.). "
            f"Chyba: {exc}\n"
        )
        sys.exit(1)

    if not os.path.isfile(args.data_json):
        sys.stderr.write(f"Soubor {args.data_json} neexistuje – zadej cestu k původnímu data.json.\n")
        sys.exit(1)

    os.chdir(PROTO_ROOT)
    print(f"[prototype] Připravuji BT files z {args.data_json}")
    create_files_for_blue_teams(args.data_json)

    if args.mode == "correctness":
        print("[prototype] Spouštím correctness_evaluation() z prototypu...")
        correctness_evaluation()
        print("[prototype] Hotovo. Výsledky jsou v ./correctness/*.txt/pdf (v rámci prototypu).")
    else:
        print("[prototype] Jen prepare mód – BT soubory vytvořeny.")


if __name__ == "__main__":
    main()
