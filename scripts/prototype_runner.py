#!/usr/bin/env python
"""
Wrapper for the link-prediction prototype from https://zenodo.org/records/10548434.

It reads the original Cyber Czech data.json file, prepares per-team inputs, and
runs correctness evaluation from the original implementation. It requires Python
3.10 or 3.11 and dependencies from data/prototype/link-prediction/requirements.txt
(PyTorch/torch-geometric).
"""

from __future__ import annotations

import argparse
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
PROTO_ROOT = os.path.join(REPO_ROOT, "data", "prototype", "link-prediction")

sys.path.insert(0, PROTO_ROOT)


def main():
    parser = argparse.ArgumentParser(description="Run the link-prediction Python prototype.")
    parser.add_argument(
        "--data-json",
        default=os.path.join(REPO_ROOT, "data", "raw", "cyber_czech", "cz.muni.csirt.IPFlowEntry", "data.json"),
        help="Path to the original Cyber Czech data.json file with bidirectional flows.",
    )
    parser.add_argument(
        "--mode",
        choices=["prepare", "correctness"],
        default="correctness",
        help="prepare = create only the BT1-6 split; correctness = run correctness_evaluation().",
    )
    args = parser.parse_args()

    if not os.path.isdir(PROTO_ROOT):
        sys.stderr.write(
            "Prototype directory does not exist: "
            f"{PROTO_ROOT}\n"
            "Download and unpack the prototype from https://zenodo.org/records/10548434 into this path.\n"
        )
        sys.exit(1)

    try:
        from data_acquisition import create_files_for_blue_teams
        from evaluation import correctness_evaluation
    except Exception as exc:
        sys.stderr.write(
            f"Cannot import the prototype. Make sure Python 3.10 or 3.11 is used and dependencies from "
            f"{os.path.join(PROTO_ROOT, 'requirements.txt')} are installed (torch/torch-geometric, etc.). "
            f"Error: {exc}\n"
        )
        sys.exit(1)

    if not os.path.isfile(args.data_json):
        sys.stderr.write(f"File {args.data_json} does not exist. Provide a path to the original data.json.\n")
        sys.exit(1)

    os.chdir(PROTO_ROOT)
    print(f"[prototype] Preparing BT files from {args.data_json}")
    create_files_for_blue_teams(args.data_json)

    if args.mode == "correctness":
        print("[prototype] Running correctness_evaluation() from the prototype...")
        correctness_evaluation()
        print("[prototype] Done. Results are in ./correctness/*.txt/pdf inside the prototype directory.")
    else:
        print("[prototype] Prepare-only mode finished. BT files were created.")


if __name__ == "__main__":
    main()
