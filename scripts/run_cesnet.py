#!/usr/bin/env python3
"""Prepare, run, and evaluate the pinned CESNET thesis scenario."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pmmap.workflow import run as workflow_run
from scripts.evaluate_cesnet_fingerprints import evaluate
from scripts.prepare_cesnet import prepare


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=REPO_ROOT / "data" / "cesnet-idle-os-traffic.zip",
        help="Original CESNET ZIP or an extracted merged_tls.csv.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "data" / "run" / "cesnet",
    )
    parser.add_argument(
        "--cpe-map",
        type=Path,
        default=REPO_ROOT / "data" / "cpe_map.sample.yaml",
    )
    parser.add_argument(
        "--label-map",
        type=Path,
        default=REPO_ROOT / "data" / "evaluation" / "os_cpe_label_map.json",
    )
    parser.add_argument("--limit", type=int, default=2000)
    parser.add_argument(
        "--pdf",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Attempt report PDF generation with Pandoc.",
    )
    args = parser.parse_args(argv)

    # Keep the adapter output separate from the workflow's validated,
    # scope-annotated normalized output. This preserves the exact file whose
    # hash is recorded as the workflow input instead of overwriting it in
    # place.
    prepared_dir = args.output / "prepared"
    flows_path = prepared_dir / "flows.jsonl"
    truth_path = prepared_dir / "cesnet_ground_truth.jsonl"
    preparation_manifest_path = prepared_dir / "cesnet_preparation_manifest.json"
    fingerprint_report_path = args.output / "fingerprint_validation.json"
    try:
        # Remove artifacts created by versions that wrote preparation outputs
        # into normalized/ and then overwrote flows.jsonl in place.
        for legacy_path in (
            args.output / "normalized" / "cesnet_ground_truth.jsonl",
            args.output / "normalized" / "cesnet_preparation_manifest.json",
        ):
            legacy_path.unlink(missing_ok=True)
        prepare(
            args.input,
            flows_path,
            truth_path,
            preparation_manifest_path,
            limit=args.limit,
            offset=0,
        )
        run_manifest_path = Path(workflow_run(
            out_dir=str(args.output),
            flows_path=str(flows_path),
            include_cidrs=[],
            exclude_cidrs=[],
            drop_outside=False,
            cpe_map_path=str(args.cpe_map) if args.cpe_map else None,
            title="CESNET Idle OS Traffic Evaluation",
            pdf=args.pdf,
            top_k=10,
        ))
        fingerprint_report = evaluate(
            truth_path,
            args.output / "enriched" / "enriched_hosts.jsonl",
            args.label_map,
            fingerprint_report_path,
        )
        run_manifest = json.loads(
            run_manifest_path.read_text(encoding="utf-8")
        )
        run_manifest["post_evaluations"] = [
            {
                "name": "cesnet_os_fingerprint_validation",
                "status": "completed",
                "output": str(fingerprint_report_path.resolve()),
                "output_sha256": _sha256(fingerprint_report_path),
                "metrics": fingerprint_report["metrics"],
                "counts": fingerprint_report["counts"],
            }
        ]
        run_manifest_path.write_text(
            json.dumps(run_manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"[cesnet] run failed: {exc}", file=sys.stderr)
        return 1

    coverage = fingerprint_report["metrics"]["os_prediction_coverage"]
    match_rate = fingerprint_report["metrics"][
        "os_prediction_label_match_rate_on_covered_rows"
    ]
    match_text = "n/a" if match_rate is None else f"{match_rate:.2%}"
    print(
        f"[cesnet] completed: coverage={coverage:.2%}, "
        f"label_match_rate_on_covered={match_text}, output={args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
