#!/usr/bin/env python3
"""Run and validate the small known-topology correctness scenario."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pmmap.workflow import run as workflow_run


DEFAULT_INPUT = REPO_ROOT / "data" / "evaluation" / "ground_truth_flows.csv"
DEFAULT_EXPECTED = REPO_ROOT / "data" / "evaluation" / "ground_truth_expected.json"


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def validate(input_path: Path, expected_path: Path, output_dir: Path) -> dict:
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    scope = expected["scope"]
    manifest_path = Path(
        workflow_run(
            out_dir=str(output_dir),
            input_path=str(input_path),
            include_cidrs=scope.get("include_cidrs") or [],
            drop_outside=bool(scope.get("drop_outside")),
            title="Known-Topology Correctness Evaluation",
            top_k=10,
        )
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    graph = json.loads(
        (output_dir / "graph" / "graph.json").read_text(encoding="utf-8")
    )
    criticality = _read_jsonl(
        output_dir / "criticality" / "criticality.jsonl"
    )

    service_ids = {
        str(node["id"])
        for node in graph.get("nodes", [])
        if node.get("type") == "service"
    }
    edge_pairs = {
        (str(edge.get("src")), str(edge.get("dst")))
        for edge in graph.get("edges", [])
    }
    checks: dict[str, bool] = {}
    for key, value in expected.get("counts", {}).items():
        checks[f"count:{key}"] = manifest.get("outputs", {}).get(key) == value
    checks["required_services"] = set(expected.get("required_services", [])) <= service_ids
    checks["forbidden_services"] = not (
        set(expected.get("forbidden_services", [])) & service_ids
    )
    checks["required_edges"] = {
        tuple(pair) for pair in expected.get("required_edges", [])
    } <= edge_pairs
    checks["top_criticality"] = bool(criticality) and (
        criticality[0].get("id") == expected.get("expected_top_criticality")
    )

    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if all(checks.values()) else "failed",
        "input": str(input_path.resolve()),
        "expected": str(expected_path.resolve()),
        "run_manifest": str(manifest_path.resolve()),
        "checks": checks,
        "actual": {
            "counts": manifest.get("outputs", {}),
            "services": sorted(service_ids),
            "edges": sorted([list(pair) for pair in edge_pairs]),
            "top_criticality": criticality[0].get("id") if criticality else None,
        },
    }
    report_path = output_dir / "ground_truth_validation.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[ground-truth] {report['status']} -> {report_path}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "data" / "run" / "ground_truth",
    )
    args = parser.parse_args(argv)
    try:
        report = validate(args.input, args.expected, args.output)
    except Exception as exc:
        print(f"[ground-truth] validation could not run: {exc}", file=sys.stderr)
        return 1
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
