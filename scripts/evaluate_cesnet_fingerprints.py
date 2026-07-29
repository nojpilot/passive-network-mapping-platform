#!/usr/bin/env python3
"""Evaluate endpoint OS-CPE hypotheses against CESNET label ground truth."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GROUND_TRUTH = (
    REPO_ROOT / "data" / "run" / "cesnet" / "prepared" / "cesnet_ground_truth.jsonl"
)
DEFAULT_ENRICHED = (
    REPO_ROOT / "data" / "run" / "cesnet" / "enriched" / "enriched_hosts.jsonl"
)
DEFAULT_LABEL_MAP = REPO_ROOT / "data" / "evaluation" / "os_cpe_label_map.json"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "run" / "cesnet" / "fingerprint_validation.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_number}") from exc
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _normalize_label(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_")


def _cpe_part(cpe: str) -> str | None:
    parts = str(cpe).split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[2]
    return None


def _accepted_families(
    cpe: str,
    mappings: dict[str, list[str]],
) -> set[str] | None:
    normalized = str(cpe).lower()
    matches = [
        (prefix, families)
        for prefix, families in mappings.items()
        if normalized.startswith(prefix.lower())
    ]
    if not matches:
        return None
    _, families = max(matches, key=lambda item: len(item[0]))
    return {_normalize_label(family) for family in families}


def evaluate(
    ground_truth_path: Path,
    enriched_path: Path,
    label_map_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    ground_truth = _read_jsonl(ground_truth_path)
    enriched_rows = _read_jsonl(enriched_path)
    label_map_payload = json.loads(label_map_path.read_text(encoding="utf-8"))
    mappings = label_map_payload.get("cpe_prefix_to_os_families") or {}
    if not isinstance(mappings, dict):
        raise ValueError("Label map must contain cpe_prefix_to_os_families.")

    enriched_by_ip = {
        str(row["ip"]): row
        for row in enriched_rows
        if row.get("ip")
    }
    labelled_rows = 0
    rows_with_ja3 = 0
    rows_with_any_hypothesis = 0
    rows_with_os_hypothesis = 0
    rows_with_scored_os_hypothesis = 0
    correct_rows = 0
    unmapped_os_hypotheses = Counter()
    application_hypotheses = Counter()
    predictions_by_label: dict[str, Counter] = {}

    for truth in ground_truth:
        ip = str(truth.get("synthetic_src_ip") or "")
        actual = _normalize_label(truth.get("os_family"))
        if not actual:
            continue
        labelled_rows += 1
        if truth.get("tls_ja3"):
            rows_with_ja3 += 1
        host = enriched_by_ip.get(ip, {})
        hypotheses = [
            entry
            for entry in (host.get("cpe") or [])
            if isinstance(entry, dict) and entry.get("endpoint_role") == "client"
        ]
        if hypotheses:
            rows_with_any_hypothesis += 1

        scored_predictions: list[tuple[str, set[str]]] = []
        has_os_hypothesis = False
        for entry in hypotheses:
            cpe = str(entry.get("cpe") or "")
            part = _cpe_part(cpe)
            if part == "a":
                application_hypotheses[cpe] += 1
                continue
            if part != "o":
                continue
            has_os_hypothesis = True
            accepted = _accepted_families(cpe, mappings)
            if accepted is None:
                unmapped_os_hypotheses[cpe] += 1
                continue
            scored_predictions.append((cpe, accepted))
        if has_os_hypothesis:
            rows_with_os_hypothesis += 1
        if not scored_predictions:
            continue

        rows_with_scored_os_hypothesis += 1
        correct = any(actual in accepted for _, accepted in scored_predictions)
        if correct:
            correct_rows += 1
        label_counter = predictions_by_label.setdefault(actual, Counter())
        label_counter["evaluated"] += 1
        label_counter["correct" if correct else "incorrect"] += 1

    coverage = (
        rows_with_scored_os_hypothesis / labelled_rows
        if labelled_rows
        else 0.0
    )
    covered_row_match_rate = (
        correct_rows / rows_with_scored_os_hypothesis
        if rows_with_scored_os_hypothesis
        else None
    )
    report: dict[str, Any] = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "row_level_any_os_cpe_hypothesis_matches_os_family_label",
        "inputs": {
            "ground_truth": {
                "path": str(ground_truth_path.resolve()),
                "sha256": _sha256(ground_truth_path),
            },
            "enriched_hosts": {
                "path": str(enriched_path.resolve()),
                "sha256": _sha256(enriched_path),
            },
            "label_map": {
                "path": str(label_map_path.resolve()),
                "sha256": _sha256(label_map_path),
            },
        },
        "counts": {
            "ground_truth_rows": len(ground_truth),
            "labelled_rows": labelled_rows,
            "rows_with_ja3": rows_with_ja3,
            "rows_with_any_client_cpe_hypothesis": rows_with_any_hypothesis,
            "rows_with_os_cpe_hypothesis": rows_with_os_hypothesis,
            "rows_with_scored_os_cpe_hypothesis": rows_with_scored_os_hypothesis,
            "correct_os_family_rows": correct_rows,
        },
        "metrics": {
            "os_prediction_coverage": coverage,
            "os_prediction_label_match_rate_on_covered_rows": (
                covered_row_match_rate
            ),
        },
        "per_os_family": {
            label: dict(sorted(counter.items()))
            for label, counter in sorted(predictions_by_label.items())
        },
        "unmapped_os_hypotheses": dict(unmapped_os_hypotheses.most_common()),
        "application_hypotheses_not_scored_as_os": dict(
            application_hypotheses.most_common()
        ),
        "limitations": [
            "Coverage measures only explicit OS-part CPE hypotheses with a configured label mapping.",
            "Application CPE hypotheses are reported but are not treated as OS predictions.",
            "The covered-row label match rate counts a row as matched when any scored OS-CPE hypothesis accepts its OS-family label.",
            "The match rate is conditional on covered rows and is not hypothesis-level precision; it must be presented together with coverage.",
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--enriched", type=Path, default=DEFAULT_ENRICHED)
    parser.add_argument("--label-map", type=Path, default=DEFAULT_LABEL_MAP)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = evaluate(
            args.ground_truth,
            args.enriched,
            args.label_map,
            args.output,
        )
    except Exception as exc:
        print(f"[fingerprints] evaluation failed: {exc}", file=sys.stderr)
        return 1
    coverage = report["metrics"]["os_prediction_coverage"]
    match_rate = report["metrics"][
        "os_prediction_label_match_rate_on_covered_rows"
    ]
    match_text = "n/a" if match_rate is None else f"{match_rate:.2%}"
    print(
        f"[fingerprints] coverage={coverage:.2%}, "
        f"label_match_rate_on_covered={match_text} -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
