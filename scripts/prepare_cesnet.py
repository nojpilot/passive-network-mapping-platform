#!/usr/bin/env python3
"""Prepare a deterministic, explicitly synthetic CESNET evaluation fixture.

The source dataset contains labelled TLS observations rather than complete
network flows.  Consequently, the generated addresses, ports, timestamps,
byte counts, and packet counts are placeholders.  Ground-truth source labels
are retained in a sidecar JSONL file for a separate fingerprinting evaluation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


ADAPTER_VERSION = "2"
DATASET = {
    "title": "CESNET Idle OS Traffic",
    "version": "1",
    "record_doi": "10.5281/zenodo.15004766",
    "concept_doi": "10.5281/zenodo.15004765",
    "license": "CC BY 4.0",
}
EXPECTED_FIELDS = (
    "os_family",
    "os_type",
    "os_version",
    "TLS_VERSION",
    "TLS_ALPN",
    "TLS_JA3",
    "TLS_SNI",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _open_tls_table(input_source: Path) -> Iterator[tuple[TextIO, dict]]:
    """Open merged_tls.csv directly or stream it from the upstream ZIP."""
    if not input_source.is_file():
        raise FileNotFoundError(f"CESNET source does not exist: {input_source}")

    base_metadata = {
        "path": str(input_source.resolve()),
        "size_bytes": input_source.stat().st_size,
        "sha256": _sha256(input_source),
    }
    if input_source.suffix.lower() != ".zip":
        with input_source.open("r", encoding="utf-8-sig", newline="") as source:
            yield source, {"kind": "csv", **base_metadata}
        return

    with zipfile.ZipFile(input_source) as archive:
        candidates = [
            entry
            for entry in archive.infolist()
            if not entry.is_dir()
            and Path(entry.filename.replace("\\", "/")).name.lower()
            == "merged_tls.csv"
        ]
        if len(candidates) != 1:
            raise ValueError(
                "CESNET archive must contain exactly one merged_tls.csv; "
                f"found {len(candidates)}."
            )
        entry = candidates[0]
        metadata = {
            "kind": "zip_member",
            **base_metadata,
            "member": entry.filename,
            "member_size_bytes": entry.file_size,
            "member_crc32": f"{entry.CRC:08x}",
        }
        with archive.open(entry, "r") as raw_source:
            with io.TextIOWrapper(
                raw_source,
                encoding="utf-8-sig",
                newline="",
            ) as source:
                yield source, metadata


def _canonical_header(value: str) -> str:
    text = " ".join(str(value).strip().split())
    if " " in text:
        # Arrow/ClickHouse exports may prefix a logical type, for example
        # ``string TLS_SNI`` or ``bytes TLS_JA3``.
        text = text.rsplit(" ", 1)[-1]
    return text.lower()


def _resolve_columns(fieldnames: Iterable[str] | None) -> dict[str, str]:
    available = {
        _canonical_header(field): field
        for field in (fieldnames or [])
        if field and str(field).strip()
    }
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for expected in EXPECTED_FIELDS:
        original = available.get(expected.lower())
        if original is None:
            missing.append(expected)
        else:
            resolved[expected] = original
    if missing:
        raise ValueError(
            "Input CSV is missing expected CESNET columns: " + ", ".join(missing)
        )
    return resolved


def _write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def prepare(
    input_source: Path,
    flows_output: Path,
    ground_truth_output: Path,
    manifest_output: Path,
    *,
    limit: int,
    offset: int,
) -> dict:
    if limit < 1:
        raise ValueError("--limit must be at least 1.")
    if offset < 0:
        raise ValueError("--offset cannot be negative.")

    flow_rows: list[dict] = []
    truth_rows: list[dict] = []
    destination_by_sni: dict[str, str] = {}

    with _open_tls_table(input_source) as (source, source_metadata):
        reader = csv.DictReader(source)
        columns = _resolve_columns(reader.fieldnames)
        for source_index, row in enumerate(reader):
            if source_index < offset:
                continue
            if len(flow_rows) >= limit:
                break

            sample_index = len(flow_rows)
            sni = str(row.get(columns["TLS_SNI"]) or "").strip()
            ja3 = str(row.get(columns["TLS_JA3"]) or "").strip()
            destination_key = sni or "<missing-sni>"
            if destination_key not in destination_by_sni:
                ordinal = len(destination_by_sni) + 1
                if ordinal > 254:
                    raise ValueError(
                        "The selected sample has more than 254 unique SNI values; "
                        "increase the synthetic destination address space explicitly."
                    )
                destination_by_sni[destination_key] = f"198.51.100.{ordinal}"

            source_host = sample_index // 250
            source_octet = sample_index % 250 + 1
            if source_host > 255:
                raise ValueError(
                    "The selected sample exceeds the supported synthetic client address space."
                )
            src_ip = f"10.20.{source_host}.{source_octet}"
            dst_ip = destination_by_sni[destination_key]
            flow = {
                # These required flow fields are synthetic placeholders. Zero
                # volume prevents them from being mistaken for measurements.
                "ts": float(sample_index),
                "src_ip": src_ip,
                "src_port": 40000 + (sample_index % 20000),
                "dst_ip": dst_ip,
                "dst_port": 443,
                "proto": "tcp",
                "bytes": 0,
                "pkts": 0,
                "src_is_initiator": True,
                "orientation_source": "cesnet_dataset_adapter",
            }
            if ja3:
                flow["ja3"] = ja3
            if sni:
                flow["sni"] = sni
            flow_rows.append(flow)

            truth_rows.append(
                {
                    "sample_index": sample_index,
                    "source_row_index": source_index,
                    "synthetic_src_ip": src_ip,
                    "synthetic_dst_ip": dst_ip,
                    "os_family": row.get(columns["os_family"]),
                    "os_type": row.get(columns["os_type"]),
                    "os_version": row.get(columns["os_version"]),
                    "tls_version": row.get(columns["TLS_VERSION"]),
                    "tls_alpn": row.get(columns["TLS_ALPN"]),
                    "tls_ja3": ja3 or None,
                    "tls_sni": sni or None,
                }
            )

    if not flow_rows:
        raise ValueError("The selected CESNET row range produced no records.")

    _write_jsonl(flows_output, flow_rows)
    _write_jsonl(ground_truth_output, truth_rows)
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "adapter_version": ADAPTER_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": DATASET,
        "source": {**source_metadata, "columns": list(EXPECTED_FIELDS)},
        "selection": {
            "method": "contiguous_rows_in_source_order",
            "offset": offset,
            "limit": limit,
            "records_written": len(flow_rows),
        },
        "outputs": {
            "flows": {
                "path": str(flows_output.resolve()),
                "sha256": _sha256(flows_output),
            },
            "ground_truth": {
                "path": str(ground_truth_output.resolve()),
                "sha256": _sha256(ground_truth_output),
            },
        },
        "synthetic_fields": {
            "src_ip": "one deterministic client address per selected source row",
            "dst_ip": "one deterministic documentation address per unique SNI",
            "src_port": "deterministic ephemeral placeholder",
            "dst_port": "443 because the source records are TLS observations",
            "ts": "zero-based sample index, not capture time",
            "bytes": "zero; source data contain no byte volume",
            "pkts": "zero; source data contain no packet count",
        },
        "retained_flow_evidence": ["TLS_JA3", "TLS_SNI"],
        "ground_truth_sidecar_fields": [
            "os_family",
            "os_type",
            "os_version",
            "TLS_VERSION",
            "TLS_ALPN",
            "TLS_JA3",
            "TLS_SNI",
        ],
        "limitations": [
            "The generated records are not a captured network topology.",
            "Client and destination addresses are synthetic.",
            "Flow timestamps and traffic volumes are not measured values.",
            "The fixture validates deterministic downstream processing and TLS evidence handling.",
        ],
    }
    manifest_output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to the original CESNET ZIP or an extracted merged_tls.csv.",
    )
    parser.add_argument(
        "--flows-output",
        required=True,
        type=Path,
        help="Target normalized flows.jsonl.",
    )
    parser.add_argument(
        "--ground-truth-output",
        type=Path,
        help="Target labelled sidecar JSONL; defaults beside flows.jsonl.",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        help="Target preparation manifest; defaults beside flows.jsonl.",
    )
    parser.add_argument("--limit", type=int, default=2000, help="Rows to select.")
    parser.add_argument("--offset", type=int, default=0, help="Rows to skip first.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    flows_output = args.flows_output
    ground_truth_output = args.ground_truth_output or (
        flows_output.parent / "cesnet_ground_truth.jsonl"
    )
    manifest_output = args.manifest_output or (
        flows_output.parent / "cesnet_preparation_manifest.json"
    )
    try:
        manifest = prepare(
            input_source=args.input,
            flows_output=flows_output,
            ground_truth_output=ground_truth_output,
            manifest_output=manifest_output,
            limit=args.limit,
            offset=args.offset,
        )
    except Exception as exc:
        print(f"[cesnet] preparation failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"[cesnet] wrote {manifest['selection']['records_written']} synthetic flow records "
        f"and labelled ground truth; manifest -> {manifest_output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
