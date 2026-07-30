#!/usr/bin/env python3
"""Build the small, reviewable electronic appendix for IS MU.

The upstream CESNET archive is deliberately not embedded.  This builder copies
only the exact small table used by the evaluation and one compact raw-PCAP
fixture, together with attribution and checksums.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePath
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_PREFIX = "passive-network-mapping-platform"
EXPECTED_DATASET_MD5 = "4c0bbc96e9a7ebbc25bc309bb0206e3e"
DATASET_DOI = "10.5281/zenodo.15004766"

REQUIRED_ROOT_FILES = (
    ".gitignore",
    "LICENSE",
    "README.md",
    "README_external_criticality.md",
    "THIRD_PARTY_NOTICES.md",
    "config.yaml",
    "main.py",
    "requirements.txt",
    "requirements-evaluation.txt",
    "requirements-notebook.txt",
)

REQUIRED_DATA_FILES = (
    "data/cpe_map.sample.yaml",
    "data/evaluation/ground_truth_expected.json",
    "data/evaluation/ground_truth_flows.csv",
    "data/evaluation/os_cpe_label_map.json",
    "data/flows_demo.csv",
    "data/iana-service-names-port-numbers.csv",
)

SELECTED_RESULT_FILES = (
    "data/run/cesnet/fingerprint_validation.json",
    "data/run/cesnet/run_manifest.json",
    "data/run/cesnet/criticality/criticality.jsonl",
    "data/run/cesnet/criticality/criticality_top.json",
    "data/run/cesnet/enriched/enriched_hosts.jsonl",
    "data/run/cesnet/enriched/enrichment_manifest.json",
    "data/run/cesnet/graph/analysis_stats.json",
    "data/run/cesnet/graph/edges.jsonl",
    "data/run/cesnet/graph/graph.json",
    "data/run/cesnet/inventory/hosts.jsonl",
    "data/run/cesnet/prepared/cesnet_ground_truth.jsonl",
    "data/run/cesnet/prepared/cesnet_preparation_manifest.json",
    "data/run/cesnet/prepared/flows.jsonl",
    "data/run/cesnet/normalized/flows.jsonl",
    "data/run/cesnet/normalized/normalization_stats.json",
    "data/run/cesnet/report/figures_manifest.json",
    "data/run/cesnet/report/host_metrics.jsonl",
    "data/run/cesnet/report/report.md",
    "data/run/cesnet/report/summary.json",
    "data/run/ground_truth/criticality/criticality.jsonl",
    "data/run/ground_truth/criticality/criticality_top.json",
    "data/run/ground_truth/enriched/enriched_hosts.jsonl",
    "data/run/ground_truth/enriched/enrichment_manifest.json",
    "data/run/ground_truth/graph/analysis_stats.json",
    "data/run/ground_truth/graph/edges.jsonl",
    "data/run/ground_truth/graph/graph.json",
    "data/run/ground_truth/ground_truth_validation.json",
    "data/run/ground_truth/inventory/hosts.jsonl",
    "data/run/ground_truth/normalized/flows.jsonl",
    "data/run/ground_truth/normalized/normalization_stats.json",
    "data/run/ground_truth/preprocessed_input/ground_truth_flows.csv",
    "data/run/ground_truth/report/assets/communication_map.png",
    "data/run/ground_truth/report/assets/host_roles.png",
    "data/run/ground_truth/report/assets/host_traffic_mix.png",
    "data/run/ground_truth/report/assets/top_criticality.png",
    "data/run/ground_truth/report/assets/top_edges_flows.png",
    "data/run/ground_truth/report/figures_manifest.json",
    "data/run/ground_truth/report/host_metrics.jsonl",
    "data/run/ground_truth/report/report.md",
    "data/run/ground_truth/report/summary.json",
    "data/run/ground_truth/run_manifest.json",
)

RAW_PCAP_RESULT_FILES = (
    "data/run/zeek_debian10/criticality/criticality.jsonl",
    "data/run/zeek_debian10/criticality/criticality_top.json",
    "data/run/zeek_debian10/enriched/enriched_hosts.jsonl",
    "data/run/zeek_debian10/enriched/enrichment_manifest.json",
    "data/run/zeek_debian10/graph/analysis_stats.json",
    "data/run/zeek_debian10/graph/edges.jsonl",
    "data/run/zeek_debian10/graph/graph.json",
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/capture_loss.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/conn.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/dhcp.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/dns.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/known_hosts.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/known_services.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/loaded_scripts.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/notice.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/ntp.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/packet_filter.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/ssl.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/stats.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/telemetry.log"
    ),
    (
        "data/run/zeek_debian10/ingest/zeek/"
        "0001_debian10_traffic_sample_pcap/weird.log"
    ),
    "data/run/zeek_debian10/inventory/hosts.jsonl",
    "data/run/zeek_debian10/normalized/flows.jsonl",
    "data/run/zeek_debian10/normalized/normalization_stats.json",
    "data/run/zeek_debian10/report/assets/communication_map.png",
    "data/run/zeek_debian10/report/assets/host_roles.png",
    "data/run/zeek_debian10/report/assets/host_traffic_mix.png",
    "data/run/zeek_debian10/report/assets/top_criticality.png",
    "data/run/zeek_debian10/report/assets/top_edges_flows.png",
    "data/run/zeek_debian10/report/figures_manifest.json",
    "data/run/zeek_debian10/report/host_metrics.jsonl",
    "data/run/zeek_debian10/report/report.md",
    "data/run/zeek_debian10/report/summary.json",
    "data/run/zeek_debian10/run_manifest.json",
)

REQUIRED_FIGURE_FILES = (
    "communication_map.png",
    "host_roles.png",
    "host_traffic_mix.png",
    "top_criticality.png",
    "top_edges_flows.png",
)

DATASET_MEMBERS = {
    "merged_tls.csv": "data/evaluation/cesnet/merged_tls.csv",
    (
        "linux__debian__10-buster/"
        "2025-02-05__vagrant__debian_buster64/traffic.pcap"
    ): "data/evaluation/cesnet/debian10_traffic_sample.pcap",
    (
        "linux__debian__10-buster/"
        "2025-02-05__vagrant__debian_buster64/flows.csv"
    ): "data/evaluation/cesnet/debian10_flows_reference.csv",
    (
        "linux__debian__10-buster/"
        "2025-02-05__vagrant__debian_buster64/info.json"
    ): "data/evaluation/cesnet/debian10_info.json",
}


def _hash_bytes(payload: bytes, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    digest.update(payload)
    return digest.hexdigest()


def _hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repository_root_forms(resolved_root: PurePath) -> set[str]:
    """Return native and WSL mount spellings of a resolved repository path."""
    posix_path = resolved_root.as_posix()
    root_forms = {
        str(resolved_root),
        posix_path,
    }
    if resolved_root.drive:
        drive = resolved_root.drive.rstrip(":").lower()
        drive_relative = posix_path.split(":", 1)[1].lstrip("/")
        root_forms.add(f"/mnt/{drive}/{drive_relative}")
    wsl_match = re.fullmatch(r"/mnt/([a-zA-Z])/(.+)", posix_path)
    if wsl_match:
        windows_posix = (
            f"{wsl_match.group(1).upper()}:/{wsl_match.group(2)}"
        )
        root_forms.add(windows_posix)
        root_forms.add(windows_posix.replace("/", "\\"))
    return root_forms


def _portable_project_payload(path: Path, repo_root: Path) -> bytes:
    """Remove the build machine's repository prefix from packaged text files."""
    payload = path.read_bytes()
    if path.suffix.lower() not in {".json", ".jsonl", ".md", ".txt", ".yaml", ".yml"}:
        return payload
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload

    root_forms = _repository_root_forms(repo_root.resolve())
    for root_form in sorted(root_forms, key=len, reverse=True):
        text = text.replace(root_form, "${REPOSITORY_ROOT}")
        # JSON escapes Windows separators, so also replace the serialized form.
        text = text.replace(
            root_form.replace("\\", "\\\\"),
            "${REPOSITORY_ROOT}",
        )
    return text.encode("utf-8")


def _project_files(repo_root: Path) -> list[Path]:
    files: set[Path] = set()
    for relative in (*REQUIRED_ROOT_FILES, *REQUIRED_DATA_FILES):
        path = repo_root / relative
        if not path.is_file():
            raise FileNotFoundError(f"Required appendix file is missing: {path}")
        files.add(path)

    for directory, pattern in (
        ("pmmap", "*.py"),
        ("tests", "test_*.py"),
        ("notebooks", "*.ipynb"),
    ):
        files.update(
            path
            for path in (repo_root / directory).glob(pattern)
            if path.is_file()
        )

    canonical_scripts = (
        "build_submission_archive.py",
        "evaluate_cesnet_fingerprints.py",
        "external_criticality_stub.py",
        "prepare_cesnet.py",
        "run_cesnet.py",
        "validate_ground_truth.py",
    )
    for name in canonical_scripts:
        path = repo_root / "scripts" / name
        if not path.is_file():
            raise FileNotFoundError(f"Required appendix script is missing: {path}")
        files.add(path)

    workflow = repo_root / ".github" / "workflows" / "ci.yml"
    if workflow.is_file():
        files.add(workflow)

    for relative in (*SELECTED_RESULT_FILES, *RAW_PCAP_RESULT_FILES):
        path = repo_root / relative
        if not path.is_file():
            raise FileNotFoundError(
                f"Required evaluation artifact is missing: {path}"
            )
        files.add(path)
    figures_dir = repo_root / "data" / "run" / "cesnet" / "report" / "assets"
    for name in REQUIRED_FIGURE_FILES:
        path = figures_dir / name
        if not path.is_file():
            raise FileNotFoundError(
                f"Required evaluation figure is missing: {path}"
            )
        files.add(path)

    return sorted(files, key=lambda path: path.relative_to(repo_root).as_posix())


def _read_dataset_members(dataset_path: Path) -> dict[str, bytes]:
    if not dataset_path.is_file():
        raise FileNotFoundError(
            "Original CESNET archive is required to build the submission sample: "
            f"{dataset_path}"
        )
    actual_md5 = _hash_file(dataset_path, "md5")
    if actual_md5 != EXPECTED_DATASET_MD5:
        raise ValueError(
            "Unexpected CESNET archive MD5: "
            f"{actual_md5}; expected {EXPECTED_DATASET_MD5}."
        )

    extracted: dict[str, bytes] = {}
    with zipfile.ZipFile(dataset_path) as source:
        for member, destination in DATASET_MEMBERS.items():
            try:
                extracted[destination] = source.read(member)
            except KeyError as exc:
                raise ValueError(
                    f"CESNET archive does not contain required member: {member}"
                ) from exc
    return extracted


def _dataset_notice(dataset_payloads: dict[str, bytes]) -> bytes:
    tls_payload = dataset_payloads["data/evaluation/cesnet/merged_tls.csv"]
    pcap_payload = dataset_payloads[
        "data/evaluation/cesnet/debian10_traffic_sample.pcap"
    ]
    text = f"""# CESNET evaluation inputs

The files in this directory are extracted, unchanged members of:

- Michaela Novotná and Václav Bartoš, *CESNET Idle OS Traffic v1* (2025)
- DOI: https://doi.org/{DATASET_DOI}
- Licence: CC BY 4.0, https://creativecommons.org/licenses/by/4.0/
- Original archive MD5: `{EXPECTED_DATASET_MD5}`

`merged_tls.csv` contains 2,112 data rows and has SHA-256
`{_hash_bytes(tls_payload)}`. The recorded thesis evaluation deterministically
selects its first 2,000 rows in source order. The preparation step retains JA3
and SNI evidence and OS labels in a sidecar, while synthesising network
addresses, ports, timestamps, packet counts, and byte counts. The original CSV
itself is not modified.

`debian10_traffic_sample.pcap` is a compact raw-input fixture extracted from
the Debian 10 capture and has SHA-256 `{_hash_bytes(pcap_payload)}`. Its
corresponding upstream `info.json` and `flows.csv` are included unchanged. The
upstream flow-export header embeds IPFIX data types and is retained as a
reference artifact; it is not an input for the generic CSV adapter. The
reference contains 301 flow records, including 114 with TLS evidence and 28
with DNS evidence. The recorded raw-input run used Zeek 8.2.1 and p0f 3.09b:

```bash
python main.py run \\
  --pcap data/evaluation/cesnet/debian10_traffic_sample.pcap \\
  --output data/run/zeek_debian10 \\
  --include-cidrs 10.0.2.0/24 \\
  --include-cidrs fe80::/10 \\
  --drop-outside \\
  --zeek-bin /opt/zeek/bin/zeek \\
  --p0f-bin /usr/sbin/p0f \\
  --no-pdf
```

The complete 2.37 GB upstream archive is intentionally omitted because the
evaluation does not consume its remaining captures. Download it from the DOI
record when full-source reproduction is required. The packaged evaluation is
self-contained and can be rerun without that download:

```bash
python scripts/run_cesnet.py \\
  --input data/evaluation/cesnet/merged_tls.csv \\
  --no-pdf
```
"""
    return text.encode("utf-8")


def _write_entry(target: zipfile.ZipFile, relative: str, payload: bytes) -> None:
    info = zipfile.ZipInfo(
        filename=f"{ARCHIVE_PREFIX}/{relative}",
        date_time=(2025, 1, 1, 0, 0, 0),
    )
    # Do not let the Python host platform alter central-directory metadata.
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = (
        0o100755
        if relative.startswith("scripts/") and relative.endswith(".sh")
        else 0o100644
    )
    info.external_attr = mode << 16
    target.writestr(info, payload, compresslevel=9)


def _repair_packaged_checksum_references(payloads: dict[str, bytes]) -> None:
    """Keep cross-artifact hashes valid after portable-path sanitization."""
    fingerprint_path = "data/run/cesnet/fingerprint_validation.json"
    enriched_path = "data/run/cesnet/enriched/enriched_hosts.jsonl"
    manifest_path = "data/run/cesnet/run_manifest.json"
    if fingerprint_path not in payloads or manifest_path not in payloads:
        return
    fingerprint = json.loads(payloads[fingerprint_path])
    if enriched_path in payloads:
        enriched_input = (
            fingerprint.get("inputs", {}).get("enriched_hosts", {})
        )
        if isinstance(enriched_input, dict):
            enriched_input["sha256"] = _hash_bytes(payloads[enriched_path])
    payloads[fingerprint_path] = (
        json.dumps(fingerprint, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")

    manifest = json.loads(payloads[manifest_path])
    fingerprint_sha256 = _hash_bytes(payloads[fingerprint_path])
    for evaluation in manifest.get("post_evaluations") or []:
        if evaluation.get("name") == "cesnet_os_fingerprint_validation":
            evaluation["output_sha256"] = fingerprint_sha256
    payloads[manifest_path] = (
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")


def build_archive(
    repo_root: Path,
    dataset_path: Path,
    output_path: Path,
) -> dict:
    project_files = _project_files(repo_root)
    output_resolved = output_path.resolve()
    protected_sources = [dataset_path, *project_files]
    for source in protected_sources:
        if output_resolved == source.resolve():
            raise ValueError(
                "Appendix output must not overwrite an input or project file: "
                f"{source}"
            )

    payloads: dict[str, bytes] = {
        path.relative_to(repo_root).as_posix(): _portable_project_payload(
            path,
            repo_root,
        )
        for path in project_files
    }
    _repair_packaged_checksum_references(payloads)
    dataset_payloads = _read_dataset_members(dataset_path)
    payloads.update(dataset_payloads)
    payloads["data/evaluation/cesnet/README.md"] = _dataset_notice(
        dataset_payloads
    )

    manifest = {
        "schema_version": 1,
        "purpose": "FI MU electronic thesis appendix",
        "dataset": {
            "title": "CESNET Idle OS Traffic v1",
            "doi": DATASET_DOI,
            "license": "CC BY 4.0",
            "full_archive_included": False,
            "original_archive_md5": EXPECTED_DATASET_MD5,
            "evaluation_selection": "first 2000 rows of merged_tls.csv in source order",
        },
        "files": {
            relative: {
                "size_bytes": len(payload),
                "sha256": _hash_bytes(payload),
            }
            for relative, payload in sorted(payloads.items())
        },
    }
    manifest_payload = (
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    payloads["APPENDIX_MANIFEST.json"] = manifest_payload

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()
    with zipfile.ZipFile(output_path, "w") as target:
        for relative, payload in sorted(payloads.items()):
            _write_entry(target, relative, payload)

    return {
        "path": str(output_path.resolve()),
        "size_bytes": output_path.stat().st_size,
        "sha256": _hash_file(output_path),
        "file_count": len(payloads),
        "dataset_sample_bytes": sum(map(len, dataset_payloads.values())),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=REPO_ROOT / "data" / "cesnet-idle-os-traffic.zip",
        help="Original CESNET archive used only to extract the small sample.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            REPO_ROOT
            / "data"
            / "run"
            / "submission"
            / "passive-network-mapping-platform-appendix.zip"
        ),
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = build_archive(REPO_ROOT, args.dataset, args.output)
    except Exception as exc:
        print(f"[appendix] build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
