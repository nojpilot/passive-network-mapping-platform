"""End-to-end orchestration and reproducibility manifests.

The individual pipeline stages remain available for debugging and notebook
use.  This module provides the user-facing, single-command workflow requested
by the project specification.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from . import analyze
from . import criticality
from . import enrich
from . import export
from . import ingest
from . import inventory
from . import normalize
from .utils import NetFilter


WORKFLOW_SCHEMA_VERSION = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _input_files(paths: Iterable[str], excluded_root: Path) -> list[Path]:
    files: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        if path.is_file():
            # An explicitly selected normalized file may intentionally live
            # inside the run directory (as in the CESNET preparation flow).
            files.add(path)
            continue
        if path.is_dir():
            for candidate in path.rglob("*"):
                if candidate.is_file() and not _is_within(candidate.resolve(), excluded_root):
                    files.add(candidate.resolve())
    return sorted(files, key=lambda item: str(item).lower())


def _describe_inputs(
    paths: Iterable[str],
    excluded_root: Path,
    hash_inputs: bool,
) -> list[dict[str, Any]]:
    descriptions: list[dict[str, Any]] = []
    for path in _input_files(paths, excluded_root=excluded_root):
        stat = path.stat()
        record: dict[str, Any] = {
            "path": str(path),
            "size_bytes": stat.st_size,
        }
        if hash_inputs:
            record["sha256"] = _sha256(path)
        descriptions.append(record)
    return descriptions


def _package_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for package in ("click", "pydantic", "PyYAML", "networkx", "matplotlib"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "not-installed"
    return versions


def _tool_details(
    zeek_bin: str,
    nfdump_bin: str,
    p0f_bin: str,
) -> dict[str, dict[str, str | None]]:
    commands = {
        "zeek": (zeek_bin, ["--version"]),
        "nfdump": (nfdump_bin, ["-V"]),
        "p0f": (p0f_bin, ["-?"]),
        "pandoc": ("pandoc", ["--version"]),
    }
    details: dict[str, dict[str, str | None]] = {}
    for label, (binary, args) in commands.items():
        path = shutil.which(binary)
        version = None
        if path:
            try:
                result = subprocess.run(
                    [path, *args],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                combined = (result.stdout or result.stderr or "").strip()
                if combined:
                    version = combined.splitlines()[0].strip()
            except (OSError, subprocess.SubprocessError):
                version = None
        details[label] = {"path": path, "version": version}
    return details


def _count_jsonl(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def _output_counts(run_dir: Path) -> dict[str, int]:
    graph_path = run_dir / "graph" / "graph.json"
    graph: dict[str, Any] = {}
    if graph_path.is_file():
        try:
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            graph = {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    result = {
        "normalized_flows": _count_jsonl(run_dir / "normalized" / "flows.jsonl"),
        "inventory_hosts": _count_jsonl(run_dir / "inventory" / "hosts.jsonl"),
        "enriched_hosts": _count_jsonl(run_dir / "enriched" / "enriched_hosts.jsonl"),
        "graph_hosts": sum(1 for node in nodes if node.get("type") == "host"),
        "graph_services": sum(1 for node in nodes if node.get("type") == "service"),
        "graph_edges": len(edges),
        "criticality_rows": _count_jsonl(run_dir / "criticality" / "criticality.jsonl"),
        "host_metric_rows": _count_jsonl(run_dir / "report" / "host_metrics.jsonl"),
    }
    stats_path = run_dir / "normalized" / "normalization_stats.json"
    if stats_path.is_file():
        try:
            stats = json.loads(stats_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            stats = {}
        for source_key, output_key in (
            ("input_records_seen", "normalization_input_records"),
            ("accepted_flows", "normalization_accepted_flows"),
            ("missing_required_fields", "normalization_missing_required"),
            ("filtered_excluded", "normalization_filtered_excluded"),
            ("filtered_outside_scope", "normalization_filtered_outside"),
            ("invalid_records", "normalization_invalid_records"),
        ):
            try:
                result[output_key] = int(stats.get(source_key, 0) or 0)
            except (TypeError, ValueError):
                result[output_key] = 0
    return result


def _resolve_flows_path(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if path.is_dir():
        path = path / "flows.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"Normalized flows file '{path}' does not exist.")
    return path


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def run(
    out_dir: str,
    *,
    input_path: str | None = None,
    flows_path: str | None = None,
    pcap_inputs: Sequence[str] | None = None,
    netflow_inputs: Sequence[str] | None = None,
    include_cidrs: Sequence[str] | None = None,
    exclude_cidrs: Sequence[str] | None = None,
    drop_outside: bool | None = None,
    zeek_bin: str = "zeek",
    zeek_scripts: Sequence[str] | None = None,
    nfdump_bin: str = "nfdump",
    netflow_format: str = "csv",
    p0f_bin: str = "p0f",
    cpe_map_path: str | None = None,
    min_flows: int = 1,
    external_cmd: str | None = None,
    external_timeout: float = 60.0,
    title: str = "Passive Network Mapping Report",
    pdf: bool = False,
    top_k: int = 10,
    hash_inputs: bool = True,
) -> str:
    """Run all applicable stages and return the run-manifest path.

    Exactly one input mode is accepted:

    * already-normalized ``flows.jsonl``;
    * a CSV/JSON/Zeek-log file or directory;
    * one or more raw PCAP/NetFlow paths.
    """

    pcap_list = list(pcap_inputs or [])
    netflow_list = list(netflow_inputs or [])
    raw_mode = bool(pcap_list or netflow_list)
    modes = sum(bool(value) for value in (flows_path, input_path, raw_mode))
    if modes != 1:
        raise ValueError(
            "Choose exactly one input mode: --flows, --input, or raw --pcap/--netflow."
        )

    scope_defaults_used = {
        "include_cidrs": include_cidrs is None,
        "exclude_cidrs": exclude_cidrs is None,
        "drop_outside": drop_outside is None,
    }
    effective_filter = NetFilter(
        include_cidrs=include_cidrs,
        exclude_cidrs=exclude_cidrs,
        drop_outside=drop_outside,
    )
    effective_include_cidrs = [
        str(network) for network in effective_filter.include
    ]
    effective_exclude_cidrs = [
        str(network) for network in effective_filter.exclude
    ]
    effective_drop_outside = bool(effective_filter.drop_outside)
    if effective_drop_outside and not effective_include_cidrs:
        raise ValueError(
            "--drop-outside requires at least one effective include CIDR. "
            "Supply --include-cidrs or configure network.include_cidrs."
        )

    run_dir = Path(out_dir).expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = run_dir / "run_manifest.json"
    source_paths: list[str] = []
    if flows_path:
        source_paths.append(str(_resolve_flows_path(flows_path)))
    elif input_path:
        source = Path(input_path).expanduser().resolve()
        if not source.exists():
            raise FileNotFoundError(f"Input path '{source}' does not exist.")
        source_paths.append(str(source))
    else:
        source_paths.extend(pcap_list)
        source_paths.extend(netflow_list)
    source_paths.extend(str(item) for item in (zeek_scripts or []) if item)
    if cpe_map_path:
        source_paths.append(cpe_map_path)

    started_at = _utc_now()
    started_clock = time.perf_counter()
    manifest: dict[str, Any] = {
        "schema_version": WORKFLOW_SCHEMA_VERSION,
        "status": "running",
        "started_at": started_at,
        "input_mode": (
            "normalized_flows" if flows_path else "preprocessed" if input_path else "raw"
        ),
        "inputs": _describe_inputs(
            source_paths,
            excluded_root=run_dir,
            hash_inputs=hash_inputs,
        ),
        "parameters": {
            "include_cidrs": effective_include_cidrs,
            "exclude_cidrs": effective_exclude_cidrs,
            "drop_outside": effective_drop_outside,
            "network_scope_defaults_used": scope_defaults_used,
            "min_flows": max(1, int(min_flows)),
            "cpe_map": str(Path(cpe_map_path).resolve()) if cpe_map_path else None,
            "external_criticality_command": external_cmd,
            "external_criticality_timeout_seconds": float(external_timeout),
            "zeek_scripts": list(zeek_scripts or []),
            "netflow_format": netflow_format,
            "title": title,
            "pdf": bool(pdf),
            "top_k": max(1, int(top_k)),
            "hash_inputs": bool(hash_inputs),
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "packages": _package_versions(),
            "tools": _tool_details(zeek_bin, nfdump_bin, p0f_bin),
        },
        "resources": {
            "service_registry": inventory.service_registry_provenance(),
        },
        "stages": [],
    }
    _write_manifest(manifest_path, manifest)

    def execute(stage_name: str, operation: Callable[[], None]) -> None:
        stage_started = _utc_now()
        stage_clock = time.perf_counter()
        try:
            operation()
        except Exception as exc:
            manifest["stages"].append(
                {
                    "name": stage_name,
                    "status": "failed",
                    "started_at": stage_started,
                    "elapsed_seconds": round(time.perf_counter() - stage_clock, 6),
                    "error": {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    },
                }
            )
            _write_manifest(manifest_path, manifest)
            raise
        else:
            manifest["stages"].append(
                {
                    "name": stage_name,
                    "status": "completed",
                    "started_at": stage_started,
                    "elapsed_seconds": round(time.perf_counter() - stage_clock, 6),
                }
            )
            _write_manifest(manifest_path, manifest)

    normalized_dir = run_dir / "normalized"
    inventory_dir = run_dir / "inventory"
    enriched_dir = run_dir / "enriched"
    graph_dir = run_dir / "graph"
    criticality_dir = run_dir / "criticality"
    report_dir = run_dir / "report"
    normalized_flows = normalized_dir / "flows.jsonl"

    try:
        if flows_path:
            source_flows = _resolve_flows_path(flows_path)

            def stage_flows() -> None:
                normalize.run_normalized(
                    input_file=str(source_flows),
                    out_dir=str(normalized_dir),
                    net_cfg={
                        "include_cidrs": effective_include_cidrs,
                        "exclude_cidrs": effective_exclude_cidrs,
                        "drop_outside": effective_drop_outside,
                    },
                )

            execute("validate_normalized_flows", stage_flows)
        else:
            if raw_mode:
                ingest_dir = run_dir / "ingest"
                execute(
                    "ingest",
                    lambda: ingest.run(
                        out_dir=str(ingest_dir),
                        pcap_inputs=pcap_list,
                        netflow_inputs=netflow_list,
                        zeek_bin=zeek_bin,
                        zeek_scripts=list(zeek_scripts or []),
                        nfdump_bin=nfdump_bin,
                        netflow_format=netflow_format,
                    ),
                )
                normalize_input = ingest_dir
            else:
                source = Path(str(input_path)).expanduser().resolve()
                if source.is_file():
                    prepared_dir = run_dir / "preprocessed_input"
                    if _is_within(source, run_dir):
                        raise ValueError(
                            "The preprocessed input must be outside the selected "
                            "run directory so reruns can clean stale inputs safely."
                        )

                    def stage_prepare_input() -> None:
                        if prepared_dir.exists():
                            shutil.rmtree(prepared_dir)
                        prepared_dir.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(source, prepared_dir / source.name)

                    execute("prepare_input", stage_prepare_input)
                    normalize_input = prepared_dir
                else:
                    normalize_input = source

            execute(
                "normalize",
                lambda: normalize.run(
                    input_dir=str(normalize_input),
                    out_dir=str(normalized_dir),
                    net_cfg={
                        "include_cidrs": effective_include_cidrs,
                        "exclude_cidrs": effective_exclude_cidrs,
                        "drop_outside": effective_drop_outside,
                    },
                ),
            )

        execute(
            "inventory",
            lambda: inventory.run(
                flows_path=str(normalized_flows),
                out_dir=str(inventory_dir),
            ),
        )
        execute(
            "enrich",
            lambda: enrich.run(
                flows_path=str(normalized_flows),
                out_dir=str(enriched_dir),
                pcap_inputs=pcap_list,
                p0f_bin=p0f_bin,
                cpe_map_path=cpe_map_path,
            ),
        )
        execute(
            "analyze",
            lambda: analyze.run(
                flows_path=str(normalized_flows),
                out_dir=str(graph_dir),
                hosts_path=str(inventory_dir / "hosts.jsonl"),
                enriched_hosts_path=str(enriched_dir / "enriched_hosts.jsonl"),
                min_flows=max(1, int(min_flows)),
            ),
        )
        execute(
            "criticality",
            lambda: criticality.run(
                graph_path=str(graph_dir / "graph.json"),
                out_dir=str(criticality_dir),
                hosts_path=str(enriched_dir / "enriched_hosts.jsonl"),
                external_cmd=external_cmd,
                dump_input_path=(
                    str(criticality_dir / "criticality_input.json")
                    if external_cmd
                    else None
                ),
                external_timeout=external_timeout,
            ),
        )
        execute(
            "export",
            lambda: export.run(
                hosts_path=str(inventory_dir / "hosts.jsonl"),
                graph_path=str(graph_dir / "graph.json"),
                criticality_path=str(criticality_dir / "criticality.jsonl"),
                out_dir=str(report_dir),
                title=title,
                pdf=pdf,
                enriched_path=str(enriched_dir / "enriched_hosts.jsonl"),
                top_k=max(1, int(top_k)),
            ),
        )
        manifest["status"] = "completed"
        manifest["finished_at"] = _utc_now()
        manifest["elapsed_seconds"] = round(time.perf_counter() - started_clock, 6)
        manifest["outputs"] = _output_counts(run_dir)
        _write_manifest(manifest_path, manifest)
        print(f"[run] Completed. Manifest -> {manifest_path}")
        return str(manifest_path)
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["finished_at"] = _utc_now()
        manifest["elapsed_seconds"] = round(time.perf_counter() - started_clock, 6)
        manifest["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
        manifest["outputs"] = _output_counts(run_dir)
        _write_manifest(manifest_path, manifest)
        raise
