"""CLI helpers for the ingest stage (Zeek + nfdump orchestration)."""

import os
import re
import shutil
import subprocess
from typing import Iterable, Sequence


PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.pcap.gz', '.pcapng.gz')
NETFLOW_EXTENSIONS = ('.nfcapd', '.nfdump', '.netflow', '.flow', '.nf')
NETFLOW_PREFIXES = ('nfcapd.',)


class IngestError(RuntimeError):
    """Raised when ingest orchestration fails."""


def _ensure_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise IngestError(f"Tool '{name}' was not found in PATH.")
    return path


def _matches_name(
    path: str,
    extensions: Sequence[str],
    prefixes: Sequence[str],
) -> bool:
    name = os.path.basename(path).lower()
    return (
        (not extensions and not prefixes)
        or name.endswith(tuple(extensions))
        or name.startswith(tuple(prefixes))
    )


def _collect_files(
    inputs: Sequence[str],
    extensions: Sequence[str],
    prefixes: Sequence[str] = (),
) -> list[str]:
    """Expand files/directories and filter by extension list."""
    files: list[str] = []
    for item in inputs:
        if not item:
            continue
        expanded = os.path.abspath(item)
        if os.path.isdir(expanded):
            for root, _, names in os.walk(expanded):
                for fname in names:
                    if not _matches_name(fname, extensions, prefixes):
                        continue
                    files.append(os.path.join(root, fname))
        elif os.path.isfile(expanded):
            if _matches_name(expanded, extensions, prefixes):
                files.append(expanded)
        else:
            raise IngestError(f"Path '{item}' does not exist.")
    return sorted(set(files), key=str.lower)


def _safe_stem(path: str) -> str:
    name = os.path.basename(path)
    value = re.sub(r'[^A-Za-z0-9_-]+', '_', name).strip('_')
    return value or 'input'


def _reset_output_dir(path: str) -> None:
    """Create an empty stage directory so reruns cannot mix stale inputs."""
    if os.path.lexists(path):
        if os.path.islink(path) or os.path.isfile(path):
            os.unlink(path)
        else:
            shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)


def _run_zeek(pcap_files: Sequence[str], out_dir: str, zeek_bin: str, zeek_scripts: Sequence[str] | None):
    """Execute Zeek over the supplied PCAP files and write logs to out_dir."""
    if not pcap_files:
        return
    zeek_path = _ensure_tool(zeek_bin)
    os.makedirs(out_dir, exist_ok=True)
    # Run captures independently so their standard log names cannot overwrite
    # each other and so each Zeek command has exactly one trace input.
    for index, file_path in enumerate(sorted(pcap_files, key=str.lower), start=1):
        capture_out = os.path.join(out_dir, f'{index:04d}_{_safe_stem(file_path)}')
        os.makedirs(capture_out, exist_ok=True)
        cmd = [zeek_path, '-r', file_path]
        if zeek_scripts:
            cmd.extend(zeek_scripts)
        else:
            # Default local policy.
            cmd.append('local')
        try:
            subprocess.run(cmd, cwd=capture_out, check=True)
        except subprocess.CalledProcessError as exc:
            raise IngestError(
                f"Zeek failed while processing PCAP input {file_path}: {exc}"
            ) from exc


def _run_nfdump(flow_files: Sequence[str], out_dir: str, nfdump_bin: str, output_format: str):
    """Export nfdump data as CSV/JSON using the requested format."""
    if not flow_files:
        return
    nfdump_path = _ensure_tool(nfdump_bin)
    os.makedirs(out_dir, exist_ok=True)
    fmt = output_format.lower()
    if fmt not in ('csv', 'json'):
        raise IngestError("Supported nfdump export formats are 'csv' and 'json'.")
    for index, flow_path in enumerate(sorted(flow_files, key=str.lower), start=1):
        base = f'{index:04d}_{_safe_stem(flow_path)}'
        suffix = 'csv' if fmt == 'csv' else 'json'
        out_file = os.path.join(out_dir, f'{base}.{suffix}')
        cmd = [nfdump_path, '-r', flow_path, '-o', fmt, '-q']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as exc:
            raise IngestError(f"nfdump failed for file {flow_path}: {exc.stderr}") from exc
        with open(out_file, 'w', encoding='utf-8') as fh:
            fh.write(result.stdout)


def run(
    out_dir: str,
    pcap_inputs: Iterable[str] | None = None,
    netflow_inputs: Iterable[str] | None = None,
    zeek_bin: str = 'zeek',
    zeek_scripts: Iterable[str] | None = None,
    nfdump_bin: str = 'nfdump',
    netflow_format: str = 'csv',
):
    """Entry point triggered from CLI; coordinates Zeek/nfdump execution."""
    pcap_list = _collect_files(list(pcap_inputs or []), PCAP_EXTENSIONS)
    netflow_list = _collect_files(
        list(netflow_inputs or []),
        NETFLOW_EXTENSIONS,
        NETFLOW_PREFIXES,
    )
    if not pcap_list and not netflow_list:
        raise IngestError("Provide at least one PCAP or NetFlow input path.")

    output_root = os.path.abspath(out_dir)
    for source_path in [*pcap_list, *netflow_list]:
        try:
            source_inside_output = (
                os.path.commonpath([output_root, source_path]) == output_root
            )
        except ValueError:
            source_inside_output = False
        if source_inside_output:
            raise IngestError(
                "Raw input files must be outside the ingest output directory: "
                f"{source_path}"
            )

    zeek_out = os.path.join(out_dir, 'zeek')
    netflow_out = os.path.join(out_dir, 'nfdump')
    # Clear both source-specific outputs even when only one input type is
    # present; otherwise a second run could normalize logs from the first.
    _reset_output_dir(zeek_out)
    _reset_output_dir(netflow_out)

    if pcap_list:
        print(f"[ingest] Running Zeek over {len(pcap_list)} PCAP files -> {zeek_out}")
        _run_zeek(
            pcap_files=pcap_list,
            out_dir=zeek_out,
            zeek_bin=zeek_bin,
            zeek_scripts=list(zeek_scripts) if zeek_scripts else None,
        )
    if netflow_list:
        print(f"[ingest] Exporting {len(netflow_list)} NetFlow files with nfdump -> {netflow_out}")
        _run_nfdump(
            flow_files=netflow_list,
            out_dir=netflow_out,
            nfdump_bin=nfdump_bin,
            output_format=netflow_format,
        )
    print(f"[ingest] Done. Outputs are in {out_dir}.")
