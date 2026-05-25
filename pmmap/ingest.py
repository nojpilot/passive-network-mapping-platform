"""CLI helpers for the ingest stage (Zeek + nfdump orchestration)."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Sequence


PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.pcap.gz', '.pcapng.gz')
NETFLOW_EXTENSIONS = ('.nfcapd', '.nfdump', '.netflow', '.flow', '.nf')


class IngestError(RuntimeError):
    """Raised when ingest orchestration fails."""


def _ensure_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise IngestError(f"Tool '{name}' was not found in PATH.")
    return path


def _collect_files(inputs: Sequence[str], extensions: Sequence[str]) -> list[str]:
    """Expand files/directories and filter by extension list."""
    files: list[str] = []
    for item in inputs:
        if not item:
            continue
        expanded = os.path.abspath(item)
        if os.path.isdir(expanded):
            for root, _, names in os.walk(expanded):
                for fname in names:
                    if extensions and not fname.lower().endswith(extensions):
                        continue
                    files.append(os.path.join(root, fname))
        elif os.path.isfile(expanded):
            if not extensions or expanded.lower().endswith(extensions):
                files.append(expanded)
        else:
            raise IngestError(f"Path '{item}' does not exist.")
    return files


def _run_zeek(pcap_files: Sequence[str], out_dir: str, zeek_bin: str, zeek_scripts: Sequence[str] | None):
    """Execute Zeek over the supplied PCAP files and write logs to out_dir."""
    if not pcap_files:
        return
    zeek_path = _ensure_tool(zeek_bin)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [zeek_path]
    for file_path in pcap_files:
        cmd.extend(['-r', file_path])
    if zeek_scripts:
        cmd.extend(zeek_scripts)
    else:
        # Default local policy.
        cmd.append('local')
    try:
        subprocess.run(cmd, cwd=out_dir, check=True)
    except subprocess.CalledProcessError as exc:
        raise IngestError(f"Zeek failed while processing PCAP inputs: {exc}") from exc


def _run_nfdump(flow_files: Sequence[str], out_dir: str, nfdump_bin: str, output_format: str):
    """Export nfdump data as CSV/JSON using the requested format."""
    if not flow_files:
        return
    nfdump_path = _ensure_tool(nfdump_bin)
    os.makedirs(out_dir, exist_ok=True)
    fmt = output_format.lower()
    if fmt not in ('csv', 'json'):
        raise IngestError("Supported nfdump export formats are 'csv' and 'json'.")
    for flow_path in flow_files:
        base = Path(flow_path).stem
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
    netflow_list = _collect_files(list(netflow_inputs or []), NETFLOW_EXTENSIONS)
    if not pcap_list and not netflow_list:
        raise IngestError("Provide at least one PCAP or NetFlow input path.")

    zeek_out = os.path.join(out_dir, 'zeek')
    netflow_out = os.path.join(out_dir, 'nfdump')

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
