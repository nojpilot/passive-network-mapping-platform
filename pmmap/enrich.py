"""Enrichment stage: fingerprint aggregation and optional p0f OS guesses."""

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterable, Sequence

from .cpe import CPEMapper, SUPPORTED_CPE_SECTIONS, map_host_fingerprints
from .utils import write_jsonl


PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.pcap.gz', '.pcapng.gz')


class EnrichError(RuntimeError):
    """Raised when enrichment fails."""


def _load_flows(flows_path: str):
    """Yield parsed flow objects from flows.jsonl."""
    if os.path.isdir(flows_path):
        flows_file = os.path.join(flows_path, 'flows.jsonl')
    else:
        flows_file = flows_path
    if not os.path.isfile(flows_file):
        raise FileNotFoundError(f"Soubor s toky '{flows_file}' neexistuje.")
    with open(flows_file, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _collect_files(inputs: Sequence[str], extensions: Sequence[str]) -> list[str]:
    """Expand files/directories and filter by extension list."""
    files: list[str] = []
    for item in inputs or []:
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
            raise EnrichError(f"Cesta '{item}' neexistuje.")
    return files


def _parse_p0f_log(text: str) -> dict[str, Counter]:
    """Parse p0f log lines to accumulate non-fuzzy OS guesses per IP."""
    ip_os: dict[str, Counter] = defaultdict(Counter)
    # p0f v3 log line format: mod=...|cli=IP/port|srv=IP/port|subj=cli|os=Windows NT kernel|...
    pattern_os_line = re.compile(r'os=([^|]+)')
    pattern_cli = re.compile(r'cli=([0-9]{1,3}(?:\.[0-9]{1,3}){3})/')
    pattern_srv = re.compile(r'srv=([0-9]{1,3}(?:\.[0-9]{1,3}){3})/')
    pattern_subj = re.compile(r'subj=([a-z]+)')
    pattern_params = re.compile(r'(?:^|\|)params=([^|]*)')
    # fallback for very old log style with "genre"
    pattern_legacy = re.compile(r'(\d+\.\d+\.\d+\.\d+)[^\n]*genre\s+([^|\n]+)')
    for line in text.splitlines():
        params_match = pattern_params.search(line)
        params = {
            item.strip().lower()
            for item in (params_match.group(1).split(',') if params_match else [])
            if item.strip()
        }
        # The output schema currently has no confidence field. Promoting a
        # p0f approximate match without its "fuzzy" qualifier would make weak
        # evidence look exact, so retain only non-fuzzy guesses.
        if 'fuzzy' in params:
            continue
        os_match = pattern_os_line.search(line)
        if os_match:
            guess = os_match.group(1).strip()
            if guess and guess not in ('???', 'unknown'):
                subj_match = pattern_subj.search(line)
                subj = subj_match.group(1) if subj_match else None
                cli = pattern_cli.search(line)
                srv = pattern_srv.search(line)
                ip = None
                if subj == 'cli' and cli:
                    ip = cli.group(1)
                elif subj == 'srv' and srv:
                    ip = srv.group(1)
                elif cli:
                    ip = cli.group(1)
                elif srv:
                    ip = srv.group(1)
                if ip:
                    ip_os[ip][guess] += 1
                continue
        legacy_match = pattern_legacy.search(line)
        if legacy_match:
            ip = legacy_match.group(1)
            genre = legacy_match.group(2).strip()
            if ip and genre:
                ip_os[ip][genre] += 1
    return ip_os


def _run_p0f(pcap_files: Sequence[str], p0f_bin: str) -> dict[str, Counter]:
    """Run p0f over supplied pcaps; return OS guess counters per IP."""
    results: dict[str, Counter] = defaultdict(Counter)
    if not pcap_files:
        return results
    p0f_path = shutil.which(p0f_bin)
    if not p0f_path:
        print(f"[enrich] p0f '{p0f_bin}' was not found, skipping.")
        return results
    for pcap in pcap_files:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            log_path = tmp.name
        cmd = [p0f_path, '-r', pcap, '-o', log_path]
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as exc:
            print(f"[enrich] p0f failed for {pcap}: {exc}")
            try:
                os.remove(log_path)
            except OSError:
                pass
            continue
        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as fh:
                parsed = _parse_p0f_log(fh.read())
                for ip, counter in parsed.items():
                    results[ip].update(counter)
        finally:
            try:
                os.remove(log_path)
            except OSError:
                pass
    return results


def _add_value(counter: Counter, value):
    if value:
        counter[value] += 1


def _format_counter(counter: Counter) -> list[dict]:
    return [{'value': val, 'count': count} for val, count in counter.most_common()]


def _write_manifest(path: str, payload: dict) -> None:
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(temporary, path)


def run(
    flows_path: str,
    out_dir: str,
    pcap_inputs: Iterable[str] | None = None,
    p0f_bin: str = 'p0f',
    cpe_map_path: str | None = None,
):
    """Aggregate fingerprints from flows and optional p0f OS guesses."""
    hosts: dict[str, dict] = defaultdict(lambda: {
        'ja3': Counter(),
        'ja3s': Counter(),
        'hassh': Counter(),
        'hassh_server': Counter(),
        'sni_served': Counter(),
        'sni_used': Counter(),
        'dns_queries': Counter(),
        'os': Counter(),
        'scope_values': set(),
    })

    # CPE inference is strictly opt-in through this explicit function argument.
    # Environment variables and bundled examples are never loaded implicitly.
    cpe_mapper = CPEMapper.from_file(cpe_map_path) if cpe_map_path else None
    if cpe_mapper:
        print(f"[enrich] Using CPE mapping: {cpe_mapper.source}")

    for rec in _load_flows(flows_path):
        src_ip = rec.get('src_ip')
        dst_ip = rec.get('dst_ip')
        ja3 = rec.get('ja3')
        ja3s = rec.get('ja3s')
        hassh = rec.get('hassh')
        hassh_server = rec.get('hassh_server')
        sni = rec.get('sni')
        dns_qname = rec.get('dns_qname')

        if src_ip:
            hosts[src_ip]
            if isinstance(rec.get('src_in_scope'), bool):
                hosts[src_ip]['scope_values'].add(rec['src_in_scope'])
        if dst_ip:
            hosts[dst_ip]
            if isinstance(rec.get('dst_in_scope'), bool):
                hosts[dst_ip]['scope_values'].add(rec['dst_in_scope'])
        if src_ip and ja3:
            _add_value(hosts[src_ip]['ja3'], ja3)
        if dst_ip and ja3s:
            _add_value(hosts[dst_ip]['ja3s'], ja3s)
        if src_ip and hassh:
            _add_value(hosts[src_ip]['hassh'], hassh)
        if dst_ip and hassh_server:
            _add_value(hosts[dst_ip]['hassh_server'], hassh_server)
        if dst_ip and sni:
            _add_value(hosts[dst_ip]['sni_served'], sni)
        if src_ip and sni:
            _add_value(hosts[src_ip]['sni_used'], sni)
        if src_ip and dns_qname:
            _add_value(hosts[src_ip]['dns_queries'], dns_qname)

    pcap_list = _collect_files(list(pcap_inputs or []), PCAP_EXTENSIONS)
    if pcap_list:
        print(f"[enrich] Running p0f over {len(pcap_list)} PCAP files.")
        os_fingerprints = _run_p0f(pcap_list, p0f_bin)
        for ip, guesses in os_fingerprints.items():
            hosts[ip]['os'].update(guesses)

    os.makedirs(out_dir, exist_ok=True)
    records = []
    hosts_with_cpe = 0
    hypotheses_by_source: Counter = Counter()
    matched_evidence_values: set[tuple[str, str]] = set()
    for ip, data in sorted(hosts.items(), key=lambda item: item[0]):
        record = {
            'ip': ip,
            'client_ja3': _format_counter(data['ja3']),
            'server_ja3s': _format_counter(data['ja3s']),
            'hassh': _format_counter(data['hassh']),
            'server_hassh': _format_counter(data['hassh_server']),
            'sni_served': _format_counter(data['sni_served']),
            'sni_used': _format_counter(data['sni_used']),
            'dns_queries': _format_counter(data['dns_queries']),
            'in_scope': (
                True
                if True in data['scope_values']
                else False
                if False in data['scope_values']
                else None
            ),
        }
        if data['os']:
            record['os_guesses'] = _format_counter(data['os'])
        cpe_entries = map_host_fingerprints(
            mapper=cpe_mapper,
            ja3=data['ja3'].keys(),
            ja3s=data['ja3s'].keys(),
            hassh=data['hassh'].keys(),
            hassh_server=data['hassh_server'].keys(),
        ) if cpe_mapper else []
        if cpe_entries:
            record['cpe'] = cpe_entries
            hosts_with_cpe += 1
            for entry in cpe_entries:
                source = str(entry.get("source", ""))
                evidence = str(entry.get("evidence", ""))
                hypotheses_by_source[source] += 1
                matched_evidence_values.add((source, evidence))
        records.append(record)

    out_path = os.path.join(out_dir, 'enriched_hosts.jsonl')
    write_jsonl(out_path, records)
    mapping_entries = {
        section: len(cpe_mapper.mapping.get(section, {}))
        for section in SUPPORTED_CPE_SECTIONS
        if cpe_mapper and section in cpe_mapper.mapping
    }
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": {
            "flows_path": os.path.realpath(os.path.abspath(flows_path)),
            "pcap_files": [os.path.realpath(path) for path in pcap_list],
        },
        "cpe_mapping": {
            "enabled": cpe_mapper is not None,
            "path": cpe_mapper.source if cpe_mapper else None,
            "sha256": cpe_mapper.source_sha256 if cpe_mapper else None,
            "entries_by_section": mapping_entries,
        },
        "matches": {
            "hosts_with_hypotheses": hosts_with_cpe,
            "hypotheses_emitted": sum(hypotheses_by_source.values()),
            "unique_evidence_values_matched": len(matched_evidence_values),
            "hypotheses_by_source": {
                section: int(hypotheses_by_source[section])
                for section in SUPPORTED_CPE_SECTIONS
            },
        },
        "output": {
            "enriched_hosts_path": os.path.realpath(out_path),
            "hosts": len(records),
        },
    }
    manifest_path = os.path.join(out_dir, "enrichment_manifest.json")
    _write_manifest(manifest_path, manifest)
    print(f"[enrich] Wrote {len(records)} records -> {out_path}")
    print(f"[enrich] Manifest -> {manifest_path}")
