"""Aggregate normalized flows into a minimal host/service inventory."""

import csv
import hashlib
import json
import os
import socket
from collections import Counter
from typing import Dict, Iterable

from .endpoints import infer_endpoints
from .utils import write_jsonl


_PKG_DIR = os.path.dirname(__file__)
_REPO_ROOT = os.path.dirname(_PKG_DIR)

SERVICE_REGISTRY_PATHS = [
    os.environ.get('PMMAP_SERVICE_REGISTRY_PATH'),
    os.path.join(_REPO_ROOT, 'data', 'iana-service-names-port-numbers.csv'),
]


def _candidate_files(path: str | None) -> list[str]:
    """Return concrete IANA registry files to try loading."""
    candidates: list[str] = []
    if not path:
        return candidates
    if os.path.isfile(path):
        candidates.append(path)
    elif os.path.isdir(path):
        nested = os.path.join(path, 'iana-service-names-port-numbers.csv')
        if os.path.isfile(nested):
            candidates.append(nested)
    return candidates


def _load_service_registry(
    paths: Iterable[str | None] | None = None,
) -> tuple[dict[tuple[str, int], str], dict]:
    """Load the IANA service registry and retain reproducibility provenance."""
    for candidate in paths or SERVICE_REGISTRY_PATHS:
        files = _candidate_files(candidate)
        if not files:
            continue
        file_path = os.path.realpath(os.path.abspath(files[0]))
        service_map: dict[tuple[str, int], str] = {}
        try:
            with open(
                file_path,
                'r',
                encoding='utf-8-sig',
                errors='replace',
                newline='',
            ) as fh:
                for row in csv.DictReader(fh):
                    name = str(row.get('Service Name') or '').strip()
                    port_str = str(row.get('Port Number') or '').strip()
                    proto = str(row.get('Transport Protocol') or '').strip().lower()
                    if not name or not port_str or not proto:
                        continue
                    # Range rows describe unassigned/reserved intervals, not
                    # one concrete service endpoint.
                    if '-' in port_str:
                        continue
                    try:
                        port = int(port_str)
                    except ValueError:
                        continue
                    if not 0 < port <= 65535:
                        continue
                    key = (proto, port)
                    service_map.setdefault(key, name)
            if service_map:
                with open(file_path, "rb") as fh:
                    source_sha256 = hashlib.sha256(fh.read()).hexdigest()
                return service_map, {
                    "loaded": True,
                    "kind": "iana_service_names_port_numbers",
                    "path": file_path,
                    "sha256": source_sha256,
                    "entries": len(service_map),
                    "source_url": (
                        "https://www.iana.org/assignments/"
                        "service-names-port-numbers/"
                        "service-names-port-numbers.csv"
                    ),
                    "license": "CC0-1.0",
                }
        except OSError:
            continue
    return {}, {
        "loaded": False,
        "kind": "iana_service_names_port_numbers",
        "path": None,
        "sha256": None,
        "entries": 0,
        "source_url": (
            "https://www.iana.org/assignments/service-names-port-numbers/"
            "service-names-port-numbers.csv"
        ),
        "license": "CC0-1.0",
    }


SERVICE_MAP, SERVICE_REGISTRY_DATABASE = _load_service_registry()


def service_registry_provenance() -> dict:
    """Return a copy of the effective IANA service-registry provenance."""
    return dict(SERVICE_REGISTRY_DATABASE)


def _normalize_proto(value) -> str:
    """Treat protocol names in a case-insensitive way."""
    if value is None:
        return ''
    return str(value).lower()


def _to_int(value, default=0):
    """Best-effort conversion to int, falling back to default."""
    try:
        return int(value)
    except Exception:
        return default


def _ensure_host(store: Dict[str, dict], ip: str) -> dict:
    """Return the mutable host accumulator for the given IP."""
    return store.setdefault(
        ip,
        {
            'macs': set(),
            'hostnames': set(),
            'fqdns': set(),
            'domains': set(),
            'bytes_in': 0,
            'bytes_out': 0,
            'bytes_observed': 0,
            'flows_in': 0,
            'flows_out': 0,
            'services_offered': Counter(),
            'services_used': Counter(),
            'first_seen': None,
            'last_seen': None,
            'roles': set(),
            'scope_values': set(),
        },
    )


def _update_time(host: dict, ts: float):
    """Maintain first/last seen timestamps per host."""
    if ts is None:
        return
    if host['first_seen'] is None or ts < host['first_seen']:
        host['first_seen'] = ts
    if host['last_seen'] is None or ts > host['last_seen']:
        host['last_seen'] = ts


def _apply_dhcp_metadata(hosts: Dict[str, dict], record: dict):
    """Enrich host entry with DHCP assignment data if present."""
    assigned_ip = record.get('dhcp_assigned_ip') or record.get('dhcp_requested_ip')
    src_ip = record.get('src_ip')
    target_ip = assigned_ip or src_ip
    if not target_ip:
        return
    host = _ensure_host(hosts, target_ip)
    for key, field in (
        ('macs', 'dhcp_mac'),
        ('hostnames', 'dhcp_host_name'),
        ('fqdns', 'dhcp_fqdn'),
        ('domains', 'dhcp_domain'),
    ):
        value = record.get(field)
        if value and value not in ('-', ''):
            host[key].add(value)
    lease_time = record.get('dhcp_lease_time')
    if lease_time is not None:
        host.setdefault('dhcp_lease_times', []).append(lease_time)
    msg_types = record.get('dhcp_msg_types')
    if msg_types:
        host.setdefault('dhcp_msg_types', set()).update(msg_types)


def _format_services(counter: Counter) -> Iterable[dict]:
    """Turn service counters into deterministic list payload."""
    for (proto, port), count in sorted(counter.items(), key=lambda item: (item[0][0], item[0][1])):
        if port == 0:
            continue
        yield {'proto': proto, 'port': port, 'flows': count}


def _infer_role(proto: str, port: int) -> str | None:
    """Guess host role such as DNS, mail, or web from proto/port pairing."""
    if port <= 0:
        return None
    service_name = SERVICE_MAP.get((proto, port))
    if not service_name:
        try:
            service_name = socket.getservbyport(port, proto)
        except OSError:
            service_name = None
    if not service_name:
        return None
    needle = service_name.lower()
    if 'dns' in needle or needle == 'domain':
        return 'dns_server'
    if 'dhcp' in needle:
        return 'dhcp_server' if port == 67 else 'dhcp_client'
    if needle in ('kerberos', 'kerberos-sec'):
        return 'kerberos'
    if needle.startswith('ldap'):
        return 'ldap'
    if 'ntp' in needle:
        return 'ntp_server'
    if needle in ('smtp', 'submission'):
        return 'mail_server'
    if needle in ('pop3', 'imap', 'imap2'):
        return 'mail_client'
    if needle in ('https', 'http', 'http-alt'):
        return 'web_server'
    return None


def run(flows_path: str, out_dir: str):
    """Aggregate flows.jsonl into hosts.jsonl with bytes/roles/service stats."""
    if os.path.isdir(flows_path):
        flows_file = os.path.join(flows_path, 'flows.jsonl')
    else:
        flows_file = flows_path
    if not os.path.isfile(flows_file):
        raise FileNotFoundError(f"Flow file '{flows_file}' does not exist.")

    hosts: Dict[str, dict] = {}
    with open(flows_file, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            src_ip = rec.get('src_ip')
            dst_ip = rec.get('dst_ip')
            proto = _normalize_proto(rec.get('proto'))
            ts = rec.get('ts')
            bytes_val = _to_int(rec.get('bytes', 0))
            forward_bytes = rec.get('bytes_src_to_dst')
            reverse_bytes = rec.get('bytes_dst_to_src')
            directionality = rec.get('traffic_directionality')
            if forward_bytes is not None or reverse_bytes is not None:
                src_to_dst_bytes = _to_int(forward_bytes)
                dst_to_src_bytes = _to_int(reverse_bytes)
            elif directionality == 'bidirectional_total':
                src_to_dst_bytes = 0
                dst_to_src_bytes = 0
            else:
                # Canonical and ordinary unidirectional flow exports describe
                # counters in the observed source-to-destination direction.
                src_to_dst_bytes = bytes_val
                dst_to_src_bytes = 0

            if src_ip:
                host = _ensure_host(hosts, src_ip)
                host['bytes_out'] += src_to_dst_bytes
                host['bytes_in'] += dst_to_src_bytes
                host['bytes_observed'] += bytes_val
                host['flows_out'] += 1
                if isinstance(rec.get('src_in_scope'), bool):
                    host['scope_values'].add(rec['src_in_scope'])
                _update_time(host, ts)
            if dst_ip:
                host = _ensure_host(hosts, dst_ip)
                host['bytes_in'] += src_to_dst_bytes
                host['bytes_out'] += dst_to_src_bytes
                host['bytes_observed'] += bytes_val
                host['flows_in'] += 1
                if isinstance(rec.get('dst_in_scope'), bool):
                    host['scope_values'].add(rec['dst_in_scope'])
                _update_time(host, ts)

            endpoints = infer_endpoints(rec, SERVICE_MAP)
            if endpoints.service_observed:
                client = _ensure_host(hosts, endpoints.client_ip)
                server = _ensure_host(hosts, endpoints.server_ip)
                service_key = (endpoints.proto, endpoints.server_port)
                client['services_used'][service_key] += 1
                server['services_offered'][service_key] += 1
                role = _infer_role(endpoints.proto, endpoints.server_port)
                if role:
                    server['roles'].add(role)

            if rec.get('dhcp_mac') or rec.get('dhcp_assigned_ip'):
                _apply_dhcp_metadata(hosts, rec)

    os.makedirs(out_dir, exist_ok=True)
    host_records = []
    for ip, data in sorted(hosts.items(), key=lambda item: item[0]):
        record = {
            'ip': ip,
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'macs': sorted(data['macs']),
            'hostnames': sorted(data['hostnames']),
            'fqdns': sorted(data['fqdns']),
            'domains': sorted(data['domains']),
            'bytes_in': data['bytes_in'],
            'bytes_out': data['bytes_out'],
            'bytes_observed': data['bytes_observed'],
            'flows_in': data['flows_in'],
            'flows_out': data['flows_out'],
            'services_offered': list(_format_services(data['services_offered'])),
            'services_used': list(_format_services(data['services_used'])),
            'roles': sorted(data['roles']),
            'in_scope': (
                True
                if True in data['scope_values']
                else False
                if False in data['scope_values']
                else None
            ),
        }
        if 'dhcp_lease_times' in data:
            record['dhcp_lease_times'] = data['dhcp_lease_times']
        if 'dhcp_msg_types' in data:
            record['dhcp_msg_types'] = sorted(data['dhcp_msg_types'])
        host_records.append(record)

    out_path = os.path.join(out_dir, 'hosts.jsonl')
    write_jsonl(out_path, host_records)
    print(f"Host inventory saved to {out_path} ({len(host_records)} records).")
