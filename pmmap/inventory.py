"""Aggregate normalized flows into a minimal host/service inventory."""

import json
import os
import socket
from collections import Counter
from typing import Dict, Iterable

from .utils import write_jsonl


_PKG_DIR = os.path.dirname(__file__)
_REPO_ROOT = os.path.dirname(_PKG_DIR)

NMAP_SERVICE_PATHS = [
    os.environ.get('NMAP_SERVICES_PATH'),
    os.path.join(_REPO_ROOT, 'data', 'nmap-services'),
    # '/usr/share/nmap/nmap-services',
    # '/usr/local/share/nmap/nmap-services',
]


def _candidate_files(path: str) -> list[str]:
    """Return concrete files to try loading for the nmap-services database."""
    candidates: list[str] = []
    if not path:
        return candidates
    if os.path.isfile(path):
        candidates.append(path)
    elif os.path.isdir(path):
        nested = os.path.join(path, 'nmap-services')
        if os.path.isfile(nested):
            candidates.append(nested)
    return candidates


def _load_nmap_services() -> dict[tuple[str, int], str]:
    """Load the nmap-services mapping once so role detection has rich data."""
    service_map: dict[tuple[str, int], str] = {}
    for candidate in NMAP_SERVICE_PATHS:
        files = _candidate_files(candidate)
        if not files:
            continue
        file_path = files[0]
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    name = parts[0]
                    port_proto = parts[1]
                    if '/' not in port_proto:
                        continue
                    port_str, proto = port_proto.split('/', 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        continue
                    key = (proto.lower(), port)
                    service_map.setdefault(key, name)
            if service_map:
                return service_map
        except OSError:
            continue
    return service_map


SERVICE_MAP = _load_nmap_services()


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
            'flows_in': 0,
            'flows_out': 0,
            'services_offered': Counter(),
            'services_used': Counter(),
            'first_seen': None,
            'last_seen': None,
            'roles': set(),
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

            if src_ip:
                host = _ensure_host(hosts, src_ip)
                host['bytes_out'] += bytes_val
                host['flows_out'] += 1
                _update_time(host, ts)
                dst_port = _to_int(rec.get('dst_port', 0))
                host['services_used'][(proto, dst_port)] += 1
            if dst_ip:
                host = _ensure_host(hosts, dst_ip)
                host['bytes_in'] += bytes_val
                host['flows_in'] += 1
                _update_time(host, ts)
                dst_port = _to_int(rec.get('dst_port', 0))
                host['services_offered'][(proto, dst_port)] += 1
                role = _infer_role(proto, dst_port)
                if role:
                    host['roles'].add(role)

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
            'flows_in': data['flows_in'],
            'flows_out': data['flows_out'],
            'services_offered': list(_format_services(data['services_offered'])),
            'services_used': list(_format_services(data['services_used'])),
            'roles': sorted(data['roles']),
        }
        if 'dhcp_lease_times' in data:
            record['dhcp_lease_times'] = data['dhcp_lease_times']
        if 'dhcp_msg_types' in data:
            record['dhcp_msg_types'] = sorted(data['dhcp_msg_types'])
        host_records.append(record)

    out_path = os.path.join(out_dir, 'hosts.jsonl')
    write_jsonl(out_path, host_records)
    print(f"Host inventory saved to {out_path} ({len(host_records)} records).")
