"""Build a directed graph of service dependencies from normalized flows."""

import json
import os
import socket
from collections import defaultdict
from typing import Dict

from .inventory import SERVICE_MAP
from .utils import write_jsonl


def _normalize_proto(value) -> str:
    if value is None:
        return ''
    return str(value).lower()


def _to_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _infer_role(proto: str, port: int) -> str | None:
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


def _load_jsonl(path: str):
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _load_flows(flows_path: str):
    if os.path.isdir(flows_path):
        flows_file = os.path.join(flows_path, 'flows.jsonl')
    else:
        flows_file = flows_path
    if not os.path.isfile(flows_file):
        raise FileNotFoundError(f"Flow file '{flows_file}' does not exist.")
    yield from _load_jsonl(flows_file)


def _load_host_metadata(hosts_path: str | None) -> dict[str, dict]:
    """Load host-level metadata (roles/os) from hosts.jsonl or enriched_hosts.jsonl."""
    if not hosts_path or not os.path.isfile(hosts_path):
        return {}
    meta: dict[str, dict] = {}
    for rec in _load_jsonl(hosts_path):
        ip = rec.get('ip')
        if not ip:
            continue
        meta.setdefault(ip, {})
        roles = rec.get('roles') or []
        if roles:
            meta[ip].setdefault('roles', set()).update(roles)
        os_guesses = rec.get('os_guesses')
        if os_guesses and isinstance(os_guesses, list):
            best = os_guesses[0].get('value') if os_guesses else None
            if best:
                meta[ip]['os'] = best
        cpe_entries = rec.get('cpe') or []
        if cpe_entries and isinstance(cpe_entries, list):
            for entry in cpe_entries:
                cpe_val = None
                if isinstance(entry, dict):
                    cpe_val = entry.get('cpe')
                elif isinstance(entry, str):
                    cpe_val = entry
                if cpe_val:
                    meta[ip].setdefault('cpe', set()).add(cpe_val)
    return meta


def run(
    flows_path: str,
    out_dir: str,
    hosts_path: str | None = None,
    enriched_hosts_path: str | None = None,
    min_flows: int = 1,
):
    """Build host-to-service graph edges with roles and name signals."""
    hosts: Dict[str, dict] = defaultdict(lambda: {'roles': set(), 'os': None, 'cpe': set()})
    services: Dict[str, dict] = {}
    edges: Dict[tuple[str, str], dict] = {}

    hosts_meta = _load_host_metadata(hosts_path)
    enriched_meta = _load_host_metadata(enriched_hosts_path)

    def _ensure_host(ip: str):
        if ip not in hosts:
            hosts[ip] = {'roles': set(), 'os': None, 'cpe': set()}
        # merge metadata if available
        if ip in hosts_meta:
            hosts[ip]['roles'].update(hosts_meta.get(ip, {}).get('roles', set()))
            if hosts_meta.get(ip, {}).get('os'):
                hosts[ip]['os'] = hosts_meta[ip]['os']
            if hosts_meta.get(ip, {}).get('cpe'):
                hosts[ip]['cpe'].update(hosts_meta[ip]['cpe'])
        if ip in enriched_meta:
            hosts[ip]['roles'].update(enriched_meta.get(ip, {}).get('roles', set()))
            if enriched_meta.get(ip, {}).get('os'):
                hosts[ip]['os'] = enriched_meta[ip]['os']
            if enriched_meta.get(ip, {}).get('cpe'):
                hosts[ip]['cpe'].update(enriched_meta[ip]['cpe'])
        return hosts[ip]

    for rec in _load_flows(flows_path):
        src_ip = rec.get('src_ip')
        dst_ip = rec.get('dst_ip')
        proto = _normalize_proto(rec.get('proto'))
        dst_port = _to_int(rec.get('dst_port', 0))
        bytes_val = _to_int(rec.get('bytes', 0))
        ts = rec.get('ts')
        sni = rec.get('sni')
        dns_qname = rec.get('dns_qname')

        if not src_ip or not dst_ip or not proto:
            continue
        _ensure_host(src_ip)
        _ensure_host(dst_ip)

        service_id = f"{dst_ip}:{dst_port}/{proto}"
        if service_id not in services:
            services[service_id] = {
                'id': service_id,
                'ip': dst_ip,
                'port': dst_port,
                'proto': proto,
                'role': _infer_role(proto, dst_port),
                'hostnames': set(),
            }
        if sni:
            services[service_id]['hostnames'].add(sni)
        if dns_qname:
            services[service_id]['hostnames'].add(dns_qname)

        edge_key = (src_ip, service_id)
        edge = edges.setdefault(edge_key, {
            'src': src_ip,
            'dst': service_id,
            'flows': 0,
            'bytes': 0,
            'sni': set(),
            'dns_qnames': set(),
            'first_seen': None,
            'last_seen': None,
        })
        edge['flows'] += 1
        edge['bytes'] += bytes_val
        if sni:
            edge['sni'].add(sni)
        if dns_qname:
            edge['dns_qnames'].add(dns_qname)
        if edge['first_seen'] is None or (ts is not None and ts < edge['first_seen']):
            edge['first_seen'] = ts
        if edge['last_seen'] is None or (ts is not None and ts > edge['last_seen']):
            edge['last_seen'] = ts

        role = _infer_role(proto, dst_port)
        if role:
            hosts[dst_ip]['roles'].add(role)

    # Filter edges with insufficient flow count
    edges = {k: v for k, v in edges.items() if v['flows'] >= min_flows}

    os.makedirs(out_dir, exist_ok=True)
    nodes_payload = []
    for ip, data in sorted(hosts.items(), key=lambda item: item[0]):
        node = {
            'id': ip,
            'type': 'host',
            'roles': sorted(data['roles']),
        }
        if data.get('os'):
            node['os'] = data['os']
        if data.get('cpe'):
            node['cpe'] = sorted(data['cpe'])
        nodes_payload.append(node)

    for svc_id, svc in sorted(services.items(), key=lambda item: item[0]):
        node = {
            'id': svc_id,
            'type': 'service',
            'ip': svc['ip'],
            'port': svc['port'],
            'proto': svc['proto'],
            'hostnames': sorted(svc['hostnames']),
        }
        if svc.get('role'):
            node['role'] = svc['role']
        nodes_payload.append(node)

    edges_payload = []
    for edge in sorted(edges.values(), key=lambda e: (e['src'], e['dst'])):
        edges_payload.append({
            'src': edge['src'],
            'dst': edge['dst'],
            'flows': edge['flows'],
            'bytes': edge['bytes'],
            'sni': sorted(edge['sni']),
            'dns_qnames': sorted(edge['dns_qnames']),
            'first_seen': edge['first_seen'],
            'last_seen': edge['last_seen'],
        })

    graph = {'nodes': nodes_payload, 'edges': edges_payload}
    out_json = os.path.join(out_dir, 'graph.json')
    with open(out_json, 'w', encoding='utf-8') as fh:
        json.dump(graph, fh, ensure_ascii=False, indent=2)

    edges_path = os.path.join(out_dir, 'edges.jsonl')
    write_jsonl(edges_path, edges_payload)
    print(f"[analyze] Graph saved to {out_json} ({len(nodes_payload)} nodes, {len(edges_payload)} edges).")
