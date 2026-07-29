"""Build a directed graph of observed client-to-service communications."""

import json
import os
import socket
from collections import defaultdict
from typing import Dict

from .endpoints import infer_endpoints
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
        if isinstance(rec.get('in_scope'), bool):
            meta[ip]['in_scope'] = rec['in_scope']
    return meta


def run(
    flows_path: str,
    out_dir: str,
    hosts_path: str | None = None,
    enriched_hosts_path: str | None = None,
    min_flows: int = 1,
):
    """Build observed host-to-service edges with roles and name signals.

    An edge is evidence of communication, not proof of a causal functional
    dependency.
    """
    hosts: Dict[str, dict] = defaultdict(
        lambda: {
            'roles': set(),
            'os': None,
            'cpe': set(),
            'scope_values': set(),
        }
    )
    services: Dict[str, dict] = {}
    edges: Dict[tuple[str, str], dict] = {}

    hosts_meta = _load_host_metadata(hosts_path)
    enriched_meta = _load_host_metadata(enriched_hosts_path)

    def _ensure_host(ip: str, in_scope: bool | None = None):
        if ip not in hosts:
            hosts[ip] = {
                'roles': set(),
                'os': None,
                'cpe': set(),
                'scope_values': set(),
            }
        if isinstance(in_scope, bool):
            hosts[ip]['scope_values'].add(in_scope)
        # merge metadata if available
        if ip in hosts_meta:
            hosts[ip]['roles'].update(hosts_meta.get(ip, {}).get('roles', set()))
            if hosts_meta.get(ip, {}).get('os'):
                hosts[ip]['os'] = hosts_meta[ip]['os']
            if hosts_meta.get(ip, {}).get('cpe'):
                hosts[ip]['cpe'].update(hosts_meta[ip]['cpe'])
            if isinstance(hosts_meta.get(ip, {}).get('in_scope'), bool):
                hosts[ip]['scope_values'].add(hosts_meta[ip]['in_scope'])
        if ip in enriched_meta:
            hosts[ip]['roles'].update(enriched_meta.get(ip, {}).get('roles', set()))
            if enriched_meta.get(ip, {}).get('os'):
                hosts[ip]['os'] = enriched_meta[ip]['os']
            if enriched_meta.get(ip, {}).get('cpe'):
                hosts[ip]['cpe'].update(enriched_meta[ip]['cpe'])
            if isinstance(enriched_meta.get(ip, {}).get('in_scope'), bool):
                hosts[ip]['scope_values'].add(enriched_meta[ip]['in_scope'])
        return hosts[ip]

    analysis_counts = {
        'input_flows': 0,
        'service_observations': 0,
        'ambiguous_endpoint_flows': 0,
        'unconfirmed_service_attempts': 0,
    }
    inference_methods: Dict[str, int] = defaultdict(int)
    inference_confidences: Dict[str, int] = defaultdict(int)

    for rec in _load_flows(flows_path):
        analysis_counts['input_flows'] += 1
        src_ip = rec.get('src_ip')
        dst_ip = rec.get('dst_ip')
        bytes_val = _to_int(rec.get('bytes', 0))
        ts = rec.get('ts')
        sni = rec.get('sni')
        dns_qname = rec.get('dns_qname')

        if not src_ip or not dst_ip:
            continue
        _ensure_host(src_ip, rec.get('src_in_scope'))
        _ensure_host(dst_ip, rec.get('dst_in_scope'))

        endpoints = infer_endpoints(rec, SERVICE_MAP)
        if not endpoints.service_identified:
            # Preserve both host observations, but do not turn an ambiguous
            # destination port into a claimed service or dependency edge.
            analysis_counts['ambiguous_endpoint_flows'] += 1
            continue
        if not endpoints.service_observed:
            analysis_counts['unconfirmed_service_attempts'] += 1
            continue
        analysis_counts['service_observations'] += 1
        inference_methods[endpoints.method] += 1
        inference_confidences[endpoints.confidence] += 1
        client_ip = endpoints.client_ip
        server_ip = endpoints.server_ip
        server_port = endpoints.server_port
        proto = endpoints.proto

        service_id = f"{server_ip}:{server_port}/{proto}"
        if service_id not in services:
            services[service_id] = {
                'id': service_id,
                'ip': server_ip,
                'port': server_port,
                'proto': proto,
                'role': _infer_role(proto, server_port),
                'hostnames': set(),
            }
        if sni:
            services[service_id]['hostnames'].add(sni)

        edge_key = (client_ip, service_id)
        edge = edges.setdefault(edge_key, {
            'src': client_ip,
            'dst': service_id,
            'flows': 0,
            'bytes': 0,
            'sni': set(),
            'dns_qnames': set(),
            'endpoint_inference_methods': set(),
            'endpoint_inference_confidences': set(),
            'first_seen': None,
            'last_seen': None,
        })
        edge['flows'] += 1
        edge['bytes'] += bytes_val
        if sni:
            edge['sni'].add(sni)
        if dns_qname:
            edge['dns_qnames'].add(dns_qname)
        edge['endpoint_inference_methods'].add(endpoints.method)
        edge['endpoint_inference_confidences'].add(endpoints.confidence)
        if edge['first_seen'] is None or (ts is not None and ts < edge['first_seen']):
            edge['first_seen'] = ts
        if edge['last_seen'] is None or (ts is not None and ts > edge['last_seen']):
            edge['last_seen'] = ts

        role = _infer_role(proto, server_port)
        if role:
            hosts[server_ip]['roles'].add(role)

    candidate_edge_count = len(edges)
    candidate_service_count = len(services)
    # Filter edges with insufficient flow count and remove service nodes that
    # no longer have a retained observation edge.
    edges = {k: v for k, v in edges.items() if v['flows'] >= min_flows}
    retained_service_ids = {edge['dst'] for edge in edges.values()}
    services = {
        service_id: service
        for service_id, service in services.items()
        if service_id in retained_service_ids
    }

    os.makedirs(out_dir, exist_ok=True)
    nodes_payload = []
    for ip, data in sorted(hosts.items(), key=lambda item: item[0]):
        node = {
            'id': ip,
            'type': 'host',
            'roles': sorted(data['roles']),
            'in_scope': (
                True
                if True in data['scope_values']
                else False
                if False in data['scope_values']
                else None
            ),
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
            'in_scope': (
                True
                if True in hosts[svc['ip']]['scope_values']
                else False
                if False in hosts[svc['ip']]['scope_values']
                else None
            ),
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
            'endpoint_inference_methods': sorted(edge['endpoint_inference_methods']),
            'endpoint_inference_confidences': sorted(edge['endpoint_inference_confidences']),
            'first_seen': edge['first_seen'],
            'last_seen': edge['last_seen'],
        })

    graph = {'nodes': nodes_payload, 'edges': edges_payload}
    out_json = os.path.join(out_dir, 'graph.json')
    with open(out_json, 'w', encoding='utf-8') as fh:
        json.dump(graph, fh, ensure_ascii=False, indent=2)

    edges_path = os.path.join(out_dir, 'edges.jsonl')
    write_jsonl(edges_path, edges_payload)
    analysis_stats = {
        **analysis_counts,
        'endpoint_inference_methods': dict(sorted(inference_methods.items())),
        'endpoint_inference_confidences': dict(
            sorted(inference_confidences.items())
        ),
        'min_flows': max(1, int(min_flows)),
        'candidate_edges': candidate_edge_count,
        'retained_edges': len(edges_payload),
        'thresholded_edges': candidate_edge_count - len(edges_payload),
        'candidate_services': candidate_service_count,
        'retained_services': len(services),
        'pruned_services': candidate_service_count - len(services),
    }
    stats_path = os.path.join(out_dir, 'analysis_stats.json')
    with open(stats_path, 'w', encoding='utf-8') as fh:
        json.dump(analysis_stats, fh, ensure_ascii=False, indent=2)
        fh.write('\n')
    print(f"[analyze] Graph saved to {out_json} ({len(nodes_payload)} nodes, {len(edges_payload)} edges).")
