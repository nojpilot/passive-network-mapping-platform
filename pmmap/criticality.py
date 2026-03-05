"""Criticality scoring for passive network map using NetworkX and optional external tool."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections import defaultdict
from typing import Iterable

import networkx as nx


def _load_graph(graph_path: str) -> dict:
    if os.path.isdir(graph_path):
        candidate = os.path.join(graph_path, 'graph.json')
    else:
        candidate = graph_path
    if not os.path.isfile(candidate):
        raise FileNotFoundError(f"Soubor s grafem '{candidate}' neexistuje.")
    with open(candidate, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def _load_hosts(path: str | None) -> dict[str, dict]:
    if not path or not os.path.isfile(path):
        return {}
    hosts: dict[str, dict] = {}
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = rec.get('ip')
            if not ip:
                continue
            hosts.setdefault(ip, {})
            for key in ('roles', 'cpe', 'os'):
                if rec.get(key):
                    hosts[ip][key] = rec[key]
    return hosts


def _norm(value: float, max_value: float) -> float:
    if max_value <= 0:
        return 0.0
    return value / max_value


def _internal_scores(nodes: Iterable[dict], edges: Iterable[dict], betweenness_sample_k: int = 256) -> list[dict]:
    """Compute criticality using graph centrality, degree and traffic volume."""
    G = nx.DiGraph()
    for node in nodes:
        G.add_node(node['id'], **node)
    for edge in edges:
        G.add_edge(edge['src'], edge['dst'], **edge)

    n_nodes = G.number_of_nodes()
    betweenness: dict[str, float] = {node_id: 0.0 for node_id in G.nodes()}
    betweenness_enabled = False
    if n_nodes:
        k = None
        if n_nodes <= 2000:
            k = None
            betweenness_enabled = True
        elif n_nodes <= 10000:
            k = min(64, betweenness_sample_k, n_nodes)
            betweenness_enabled = True
        else:
            print(
                "[criticality] Graf je příliš velký, betweenness centrality přeskočena "
                "(používám degree + bytes)."
            )
        if betweenness_enabled:
            betweenness = nx.betweenness_centrality(
                G,
                weight='bytes',
                normalized=True,
                k=k,
                seed=42 if k else None,
            )
    degree = dict(G.degree())
    in_degree = dict(G.in_degree())
    out_degree = dict(G.out_degree())
    bytes_totals: dict[str, int] = defaultdict(int)
    for u, v, data in G.edges(data=True):
        b = data.get('bytes') or 0
        bytes_totals[u] += b
        bytes_totals[v] += b

    max_betw = max(betweenness.values(), default=0.0)
    max_degree = max(degree.values(), default=0.0)
    max_bytes = max(bytes_totals.values(), default=0.0)

    if betweenness_enabled:
        w_betw, w_degree, w_bytes = 0.6, 0.2, 0.2
    else:
        w_betw, w_degree, w_bytes = 0.0, 0.5, 0.5

    results: list[dict] = []
    for node_id, attrs in G.nodes(data=True):
        # skórujeme hosty; služby mají jen podpůrný charakter
        if attrs.get('type') and attrs.get('type') != 'host':
            continue
        score = (
            w_betw * _norm(betweenness.get(node_id, 0.0), max_betw)
            + w_degree * _norm(degree.get(node_id, 0), max_degree)
            + w_bytes * _norm(bytes_totals.get(node_id, 0), max_bytes)
        )
        # mírný boost pro dobře definované role
        roles = attrs.get('roles') or []
        if any(r in ('dns_server', 'ldap', 'kerberos', 'mail_server') for r in roles):
            score += 0.05
        results.append({
            'id': node_id,
            'type': attrs.get('type'),
            'score': score,
            'method': 'internal',
            'metrics': {
                'betweenness': betweenness.get(node_id, 0.0),
                'degree': degree.get(node_id, 0),
                'in_degree': in_degree.get(node_id, 0),
                'out_degree': out_degree.get(node_id, 0),
                'bytes_total': bytes_totals.get(node_id, 0),
            },
            'roles': roles,
            'cpe': attrs.get('cpe'),
            'os': attrs.get('os'),
        })
    results.sort(key=lambda r: r['score'], reverse=True)
    return results


def _coerce_external_scores(raw, node_lookup: dict[str, dict]) -> list[dict]:
    """Normalize output of external tool to internal structure."""
    if isinstance(raw, dict):
        if isinstance(raw.get('scores'), list):
            raw = raw['scores']
        elif isinstance(raw.get('results'), list):
            raw = raw['results']
    if not isinstance(raw, list):
        return []
    results = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        node_id = entry.get('id') or entry.get('node') or entry.get('target')
        if not node_id:
            continue
        try:
            score_val = float(entry.get('score', 0.0))
        except Exception:
            score_val = 0.0
        node_meta = node_lookup.get(node_id, {})
        results.append({
            'id': node_id,
            'type': node_meta.get('type'),
            'score': score_val,
            'method': 'external',
            'metrics': entry,
            'roles': node_meta.get('roles', []),
            'cpe': node_meta.get('cpe'),
            'os': node_meta.get('os'),
        })
    results.sort(key=lambda r: r['score'], reverse=True)
    return results


def _run_external(cmd: str, payload: dict) -> list[dict] | None:
    """Run external criticality tool (expects JSON on stdin, JSON on stdout)."""
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
        )
    except Exception as exc:
        print(f"[criticality] Externí nástroj selhal: {exc}")
        return None
    try:
        output = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("[criticality] Nelze parsovat JSON výstup externího nástroje, používám interní skóre.")
        return None
    return output


def run(
    graph_path: str,
    out_dir: str,
    hosts_path: str | None = None,
    external_cmd: str | None = None,
    dump_input_path: str | None = None,
):
    """Compute criticality ranking, optionally via external tool."""
    graph = _load_graph(graph_path)
    nodes = graph.get('nodes') or []
    edges = graph.get('edges') or []

    node_lookup = {n['id']: n for n in nodes if isinstance(n, dict) and n.get('id')}

    if hosts_path:
        hosts_meta = _load_hosts(hosts_path)
        for node_id, attrs in node_lookup.items():
            if node_id in hosts_meta:
                attrs.setdefault('roles', hosts_meta[node_id].get('roles', attrs.get('roles')))
                if hosts_meta[node_id].get('cpe'):
                    attrs['cpe'] = hosts_meta[node_id]['cpe']
                if hosts_meta[node_id].get('os') and not attrs.get('os'):
                    attrs['os'] = hosts_meta[node_id]['os']

    results: list[dict] = []
    payload = {'nodes': list(node_lookup.values()), 'edges': edges}

    if dump_input_path:
        try:
            dump_dir = os.path.dirname(dump_input_path)
            if dump_dir:
                os.makedirs(dump_dir, exist_ok=True)
            with open(dump_input_path, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            print(f"[criticality] Uložen vstupní payload pro externí nástroj: {dump_input_path}")
        except Exception as exc:
            print(f"[criticality] Nelze uložit dump vstupu: {exc}")

    if external_cmd:
        external_raw = _run_external(external_cmd, payload)
        if external_raw:
            coerced = _coerce_external_scores(external_raw, node_lookup)
            if coerced:
                results = coerced

    if not results:
        results = _internal_scores(node_lookup.values(), edges)

    os.makedirs(out_dir, exist_ok=True)
    jsonl_path = os.path.join(out_dir, 'criticality.jsonl')
    with open(jsonl_path, 'w', encoding='utf-8') as fh:
        for rec in results:
            fh.write(json.dumps(rec) + '\n')

    top_path = os.path.join(out_dir, 'criticality_top.json')
    with open(top_path, 'w', encoding='utf-8') as fh:
        json.dump(results[:10], fh, ensure_ascii=False, indent=2)
    print(f"[criticality] Uloženo {len(results)} výsledků → {jsonl_path}")
