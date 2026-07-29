"""Criticality scoring for passive network map using NetworkX and optional external tool."""

from __future__ import annotations

import json
import math
import os
import shlex
import subprocess
from collections import defaultdict
from typing import Iterable

import networkx as nx

from .centrality import plan_betweenness
from .graph_projection import build_host_graph


def _load_graph(graph_path: str) -> dict:
    if os.path.isdir(graph_path):
        candidate = os.path.join(graph_path, 'graph.json')
    else:
        candidate = graph_path
    if not os.path.isfile(candidate):
        raise FileNotFoundError(f"Graph file '{candidate}' does not exist.")
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
            host = hosts.setdefault(ip, {})
            roles = rec.get('roles') or []
            if isinstance(roles, str):
                roles = [roles]
            if roles:
                merged_roles = set(host.get('roles') or [])
                merged_roles.update(role for role in roles if isinstance(role, str))
                host['roles'] = sorted(merged_roles)
            for key in ('cpe', 'os'):
                if rec.get(key):
                    host[key] = rec[key]
            if isinstance(rec.get('in_scope'), bool):
                host['in_scope'] = rec['in_scope']
    return hosts


def _norm(value: float, max_value: float) -> float:
    if max_value <= 0:
        return 0.0
    return value / max_value


def _internal_scores(nodes: Iterable[dict], edges: Iterable[dict], betweenness_sample_k: int = 256) -> list[dict]:
    """Compute host criticality from the projected communication graph."""
    node_records = list(nodes)
    G = build_host_graph(node_records, edges)
    out_of_scope_hosts = {
        str(node.get('ip') or node.get('id'))
        for node in node_records
        if (
            isinstance(node, dict)
            and node.get('in_scope') is False
            and (node.get('type') == 'host' or node.get('ip'))
        )
    }
    # Boundary communication remains available in graph.json for context, but
    # an explicitly out-of-scope host must not affect centrality or volume
    # normalization for the monitored network.
    G.remove_nodes_from(
        node_id for node_id in out_of_scope_hosts if node_id in G
    )

    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()
    betweenness_plan = plan_betweenness(
        n_nodes,
        n_edges,
        requested_sample_k=betweenness_sample_k,
    )
    betweenness: dict[str, float] = {node_id: 0.0 for node_id in G.nodes()}
    betweenness_enabled = betweenness_plan['mode'] != 'skipped'
    if betweenness_enabled:
        # Traffic volume is connection strength, not path distance.  Use an
        # unweighted undirected projection for structural centrality.
        centrality_graph = G.to_undirected()
        k = betweenness_plan['sample_k']
        betweenness = nx.betweenness_centrality(
            centrality_graph,
            weight=None,
            normalized=True,
            k=k,
            seed=betweenness_plan['sample_seed'] if k else None,
        )
    elif n_nodes:
        print(
            "[criticality] Betweenness centrality was skipped because its "
            "estimated work exceeds the configured safety limit "
            "(using the remaining available signals)."
        )
    degree = dict(G.degree())
    in_degree = dict(G.in_degree())
    out_degree = dict(G.out_degree())
    bytes_totals: dict[str, int] = defaultdict(int)
    flows_totals: dict[str, int] = defaultdict(int)
    for u, v, data in G.edges(data=True):
        b = data.get('bytes') or 0
        flows = data.get('flows') or 0
        bytes_totals[u] += b
        bytes_totals[v] += b
        flows_totals[u] += flows
        flows_totals[v] += flows

    max_betw = max(betweenness.values(), default=0.0)
    max_degree = max(degree.values(), default=0.0)
    max_bytes = max(bytes_totals.values(), default=0.0)

    if betweenness_enabled:
        nominal_weights = {
            'betweenness': 0.6,
            'degree': 0.2,
            'bytes_total': 0.2,
        }
    else:
        nominal_weights = {
            'betweenness': 0.0,
            'degree': 0.5,
            'bytes_total': 0.5,
        }
    available = {
        'betweenness': max_betw > 0,
        'degree': max_degree > 0,
        'bytes_total': max_bytes > 0,
    }
    available_weight = sum(
        weight
        for signal, weight in nominal_weights.items()
        if available[signal]
    )
    effective_weights = {
        signal: (
            weight / available_weight
            if available[signal] and available_weight > 0
            else 0.0
        )
        for signal, weight in nominal_weights.items()
    }
    w_betw = effective_weights['betweenness']
    w_degree = effective_weights['degree']
    w_bytes = effective_weights['bytes_total']

    results: list[dict] = []
    for node_id, attrs in G.nodes(data=True):
        if attrs.get('in_scope') is False:
            continue
        score = (
            w_betw * _norm(betweenness.get(node_id, 0.0), max_betw)
            + w_degree * _norm(degree.get(node_id, 0), max_degree)
            + w_bytes * _norm(bytes_totals.get(node_id, 0), max_bytes)
        )
        # Slight boost for well-defined infrastructure roles.
        roles = attrs.get('roles') or []
        role_boost = (
            0.05
            if any(r in ('dns_server', 'ldap', 'kerberos', 'mail_server') for r in roles)
            else 0.0
        )
        score += role_boost
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
                'flows_total': flows_totals.get(node_id, 0),
                'role_boost': role_boost,
            },
            'provenance': {
                'method_version': 3,
                'projection': 'host_to_host_via_service',
                'centrality_graph': 'undirected',
                'betweenness_weight': None,
                'betweenness_mode': betweenness_plan['mode'],
                'betweenness_sample_k': betweenness_plan['sample_k'],
                'betweenness_plan': betweenness_plan,
                'available_signals': available,
                'nominal_score_weights': nominal_weights,
                'score_weights': effective_weights,
                'infrastructure_role_boost': 0.05,
            },
            'roles': roles,
            'cpe': attrs.get('cpe'),
            'os': attrs.get('os'),
            'in_scope': attrs.get('in_scope'),
        })
    results.sort(key=lambda r: (-r['score'], r['id']))
    return results


def _coerce_external_scores(raw, node_lookup: dict[str, dict]) -> list[dict]:
    """Normalize output of external tool to internal structure."""
    if isinstance(raw, dict):
        if isinstance(raw.get('scores'), list):
            raw = raw['scores']
        elif isinstance(raw.get('results'), list):
            raw = raw['results']
    if not isinstance(raw, list):
        raise ValueError("External criticality output must be a JSON list.")
    results = []
    seen_ids: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("Every external criticality result must be an object.")
        node_id = entry.get('id') or entry.get('node') or entry.get('target')
        if not node_id:
            raise ValueError("Every external criticality result requires an id.")
        node_id = str(node_id)
        if node_id not in node_lookup:
            raise ValueError(
                f"External criticality returned unknown or out-of-scope id: {node_id}"
            )
        if node_id in seen_ids:
            raise ValueError(
                f"External criticality returned duplicate id: {node_id}"
            )
        if 'score' not in entry:
            raise ValueError(
                f"External criticality result for {node_id} is missing score."
            )
        if isinstance(entry.get('score'), bool):
            raise ValueError(
                f"External criticality returned a non-numeric score for {node_id}."
            )
        try:
            score_val = float(entry['score'])
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"External criticality returned a non-numeric score for {node_id}."
            ) from exc
        if not math.isfinite(score_val):
            raise ValueError(
                f"External criticality returned a non-finite score for {node_id}."
            )
        seen_ids.add(node_id)
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
            'in_scope': node_meta.get('in_scope'),
        })
    results.sort(key=lambda r: (-r['score'], r['id']))
    return results


def _run_external(
    cmd: str,
    payload: dict,
    timeout_seconds: float = 60.0,
) -> list[dict]:
    """Run external criticality tool (expects JSON on stdin, JSON on stdout)."""
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
            timeout=max(0.1, float(timeout_seconds)),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"External criticality tool failed: {exc}") from exc
    try:
        output = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "External criticality tool returned invalid JSON."
        ) from exc
    return output


def run(
    graph_path: str,
    out_dir: str,
    hosts_path: str | None = None,
    external_cmd: str | None = None,
    dump_input_path: str | None = None,
    external_timeout: float = 60.0,
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
                graph_roles = attrs.get('roles') or []
                if isinstance(graph_roles, str):
                    graph_roles = [graph_roles]
                host_roles = hosts_meta[node_id].get('roles') or []
                attrs['roles'] = sorted({
                    role
                    for role in [*graph_roles, *host_roles]
                    if isinstance(role, str)
                })
                if hosts_meta[node_id].get('cpe'):
                    attrs['cpe'] = hosts_meta[node_id]['cpe']
                if hosts_meta[node_id].get('os') and not attrs.get('os'):
                    attrs['os'] = hosts_meta[node_id]['os']
                if isinstance(hosts_meta[node_id].get('in_scope'), bool):
                    attrs['in_scope'] = hosts_meta[node_id]['in_scope']

    # Older graph artifacts may only carry scope on their host node. Mirror it
    # to the corresponding service node before constructing a scoped payload.
    for attrs in node_lookup.values():
        if attrs.get('type') != 'service' or not attrs.get('ip'):
            continue
        host_scope = node_lookup.get(str(attrs['ip']), {}).get('in_scope')
        if not isinstance(attrs.get('in_scope'), bool) and isinstance(
            host_scope,
            bool,
        ):
            attrs['in_scope'] = host_scope

    eligible_lookup = {
        node_id: node
        for node_id, node in node_lookup.items()
        if node.get('in_scope') is not False
    }
    eligible_ids = set(eligible_lookup)
    scoped_edges = [
        edge
        for edge in edges
        if (
            isinstance(edge, dict)
            and edge.get('src') in eligible_ids
            and edge.get('dst') in eligible_ids
        )
    ]

    results: list[dict] = []
    payload = {'nodes': list(eligible_lookup.values()), 'edges': scoped_edges}

    os.makedirs(out_dir, exist_ok=True)
    jsonl_path = os.path.join(out_dir, 'criticality.jsonl')
    top_path = os.path.join(out_dir, 'criticality_top.json')
    default_dump_path = os.path.join(out_dir, 'criticality_input.json')
    # A failed external rerun must not leave apparently valid results from an
    # earlier invocation in the selected output directory.
    for stale_path in (jsonl_path, top_path):
        try:
            os.remove(stale_path)
        except FileNotFoundError:
            pass
    if (
        os.path.isfile(default_dump_path)
        and (
            dump_input_path is None
            or os.path.realpath(dump_input_path)
            != os.path.realpath(default_dump_path)
        )
    ):
        os.remove(default_dump_path)

    if dump_input_path:
        try:
            dump_dir = os.path.dirname(dump_input_path)
            if dump_dir:
                os.makedirs(dump_dir, exist_ok=True)
            with open(dump_input_path, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            print(f"[criticality] Saved input payload for external tool: {dump_input_path}")
        except Exception as exc:
            print(f"[criticality] Cannot save input dump: {exc}")

    if external_cmd:
        external_raw = _run_external(
            external_cmd,
            payload,
            timeout_seconds=external_timeout,
        )
        results = _coerce_external_scores(external_raw, eligible_lookup)
        if not results:
            raise ValueError("External criticality tool returned no usable scores.")
    else:
        results = _internal_scores(node_lookup.values(), edges)

    with open(jsonl_path, 'w', encoding='utf-8') as fh:
        for rec in results:
            fh.write(json.dumps(rec) + '\n')

    with open(top_path, 'w', encoding='utf-8') as fh:
        json.dump(results[:10], fh, ensure_ascii=False, indent=2)
    print(f"[criticality] Wrote {len(results)} results -> {jsonl_path}")
