#!/usr/bin/env python
"""
Stub externího nástroje pro kritičnost.

Čte payload (nodes/edges) z stdin a vypisuje JSON seznam se skóre.
Vhodné pro otestování integrace (--external-cmd) bez skutečného nástroje.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict

import networkx as nx


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:  # pragma: no cover - integrační util
        sys.stderr.write(f"Cannot parse input JSON: {exc}\n")
        sys.exit(1)

    nodes = payload.get('nodes') or []
    edges = payload.get('edges') or []

    G = nx.DiGraph()
    for node in nodes:
        if not isinstance(node, dict) or 'id' not in node:
            continue
        G.add_node(node['id'], **node)
    for edge in edges:
        if not isinstance(edge, dict) or 'src' not in edge or 'dst' not in edge:
            continue
        G.add_edge(edge['src'], edge['dst'], **edge)

    betweenness: dict[str, float] = {}
    if G.number_of_nodes():
        k = None
        if G.number_of_nodes() > 2000:
            k = min(256, G.number_of_nodes())
        betweenness = nx.betweenness_centrality(G, weight='bytes', normalized=True, k=k, seed=42 if k else None)
    degree = dict(G.degree())
    bytes_totals: dict[str, int] = defaultdict(int)
    for u, v, data in G.edges(data=True):
        bytes_totals[u] += data.get('bytes', 0) or 0
        bytes_totals[v] += data.get('bytes', 0) or 0

    max_betw = max(betweenness.values(), default=0.0)
    max_deg = max(degree.values(), default=0.0)
    max_bytes = max(bytes_totals.values(), default=0.0)

    results = []
    for node_id, attrs in G.nodes(data=True):
        if attrs.get('type') and attrs.get('type') != 'host':
            continue
        score = (
            0.6 * (betweenness.get(node_id, 0.0) / max_betw if max_betw else 0.0)
            + 0.2 * (degree.get(node_id, 0) / max_deg if max_deg else 0.0)
            + 0.2 * (bytes_totals.get(node_id, 0) / max_bytes if max_bytes else 0.0)
        )
        roles = attrs.get('roles') or []
        explanation_parts = [
            f"betw={betweenness.get(node_id, 0.0):.4f}",
            f"deg={degree.get(node_id, 0)}",
            f"bytes={bytes_totals.get(node_id, 0)}",
        ]
        if roles:
            explanation_parts.append(f"roles={','.join(roles)}")
        results.append({
            'id': node_id,
            'score': round(score, 6),
            'explanation': "; ".join(explanation_parts),
            'roles': roles,
        })

    results.sort(key=lambda r: r['score'], reverse=True)
    json.dump(results, sys.stdout, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
