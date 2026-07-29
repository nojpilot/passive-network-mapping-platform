#!/usr/bin/env python
"""Minimal degree-based example of the external criticality JSON transport.

This program is deliberately not a second implementation of the built-in
criticality heuristic.  It projects host-to-service observations to host
neighbours and returns normalized undirected host degree.  Its purpose is to
demonstrate the stdin/stdout contract used by ``--external-cmd``.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Any


def _degree_scores(payload: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = payload.get("nodes") or []
    edges = payload.get("edges") or []

    hosts: dict[str, dict[str, Any]] = {}
    service_owners: dict[str, str] = {}
    for node in nodes:
        if not isinstance(node, dict) or not node.get("id"):
            continue
        node_id = str(node["id"])
        if node.get("type") == "host":
            hosts[node_id] = node
        elif node.get("type") == "service" and node.get("ip"):
            service_owners[node_id] = str(node["ip"])

    neighbours: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if not isinstance(edge, dict) or not edge.get("src") or not edge.get("dst"):
            continue
        src = str(edge["src"])
        raw_dst = str(edge["dst"])
        dst = service_owners.get(raw_dst, raw_dst if raw_dst in hosts else "")
        if src not in hosts or dst not in hosts or src == dst:
            continue
        neighbours[src].add(dst)
        neighbours[dst].add(src)

    degree = {host_id: len(neighbours[host_id]) for host_id in hosts}
    max_degree = max(degree.values(), default=0)
    results = []
    for host_id in sorted(hosts):
        value = degree[host_id]
        roles = hosts[host_id].get("roles") or []
        if isinstance(roles, str):
            roles = [roles]
        results.append(
            {
                "id": host_id,
                "score": value / max_degree if max_degree else 0.0,
                "degree": value,
                "explanation": (
                    "Normalized undirected host degree; transport example only"
                ),
                "roles": roles,
            }
        )

    results.sort(key=lambda row: (-row["score"], row["id"]))
    return results


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:  # pragma: no cover - command-line error path
        sys.stderr.write(f"Cannot parse input JSON: {exc}\n")
        raise SystemExit(1) from exc

    if not isinstance(payload, dict):
        sys.stderr.write("Input JSON must be an object.\n")
        raise SystemExit(1)

    json.dump(_degree_scores(payload), sys.stdout, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
