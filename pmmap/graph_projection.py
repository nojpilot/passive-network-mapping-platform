"""Deterministic graph projections shared by analysis consumers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import networkx as nx


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def build_host_graph(
    nodes: Iterable[Mapping[str, Any]],
    edges: Iterable[Mapping[str, Any]],
) -> nx.DiGraph:
    """Project host-to-service observations into a host-to-host graph.

    The analysis graph records a communication as ``host -> service`` while
    also containing a separate host node for the service IP.  This projection
    connects the source host to that destination host and aggregates all
    observed services between the pair.

    Nodes and edges are inserted in sorted order.  NetworkX's approximate
    centrality routines sample from node insertion order, so stable insertion
    is necessary for reproducible results even when the JSON input order
    changes.
    """
    node_records = [
        dict(node)
        for node in nodes
        if isinstance(node, Mapping) and node.get("id")
    ]
    edge_records = [
        dict(edge)
        for edge in edges
        if isinstance(edge, Mapping) and edge.get("src") and edge.get("dst")
    ]

    nodes_by_id = {str(node["id"]): node for node in node_records}
    service_nodes = {
        node_id: node
        for node_id, node in nodes_by_id.items()
        if node.get("type") == "service"
    }
    host_nodes = {
        node_id: node
        for node_id, node in nodes_by_id.items()
        if node.get("type") == "host"
    }

    projected: dict[tuple[str, str], dict[str, Any]] = {}
    discovered_hosts: set[str] = set(host_nodes)

    for edge in sorted(
        edge_records,
        key=lambda item: (str(item.get("src")), str(item.get("dst"))),
    ):
        src = str(edge["src"])
        raw_dst = str(edge["dst"])
        service = service_nodes.get(raw_dst)

        if service is not None:
            dst_value = service.get("ip")
            if not dst_value:
                continue
            dst = str(dst_value)
            service_id: str | None = raw_dst
        elif raw_dst in host_nodes:
            # Accept an already host-to-host edge as a defensive convenience.
            dst = raw_dst
            service_id = None
        else:
            continue

        discovered_hosts.update((src, dst))
        projected_edge = projected.setdefault(
            (src, dst),
            {
                "flows": 0,
                "bytes": 0,
                "observation_edges": 0,
                "service_ids": set(),
                "ports": set(),
                "protocols": set(),
            },
        )
        projected_edge["flows"] += _as_int(edge.get("flows"))
        projected_edge["bytes"] += _as_int(edge.get("bytes"))
        projected_edge["observation_edges"] += 1

        if service_id is not None:
            projected_edge["service_ids"].add(service_id)
            port = service.get("port")
            if port is not None:
                projected_edge["ports"].add(port)
            proto = service.get("proto")
            if proto:
                projected_edge["protocols"].add(str(proto))

    graph = nx.DiGraph()
    for host_id in sorted(discovered_hosts):
        attrs = dict(host_nodes.get(host_id, {}))
        attrs.pop("id", None)
        attrs["type"] = "host"
        graph.add_node(host_id, **attrs)

    for (src, dst), attrs in sorted(projected.items()):
        graph.add_edge(
            src,
            dst,
            flows=attrs["flows"],
            bytes=attrs["bytes"],
            observation_edges=attrs["observation_edges"],
            service_ids=tuple(sorted(attrs["service_ids"])),
            ports=tuple(sorted(attrs["ports"], key=str)),
            protocols=tuple(sorted(attrs["protocols"])),
        )

    return graph
