"""Shared edge aggregation helpers for reports and figures."""

from __future__ import annotations

from typing import Any, Dict, List


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _merge_values(target: set[str], value: Any) -> None:
    if not value:
        return
    if isinstance(value, list):
        for item in value:
            if item:
                target.add(str(item))
        return
    target.add(str(value))


def edge_source_label(edge: Dict[str, Any]) -> str:
    """Return a compact source label for raw or destination-aggregated edges."""
    source_count = _as_int(edge.get("source_count"), default=0)
    if source_count > 1:
        return f"{source_count} sources"
    return str(edge.get("src") or "")


def top_service_edges(graph: Dict[str, Any], k: int = 10) -> List[Dict[str, Any]]:
    """Rank edges aggregated by destination service.

    The graph stores raw client-to-service edges. For reports, aggregating by
    destination service exposes service hubs that would otherwise be hidden by
    many one-flow client edges.
    """
    edges = graph.get("edges") or []
    if not edges:
        return []

    grouped: dict[str, dict[str, Any]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        dst = edge.get("dst")
        if not dst:
            continue
        bucket = grouped.setdefault(
            str(dst),
            {
                "dst": str(dst),
                "flows": 0,
                "bytes": 0,
                "raw_edge_count": 0,
                "_sources": set(),
                "_sni": set(),
                "_dns_qnames": set(),
            },
        )
        src = edge.get("src")
        if src:
            bucket["_sources"].add(str(src))
        bucket["flows"] += _as_int(edge.get("flows", 0))
        bucket["bytes"] += _as_int(edge.get("bytes", 0))
        bucket["raw_edge_count"] += 1
        _merge_values(bucket["_sni"], edge.get("sni"))
        _merge_values(bucket["_dns_qnames"], edge.get("dns_qnames"))

    records: list[dict[str, Any]] = []
    for dst, bucket in grouped.items():
        sources = sorted(bucket["_sources"])
        source_count = len(sources)
        record: dict[str, Any] = {
            "src": sources[0] if source_count == 1 else f"{source_count} sources",
            "dst": dst,
            "flows": bucket["flows"],
            "bytes": bucket["bytes"],
            "source_count": source_count,
            "raw_edge_count": bucket["raw_edge_count"],
            "aggregation": "destination_service",
        }
        if source_count <= 10:
            record["sources"] = sources
        else:
            record["sample_sources"] = sources[:10]
        if bucket["_sni"]:
            record["sni"] = sorted(bucket["_sni"])
        if bucket["_dns_qnames"]:
            record["dns_qnames"] = sorted(bucket["_dns_qnames"])
        records.append(record)

    return sorted(
        records,
        key=lambda item: (
            -_as_int(item.get("flows", 0)),
            -_as_int(item.get("bytes", 0)),
            -_as_int(item.get("source_count", 0)),
            str(item.get("dst", "")),
        ),
    )[: max(1, int(k))]
