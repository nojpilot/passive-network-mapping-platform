"""Deterministic resource policy for betweenness-centrality computation."""

from __future__ import annotations

from typing import Any


# Unweighted Brandes traverses the graph once per source.  NetworkX also
# initializes per-node state for each source, so ``sources * (V + E)`` is a
# useful conservative work estimate for both sparse and disconnected graphs.
EXACT_BETWEENNESS_WORK_LIMIT = 10_000_000
SAMPLED_BETWEENNESS_WORK_LIMIT = 10_000_000
MAX_BETWEENNESS_SAMPLE_K = 64


def plan_betweenness(
    n_nodes: int,
    n_edges: int,
    requested_sample_k: int = 256,
) -> dict[str, Any]:
    """Choose exact, deterministic sampled, or skipped betweenness.

    The decision is based on the expected amount of graph traversal rather
    than an arbitrary node-count boundary.  This lets sparse graphs such as
    the CESNET evaluation graph use the exact algorithm while bounding work
    for dense or very large graphs.
    """
    n_nodes = max(0, int(n_nodes))
    n_edges = max(0, int(n_edges))
    work_per_source = n_nodes + n_edges
    exact_work = n_nodes * work_per_source

    base: dict[str, Any] = {
        "work_model": "sources * (nodes + edges)",
        "nodes": n_nodes,
        "edges": n_edges,
        "estimated_exact_work": exact_work,
        "exact_work_limit": EXACT_BETWEENNESS_WORK_LIMIT,
        "sampled_work_limit": SAMPLED_BETWEENNESS_WORK_LIMIT,
        "sample_seed": 42,
    }

    if n_nodes == 0:
        return {
            **base,
            "mode": "skipped",
            "sample_k": None,
            "estimated_selected_work": 0,
            "skipped_reason": "empty_graph",
        }

    if exact_work <= EXACT_BETWEENNESS_WORK_LIMIT:
        return {
            **base,
            "mode": "exact",
            "sample_k": None,
            "estimated_selected_work": exact_work,
            "skipped_reason": None,
        }

    sample_k = min(
        n_nodes,
        MAX_BETWEENNESS_SAMPLE_K,
        max(1, int(requested_sample_k)),
    )
    sampled_work = sample_k * work_per_source
    if sampled_work <= SAMPLED_BETWEENNESS_WORK_LIMIT:
        return {
            **base,
            "mode": "sampled",
            "sample_k": sample_k,
            "estimated_selected_work": sampled_work,
            "skipped_reason": None,
        }

    return {
        **base,
        "mode": "skipped",
        "sample_k": None,
        "estimated_selected_work": sampled_work,
        "skipped_reason": "sampled_work_limit_exceeded",
    }
