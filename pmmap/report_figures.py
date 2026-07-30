"""Generate report-ready static charts and save a figure manifest."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List

from .edge_summary import edge_source_label, top_service_edges


def _load_json(path: str) -> Dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            return {}


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    if not path or not os.path.isfile(path):
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _host_id(record: Dict[str, Any]) -> str | None:
    value = record.get("ip") or record.get("id")
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _excluded_host_ids(
    graph: Dict[str, Any],
    hosts: List[Dict[str, Any]],
    criticality: List[Dict[str, Any]],
) -> set[str]:
    """Collect hosts explicitly marked out of scope in any report input."""
    graph_hosts = [
        node
        for node in (graph.get("nodes") or [])
        if isinstance(node, dict) and node.get("type") == "host"
    ]
    excluded: set[str] = set()
    for record in [*graph_hosts, *hosts, *criticality]:
        host_id = _host_id(record)
        if host_id and record.get("in_scope") is False:
            excluded.add(host_id)
    return excluded


def _observed_bytes(host: Dict[str, Any]) -> int:
    if host.get("bytes_observed") is not None:
        return int(host.get("bytes_observed") or 0)
    return int(host.get("bytes_in", 0) or 0) + int(host.get("bytes_out", 0) or 0)


def _top_edges(graph: Dict[str, Any], k: int) -> List[Dict[str, Any]]:
    return top_service_edges(graph, k=k)


def _shorten(text: str, max_len: int = 60) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "..."


def _save_figure(fig, out_path: str) -> None:
    fig.tight_layout()
    fig.savefig(out_path, dpi=160, bbox_inches="tight")


def _portable_relative_path(path: str, start: str) -> str:
    """Return a relative path suitable for JSON and Markdown on every OS."""
    return os.path.relpath(path, start).replace("\\", "/")


def generate_figures(
    report_dir: str,
    graph_path: str,
    criticality_path: str | None = None,
    hosts_path: str | None = None,
    top_k: int = 10,
    manifest_path: str | None = None,
) -> str:
    """Generate charts into report_dir/assets and return manifest path."""
    if "MPLCONFIGDIR" not in os.environ:
        fallback_cache = os.path.join(
            tempfile.gettempdir(),
            "pmmap-matplotlib-cache",
        )
        os.makedirs(fallback_cache, exist_ok=True)
        os.environ["MPLCONFIGDIR"] = fallback_cache
    # Report generation is non-interactive and must not depend on a desktop
    # Tcl/Tk installation (common in servers, containers, and CI).
    os.environ.setdefault("MPLBACKEND", "Agg")
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError(
            "Missing matplotlib. Install dependencies from requirements.txt."
        ) from exc

    top_k = max(1, int(top_k))
    os.makedirs(report_dir, exist_ok=True)
    assets_dir = os.path.join(report_dir, "assets")
    os.makedirs(assets_dir, exist_ok=True)

    graph = _load_json(graph_path)
    criticality = _load_jsonl(criticality_path) if criticality_path else []
    hosts = _load_jsonl(hosts_path) if hosts_path else []
    excluded = _excluded_host_ids(graph, hosts, criticality)
    criticality = [
        row
        for row in criticality
        if _host_id(row) not in excluded and row.get("in_scope") is not False
    ]
    hosts = [
        row
        for row in hosts
        if _host_id(row) not in excluded and row.get("in_scope") is not False
    ]

    figures: List[Dict[str, str]] = []

    if criticality:
        top = criticality[:top_k]
        labels = [str(row.get("id", "")) for row in top]
        scores = [float(row.get("score", 0.0) or 0.0) for row in top]
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.barh(labels[::-1], scores[::-1], color="#1f77b4")
        ax.set_title(f"Top {top_k} Critical Nodes")
        ax.set_xlabel("Criticality score")
        out_path = os.path.join(assets_dir, "top_criticality.png")
        _save_figure(fig, out_path)
        plt.close(fig)
        figures.append(
            {
                "path": _portable_relative_path(out_path, report_dir),
                "caption": f"Top {top_k} nodes ranked by criticality score.",
                "section": "Criticality",
            }
        )

    top_edges = _top_edges(graph, top_k) if graph else []
    if top_edges:
        labels = [_shorten(f"{edge_source_label(e)} -> {e.get('dst','')}") for e in top_edges]
        flows = [int(e.get("flows", 0) or 0) for e in top_edges]
        fig, ax = plt.subplots(figsize=(11, 6))
        ax.barh(labels[::-1], flows[::-1], color="#2ca02c")
        ax.set_title(f"Top {top_k} Service Destinations by Flow Count")
        ax.set_xlabel("Flows")
        out_path = os.path.join(assets_dir, "top_edges_flows.png")
        _save_figure(fig, out_path)
        plt.close(fig)
        figures.append(
            {
                "path": _portable_relative_path(out_path, report_dir),
                "caption": f"Top {top_k} service destinations by aggregated number of flows.",
                "section": "Communication Services",
            }
        )

        # A deliberately filtered network view communicates the actual mapping
        # result without producing an unreadable full-graph hairball.
        try:
            import networkx as nx

            overview = nx.Graph()
            selected_edges = top_edges[: min(top_k, 8)]
            service_ids: list[str] = []
            client_ids: set[str] = set()
            for service in selected_edges:
                service_id = str(service.get("dst") or "")
                if not service_id:
                    continue
                service_ids.append(service_id)
                overview.add_node(service_id, node_type="service")
                sources = service.get("sources") or service.get("sample_sources") or []
                for source in sorted(str(item) for item in sources if item)[:5]:
                    client_ids.add(source)
                    overview.add_node(source, node_type="host")
                    overview.add_edge(
                        source,
                        service_id,
                        flows=int(service.get("flows", 0) or 0),
                    )

            if overview.number_of_edges() > 0:
                fig, ax = plt.subplots(figsize=(12, 8))
                positions = nx.spring_layout(overview, seed=42)
                nx.draw_networkx_edges(
                    overview,
                    positions,
                    ax=ax,
                    width=1.8,
                    alpha=0.9,
                    edge_color="#4f5b62",
                )
                nx.draw_networkx_nodes(
                    overview,
                    positions,
                    nodelist=sorted(client_ids),
                    node_size=90,
                    node_color="#4c78a8",
                    alpha=0.8,
                    ax=ax,
                    label="Observed client",
                )
                nx.draw_networkx_nodes(
                    overview,
                    positions,
                    nodelist=service_ids,
                    node_size=520,
                    node_color="#f58518",
                    edgecolors="#8c4b08",
                    linewidths=0.8,
                    ax=ax,
                    label="Service destination",
                )
                service_labels = {
                    service_id: _shorten(service_id, 32)
                    for service_id in service_ids
                }
                nx.draw_networkx_labels(
                    overview,
                    positions,
                    labels=service_labels,
                    font_size=8,
                    ax=ax,
                )
                ax.set_title(
                    "Leading Service Destinations and Sample Observed Clients"
                )
                ax.legend(loc="best")
                ax.axis("off")
                out_path = os.path.join(assets_dir, "communication_map.png")
                _save_figure(fig, out_path)
                plt.close(fig)
                figures.append(
                    {
                        "path": _portable_relative_path(out_path, report_dir),
                        "caption": (
                            "Illustrative communication map of the leading service "
                            "destinations and up to five observed clients per destination."
                        ),
                        "section": "Communication Map",
                    }
                )
        except Exception as exc:
            # Other report charts remain useful when optional network rendering
            # is unavailable. The export caller already treats figures as best-effort.
            print(f"[figures] Communication-map generation skipped: {exc}")

    if hosts:
        role_counts: Dict[str, int] = {}
        for row in hosts:
            roles = row.get("roles") or []
            if not roles:
                role_counts["unknown"] = role_counts.get("unknown", 0) + 1
                continue
            for role in roles:
                role_key = str(role)
                role_counts[role_key] = role_counts.get(role_key, 0) + 1
        top_roles = sorted(role_counts.items(), key=lambda x: x[1], reverse=True)[:top_k]
        if top_roles:
            labels = [r[0] for r in top_roles]
            counts = [int(r[1]) for r in top_roles]
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.bar(labels, counts, color="#ff7f0e")
            ax.set_title(f"Top {top_k} Host Roles")
            ax.set_ylabel("Host count")
            ax.tick_params(axis="x", rotation=30)
            out_path = os.path.join(assets_dir, "host_roles.png")
            _save_figure(fig, out_path)
            plt.close(fig)
            figures.append(
                {
                    "path": _portable_relative_path(out_path, report_dir),
                    "caption": "Distribution of detected host roles.",
                    "section": "Inventory",
                }
            )

        host_rows = []
        for row in hosts:
            host_rows.append(
                (
                    str(row.get("ip", "")),
                    int(row.get("flows_in", 0) or 0) + int(row.get("flows_out", 0) or 0),
                    _observed_bytes(row),
                )
            )
        has_measured_bytes = any(row[2] for row in host_rows)
        host_rows = sorted(
            host_rows,
            key=lambda x: (
                x[2] if has_measured_bytes else x[1],
                x[1],
                x[0],
            ),
            reverse=True,
        )[:top_k]
        if host_rows:
            labels = [_shorten(ip, 40) for ip, _, _ in host_rows]
            bytes_total = [b for _, _, b in host_rows]
            flows_total = [f for _, f, _ in host_rows]
            fig, ax = plt.subplots(figsize=(11, 6))
            if has_measured_bytes:
                ax.bar(
                    labels,
                    bytes_total,
                    color="#9467bd",
                    alpha=0.75,
                    label="Observed bytes",
                )
                ax.set_ylabel("Observed bytes")
                ax2 = ax.twinx()
                ax2.plot(labels, flows_total, color="#d62728", marker="o", label="Flows")
                ax2.set_ylabel("Flows")
                ax.set_title(f"Top {top_k} Hosts: Observed Bytes vs Flows")
                caption = (
                    "Comparison of top hosts by observed traffic volume "
                    "and flow count."
                )
            else:
                ax.bar(labels, flows_total, color="#d62728", alpha=0.8)
                ax.set_ylabel("Flows")
                ax.set_title(
                    f"Top {top_k} Hosts by Flow Count (Byte Volume Unavailable)"
                )
                caption = (
                    "Top hosts by flow count; the selected source does not "
                    "provide measured byte volume."
                )
            ax.tick_params(axis="x", rotation=30)
            out_path = os.path.join(assets_dir, "host_traffic_mix.png")
            _save_figure(fig, out_path)
            plt.close(fig)
            figures.append(
                {
                    "path": _portable_relative_path(out_path, report_dir),
                    "caption": caption,
                    "section": "Inventory",
                }
            )

    if not manifest_path:
        manifest_path = os.path.join(report_dir, "figures_manifest.json")
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "figures": figures,
    }
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return manifest_path
