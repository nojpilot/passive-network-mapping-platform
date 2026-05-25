"""Generate report-ready static charts and save a figure manifest."""

from __future__ import annotations

import json
import os
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


def _top_edges(graph: Dict[str, Any], k: int) -> List[Dict[str, Any]]:
    return top_service_edges(graph, k=k)


def _shorten(text: str, max_len: int = 60) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "..."


def _save_figure(fig, out_path: str) -> None:
    fig.tight_layout()
    fig.savefig(out_path, dpi=160, bbox_inches="tight")


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
        fallback_cache = os.path.join("/tmp", "matplotlib-cache")
        os.makedirs(fallback_cache, exist_ok=True)
        os.environ["MPLCONFIGDIR"] = fallback_cache
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
                "path": os.path.relpath(out_path, report_dir),
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
                "path": os.path.relpath(out_path, report_dir),
                "caption": f"Top {top_k} service destinations by aggregated number of flows.",
                "section": "Communication Services",
            }
        )

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
                    "path": os.path.relpath(out_path, report_dir),
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
                    int(row.get("bytes_in", 0) or 0) + int(row.get("bytes_out", 0) or 0),
                )
            )
        host_rows = sorted(host_rows, key=lambda x: x[2], reverse=True)[:top_k]
        if host_rows:
            labels = [_shorten(ip, 40) for ip, _, _ in host_rows]
            bytes_total = [b for _, _, b in host_rows]
            flows_total = [f for _, f, _ in host_rows]
            fig, ax = plt.subplots(figsize=(11, 6))
            ax.bar(labels, bytes_total, color="#9467bd", alpha=0.75, label="Bytes")
            ax.set_ylabel("Bytes")
            ax.tick_params(axis="x", rotation=30)
            ax2 = ax.twinx()
            ax2.plot(labels, flows_total, color="#d62728", marker="o", label="Flows")
            ax2.set_ylabel("Flows")
            ax.set_title(f"Top {top_k} Hosts: Bytes vs Flows")
            out_path = os.path.join(assets_dir, "host_traffic_mix.png")
            _save_figure(fig, out_path)
            plt.close(fig)
            figures.append(
                {
                    "path": os.path.relpath(out_path, report_dir),
                    "caption": "Comparison of top hosts by traffic volume and flow count.",
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
