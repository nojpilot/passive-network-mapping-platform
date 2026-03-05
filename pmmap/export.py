"""Lightweight export/report generator."""

from __future__ import annotations

import json
import os
import subprocess
from collections import deque
from datetime import datetime, timezone
from heapq import nlargest
from typing import Any, Dict, List, Sequence

import networkx as nx


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if not path or not os.path.isfile(path):
        return records
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _load_json(path: str) -> Dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            return {}


def _load_figures_manifest(path: str | None, out_dir: str) -> List[Dict[str, str]]:
    candidates: List[str] = []
    if path:
        candidates.append(path)
    candidates.append(os.path.join(out_dir, "figures_manifest.json"))

    selected = None
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            selected = candidate
            break
    if not selected:
        return []

    try:
        with open(selected, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    if isinstance(payload, dict):
        raw_figures = payload.get("figures")
        if not isinstance(raw_figures, list):
            return []
    elif isinstance(payload, list):
        raw_figures = payload
    else:
        return []

    figures: List[Dict[str, str]] = []
    for item in raw_figures:
        if not isinstance(item, dict):
            continue
        fig_path = item.get("path")
        if not isinstance(fig_path, str) or not fig_path.strip():
            continue
        caption = item.get("caption")
        if not isinstance(caption, str):
            caption = ""
        section = item.get("section")
        if not isinstance(section, str):
            section = "Vizualizace"
        # Keep paths relative to report output dir for portable markdown/PDF export.
        if os.path.isabs(fig_path):
            fig_path = os.path.relpath(fig_path, out_dir)
        figures.append(
            {
                "path": fig_path,
                "caption": caption,
                "section": section,
            }
        )
    return figures


def _top_critical(crit: List[Dict[str, Any]], k: int = 10) -> List[Dict[str, Any]]:
    if not crit:
        return []
    return nlargest(k, crit, key=lambda rec: _as_float(rec.get("score", 0.0)))


def _fingerprint_summary(enriched: List[Dict[str, Any]], k: int = 10) -> Dict[str, List[tuple[str, int]]]:
    from collections import Counter

    ja3 = Counter()
    ja3s = Counter()
    hassh = Counter()
    sni = Counter()
    cpe = Counter()
    for rec in enriched:
        for key, ctr in (
            ("client_ja3", ja3),
            ("server_ja3s", ja3s),
            ("hassh", hassh),
            ("sni_served", sni),
            ("sni_used", sni),
        ):
            values = rec.get(key) or []
            for item in values:
                if isinstance(item, dict):
                    val = item.get("value")
                    cnt = item.get("count", 1)
                else:
                    val = item
                    cnt = 1
                if val:
                    ctr[val] += cnt
        for entry in rec.get("cpe") or []:
            if isinstance(entry, dict):
                val = entry.get("cpe")
            else:
                val = entry
            if val:
                cpe[val] += 1
    def top(counter: Counter):
        return counter.most_common(k)
    return {
        "ja3": top(ja3),
        "ja3s": top(ja3s),
        "hassh": top(hassh),
        "sni": top(sni),
        "cpe": top(cpe),
    }


def _top_edges(graph: Dict[str, Any], k: int = 10) -> List[Dict[str, Any]]:
    edges = graph.get("edges") or []
    if not edges:
        return []
    return nlargest(k, edges, key=lambda e: (e.get("flows", 0), e.get("bytes", 0)))


def _shortest_paths_total(graph: nx.Graph) -> dict[str, int]:
    """Count total number of shortest paths from each node to all others."""
    totals: dict[str, int] = {node: 0 for node in graph.nodes()}
    for source in graph.nodes():
        dist: dict[str, int] = {source: 0}
        sigma: dict[str, int] = {source: 1}
        queue = deque([source])
        while queue:
            v = queue.popleft()
            for w in graph.neighbors(v):
                if w not in dist:
                    dist[w] = dist[v] + 1
                    sigma[w] = sigma[v]
                    queue.append(w)
                elif dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
        totals[source] = sum(sigma.values()) - 1
    return totals


def _build_host_graph(graph: Dict[str, Any]) -> nx.DiGraph:
    """Project host→service edges into a host→host dependency graph."""
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    host_nodes = {n.get("id") for n in nodes if n.get("type") == "host" and n.get("id")}
    service_nodes = {n.get("id"): n for n in nodes if n.get("type") == "service" and n.get("id")}

    G = nx.DiGraph()
    for host_id in host_nodes:
        G.add_node(host_id)

    for edge in edges:
        src = edge.get("src")
        svc_id = edge.get("dst")
        svc = service_nodes.get(svc_id)
        if not src or not svc:
            continue
        dst = svc.get("ip")
        if not dst:
            continue
        flows = int(edge.get("flows", 0) or 0)
        bytes_val = int(edge.get("bytes", 0) or 0)
        if not G.has_node(src):
            G.add_node(src)
        if not G.has_node(dst):
            G.add_node(dst)
        if G.has_edge(src, dst):
            G[src][dst]["flows"] += flows
            G[src][dst]["bytes"] += bytes_val
        else:
            G.add_edge(src, dst, flows=flows, bytes=bytes_val)
    return G


def _host_metrics(
    graph: Dict[str, Any],
    hosts: List[Dict[str, Any]],
    criticality: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Compute per-host metrics for reporting."""
    host_graph = _build_host_graph(graph)
    n_nodes = host_graph.number_of_nodes()
    meta = {
        "nodes": n_nodes,
        "betweenness_sample_k": None,
        "betweenness_computed": False,
        "closeness_computed": False,
        "shortest_paths_computed": False,
        "shortest_paths_max_nodes": 500,
    }
    if n_nodes == 0:
        return [], meta

    host_lookup = {h.get("ip"): h for h in hosts if h.get("ip")}
    crit_map = {c.get("id"): c.get("score") for c in criticality if c.get("id")}

    degree = dict(host_graph.degree())
    in_degree = dict(host_graph.in_degree())
    out_degree = dict(host_graph.out_degree())

    # Centrality metrics on undirected projection for stability.
    ug = host_graph.to_undirected()
    betweenness: Dict[str, float] = {node_id: 0.0 for node_id in ug.nodes()}
    betw_k = None
    if ug.number_of_nodes() <= 2000:
        betw_k = None
    elif ug.number_of_nodes() <= 10000:
        betw_k = min(64, ug.number_of_nodes())
    else:
        meta["betweenness_skipped_reason"] = "graph_too_large"

    if "betweenness_skipped_reason" not in meta:
        meta["betweenness_sample_k"] = betw_k
        betweenness = nx.betweenness_centrality(
            ug,
            normalized=True,
            k=betw_k,
            seed=42 if betw_k else None,
        )
        meta["betweenness_computed"] = True

    closeness = {}
    if ug.number_of_nodes() <= 2000:
        closeness = nx.closeness_centrality(ug)
        meta["closeness_computed"] = True

    shortest_paths_total = {}
    if ug.number_of_nodes() <= meta["shortest_paths_max_nodes"]:
        shortest_paths_total = _shortest_paths_total(ug)
        meta["shortest_paths_computed"] = True

    metrics: List[Dict[str, Any]] = []
    for node_id in sorted(ug.nodes()):
        host = host_lookup.get(node_id, {})
        bytes_in = int(host.get("bytes_in", 0) or 0)
        bytes_out = int(host.get("bytes_out", 0) or 0)
        flows_in = int(host.get("flows_in", 0) or 0)
        flows_out = int(host.get("flows_out", 0) or 0)
        metrics.append(
            {
                "id": node_id,
                "degree": int(degree.get(node_id, 0)),
                "in_degree": int(in_degree.get(node_id, 0)),
                "out_degree": int(out_degree.get(node_id, 0)),
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "bytes_total": bytes_in + bytes_out,
                "flows_in": flows_in,
                "flows_out": flows_out,
                "flows_total": flows_in + flows_out,
                "betweenness": float(betweenness.get(node_id, 0.0)),
                "closeness": float(closeness.get(node_id, 0.0)) if closeness else None,
                "shortest_paths_total": int(shortest_paths_total.get(node_id, 0))
                if shortest_paths_total
                else None,
                "criticality_score": crit_map.get(node_id),
            }
        )
    return metrics, meta


def _top_items(metrics: List[Dict[str, Any]], key: str, k: int = 10) -> List[Dict[str, Any]]:
    def _val(rec: Dict[str, Any]):
        value = rec.get(key)
        if value is None:
            return 0
        return value

    return sorted(metrics, key=_val, reverse=True)[:k]


def _format_metric_value(key: str, value: Any) -> str:
    if value is None:
        return "0"
    if key in {"degree", "bytes_total", "flows_total", "shortest_paths_total"}:
        try:
            return str(int(value))
        except Exception:
            return str(value)
    try:
        return f"{float(value):.6f}"
    except Exception:
        return str(value)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _md_escape(value: Any) -> str:
    text = str(value) if value is not None else ""
    return text.replace("\n", " ").replace("|", "\\|").strip()


def _fmt_int(value: Any) -> str:
    return f"{_as_int(value):,}"


def _fmt_float(value: Any, digits: int = 6) -> str:
    return f"{_as_float(value):.{digits}f}"


def _fmt_optional_float(value: Any, digits: int = 6, none_value: str = "-") -> str:
    if value is None:
        return none_value
    return _fmt_float(value, digits=digits)


def _add_table(
    md_lines: List[str],
    headers: Sequence[str],
    alignments: Sequence[str],
    rows: Sequence[Sequence[str]],
) -> None:
    align_map = {"l": "---", "r": "---:", "c": ":---:"}
    md_lines.append("| " + " | ".join(headers) + " |")
    md_lines.append("| " + " | ".join(align_map.get(a, "---") for a in alignments) + " |")
    for row in rows:
        md_lines.append("| " + " | ".join(row) + " |")
    md_lines.append("")


def _render_report_markdown(
    *,
    title: str,
    top_k: int,
    stats: Dict[str, Any],
    criticality: List[Dict[str, Any]],
    hosts: List[Dict[str, Any]],
    top_edges: List[Dict[str, Any]],
    host_metrics: List[Dict[str, Any]],
    host_meta: Dict[str, Any],
    fp_summary: Dict[str, List[tuple[str, int]]],
    figures: List[Dict[str, str]],
    pdf_enabled: bool,
) -> List[str]:
    md_lines: List[str] = []
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    md_lines.append(f"# {title}")
    md_lines.append("")
    md_lines.append(f"_Generated: {generated_at}_")
    md_lines.append("")

    md_lines.append("## Executive Summary")
    md_lines.append("")
    summary_rows = [
        ["Hosts", _fmt_int(stats.get("hosts", 0))],
        ["Services", _fmt_int(stats.get("services", 0))],
        ["Communication edges", _fmt_int(stats.get("edges", 0))],
        ["Criticality rows", _fmt_int(len(criticality))],
        ["Host metrics rows", _fmt_int(len(host_metrics))],
        ["Figures", _fmt_int(len(figures))],
    ]
    _add_table(md_lines, ["Metric", "Value"], ["l", "r"], summary_rows)

    if criticality:
        md_lines.append(f"## Top {top_k} Critical Nodes")
        md_lines.append("")
        crit_rows = []
        for idx, entry in enumerate(_top_critical(criticality, k=top_k), start=1):
            crit_rows.append(
                [
                    str(idx),
                    _md_escape(entry.get("id", "")),
                    _fmt_float(entry.get("score", 0.0), digits=4),
                    _md_escape(entry.get("method") or "-"),
                ]
            )
        _add_table(
            md_lines,
            ["Rank", "Node", "Score", "Method"],
            ["r", "l", "r", "l"],
            crit_rows,
        )

    if hosts:
        md_lines.append(f"## Host Inventory Snapshot (Top {top_k})")
        md_lines.append("")
        md_lines.append("Hosts are ranked by total traffic volume (`bytes_in + bytes_out`).")
        md_lines.append("")
        ranked_hosts = sorted(
            hosts,
            key=lambda h: (
                _as_int(h.get("bytes_in", 0)) + _as_int(h.get("bytes_out", 0)),
                _as_int(h.get("flows_in", 0)) + _as_int(h.get("flows_out", 0)),
            ),
            reverse=True,
        )[:top_k]
        host_rows = []
        for idx, host in enumerate(ranked_hosts, start=1):
            roles_raw = [str(role) for role in (host.get("roles") or [])]
            roles = ", ".join(sorted(roles_raw)) if roles_raw else "unknown"
            host_rows.append(
                [
                    str(idx),
                    _md_escape(host.get("ip", "")),
                    _md_escape(roles),
                    _fmt_int(host.get("bytes_in", 0)),
                    _fmt_int(host.get("bytes_out", 0)),
                    _fmt_int(host.get("flows_in", 0)),
                    _fmt_int(host.get("flows_out", 0)),
                ]
            )
        _add_table(
            md_lines,
            ["Rank", "Host IP", "Roles", "Bytes In", "Bytes Out", "Flows In", "Flows Out"],
            ["r", "l", "l", "r", "r", "r", "r"],
            host_rows,
        )

    if top_edges:
        md_lines.append(f"## Top Communication Edges (Top {top_k})")
        md_lines.append("")
        edge_rows = []
        for idx, edge in enumerate(top_edges, start=1):
            edge_rows.append(
                [
                    str(idx),
                    _md_escape(edge.get("src", "")),
                    _md_escape(edge.get("dst", "")),
                    _fmt_int(edge.get("flows", 0)),
                    _fmt_int(edge.get("bytes", 0)),
                ]
            )
        _add_table(
            md_lines,
            ["Rank", "Source", "Destination", "Flows", "Bytes"],
            ["r", "l", "l", "r", "r"],
            edge_rows,
        )

    if host_metrics:
        md_lines.append(f"## Host Metrics (Top {top_k})")
        md_lines.append("")
        md_lines.append("Metrics are computed on a host-to-host projection (client -> server).")
        md_lines.append("")

        notes_rows = []
        if host_meta.get("betweenness_computed"):
            if host_meta.get("betweenness_sample_k"):
                notes_rows.append(
                    ["Betweenness", f"Approximation with sample k={host_meta['betweenness_sample_k']}"]
                )
            else:
                notes_rows.append(["Betweenness", "Exact"])
        else:
            notes_rows.append(["Betweenness", "Skipped (graph too large)"])
        notes_rows.append(
            [
                "Closeness",
                "Computed" if host_meta.get("closeness_computed") else "Skipped (graph too large)",
            ]
        )
        notes_rows.append(
            [
                "Shortest-path counts",
                "Computed"
                if host_meta.get("shortest_paths_computed")
                else "Skipped (graph too large)",
            ]
        )
        _add_table(md_lines, ["Computation", "Status"], ["l", "l"], notes_rows)

        has_criticality = any(rec.get("criticality_score") is not None for rec in host_metrics)
        sort_key = "criticality_score" if has_criticality else "degree"
        metric_rows = []
        for idx, rec in enumerate(_top_items(host_metrics, sort_key, k=top_k), start=1):
            metric_rows.append(
                [
                    str(idx),
                    _md_escape(rec.get("id", "")),
                    _fmt_int(rec.get("degree", 0)),
                    _fmt_int(rec.get("in_degree", 0)),
                    _fmt_int(rec.get("out_degree", 0)),
                    _fmt_int(rec.get("bytes_total", 0)),
                    _fmt_int(rec.get("flows_total", 0)),
                    _fmt_float(rec.get("betweenness", 0.0), digits=6),
                    _fmt_optional_float(rec.get("closeness"), digits=6),
                    _fmt_int(rec.get("shortest_paths_total", 0))
                    if rec.get("shortest_paths_total") is not None
                    else "-",
                    _fmt_optional_float(rec.get("criticality_score"), digits=6),
                ]
            )
        _add_table(
            md_lines,
            [
                "Rank",
                "Host IP",
                "Degree",
                "In",
                "Out",
                "Bytes",
                "Flows",
                "Betweenness",
                "Closeness",
                "Shortest Paths",
                "Criticality",
            ],
            ["r", "l", "r", "r", "r", "r", "r", "r", "r", "r", "r"],
            metric_rows,
        )

        md_lines.append("### Metric Leaders")
        md_lines.append("")
        for table_title, key in (
            ("Degree", "degree"),
            ("Betweenness", "betweenness"),
            ("Traffic Bytes", "bytes_total"),
            ("Traffic Flows", "flows_total"),
            ("Shortest-path Counts", "shortest_paths_total"),
        ):
            leaders = _top_items(host_metrics, key, k=top_k)
            if not leaders:
                continue
            md_lines.append(f"#### Top {top_k} by {table_title}")
            md_lines.append("")
            leader_rows = []
            for idx, rec in enumerate(leaders, start=1):
                leader_rows.append(
                    [
                        str(idx),
                        _md_escape(rec.get("id", "")),
                        _format_metric_value(key, rec.get(key, 0)),
                    ]
                )
            _add_table(md_lines, ["Rank", "Host IP", "Value"], ["r", "l", "r"], leader_rows)

        md_lines.append("Full per-host metrics are available in `host_metrics.jsonl`.")
        md_lines.append("")

    if fp_summary:
        md_lines.append(f"## Fingerprint and CPE Summary (Top {top_k})")
        md_lines.append("")
        fp_groups = (
            ("SNI", fp_summary.get("sni") or []),
            ("JA3", fp_summary.get("ja3") or []),
            ("JA3S", fp_summary.get("ja3s") or []),
            ("HASSH", fp_summary.get("hassh") or []),
            ("CPE", fp_summary.get("cpe") or []),
        )
        has_fp_data = any(items for _, items in fp_groups)
        if not has_fp_data:
            md_lines.append("No fingerprint artifacts were observed in the selected dataset.")
            md_lines.append("")
        else:
            for section_title, items in fp_groups:
                if not items:
                    continue
                md_lines.append(f"### {section_title}")
                md_lines.append("")
                fp_rows = []
                for idx, (value, count) in enumerate(items, start=1):
                    fp_rows.append([str(idx), _md_escape(value), _fmt_int(count)])
                _add_table(md_lines, ["Rank", "Value", "Count"], ["r", "l", "r"], fp_rows)

    if figures:
        md_lines.append("\\newpage")
        md_lines.append("")
        md_lines.append("## Figures")
        md_lines.append("")
        current_section = None
        for idx, fig in enumerate(figures, start=1):
            section = fig.get("section") or "Visualizations"
            if section != current_section:
                if current_section is not None:
                    md_lines.append("\\clearpage")
                    md_lines.append("")
                md_lines.append(f"### {_md_escape(section)}")
                md_lines.append("")
                current_section = section
            caption = fig.get("caption") or f"Figure {idx}"
            path = str(fig.get("path", "")).strip()
            alt_text = _md_escape(caption)
            md_lines.append(f"![{alt_text}]({path}){{ width=95% }}")
            md_lines.append("")

    if figures:
        md_lines.append("\\clearpage")
        md_lines.append("")
    md_lines.append("## Output Artifacts")
    md_lines.append("")
    artifact_rows = [["Summary JSON", "`summary.json`"], ["Markdown Report", "`report.md`"]]
    if pdf_enabled:
        artifact_rows.append(["PDF Report", "`report.pdf`"])
    if host_metrics:
        artifact_rows.append(["Host Metrics", "`host_metrics.jsonl`"])
    if figures:
        artifact_rows.append(["Figures Manifest", "`figures_manifest.json`"])
    _add_table(md_lines, ["Artifact", "Path"], ["l", "l"], artifact_rows)

    return md_lines


def run(
    hosts_path: str,
    graph_path: str,
    criticality_path: str | None,
    out_dir: str,
    title: str = "Passive Network Mapping Report",
    pdf: bool = False,
    enriched_path: str | None = None,
    top_k: int = 10,
    figures_manifest_path: str | None = None,
    regenerate_figures: bool = True,
):
    """Generate a markdown report + JSON summary from pipeline outputs and optional figure manifest."""
    hosts = _load_jsonl(hosts_path)
    graph = _load_json(graph_path)
    criticality = _load_jsonl(criticality_path) if criticality_path else []
    enriched = _load_jsonl(enriched_path) if enriched_path else []

    os.makedirs(out_dir, exist_ok=True)
    top_k = max(1, int(top_k))
    figures = _load_figures_manifest(figures_manifest_path, out_dir)
    if graph and regenerate_figures:
        try:
            from .report_figures import generate_figures

            manifest_path = generate_figures(
                report_dir=out_dir,
                graph_path=graph_path,
                criticality_path=criticality_path,
                hosts_path=hosts_path if os.path.isfile(hosts_path) else None,
                top_k=top_k,
                manifest_path=figures_manifest_path,
            )
            refreshed = _load_figures_manifest(manifest_path, out_dir)
            if refreshed:
                figures = refreshed
                print(f"[export] Generated {len(figures)} figures for the report.")
        except Exception as exc:
            if figures:
                print(f"[export] Figure generation failed; using existing manifest. Reason: {exc}")
            else:
                print(f"[export] Figure generation failed: {exc}")

    stats = {
        "hosts": len([n for n in (graph.get("nodes") or []) if n.get("type") == "host"]),
        "services": len([n for n in (graph.get("nodes") or []) if n.get("type") == "service"]),
        "edges": len(graph.get("edges") or []),
    }
    fp_summary = _fingerprint_summary(enriched, k=top_k) if enriched else {}
    top_edges = _top_edges(graph, k=top_k) if graph else []
    host_metrics, host_meta = _host_metrics(graph, hosts, criticality) if graph else ([], {})
    top_hosts = {
        "by_degree": _top_items(host_metrics, "degree", k=top_k),
        "by_betweenness": _top_items(host_metrics, "betweenness", k=top_k),
        "by_bytes": _top_items(host_metrics, "bytes_total", k=top_k),
        "by_flows": _top_items(host_metrics, "flows_total", k=top_k),
        "by_shortest_paths": _top_items(host_metrics, "shortest_paths_total", k=top_k),
    }
    generated_at = datetime.now(timezone.utc).isoformat()
    summary = {
        "title": title,
        "generated_at": generated_at,
        "stats": stats,
        "top_critical": _top_critical(criticality, k=top_k),
        "fingerprints": fp_summary,
        "top_edges": top_edges,
        "top_hosts": top_hosts,
        "host_metrics_meta": host_meta,
        "figures": figures,
    }

    # Save JSON summary
    json_out = os.path.join(out_dir, "summary.json")
    with open(json_out, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    if host_metrics:
        metrics_path = os.path.join(out_dir, "host_metrics.jsonl")
        with open(metrics_path, "w", encoding="utf-8") as fh:
            for rec in host_metrics:
                fh.write(json.dumps(rec) + "\n")

    # Markdown report
    md_lines = _render_report_markdown(
        title=title,
        top_k=top_k,
        stats=stats,
        criticality=criticality,
        hosts=hosts,
        top_edges=top_edges,
        host_metrics=host_metrics,
        host_meta=host_meta,
        fp_summary=fp_summary,
        figures=figures,
        pdf_enabled=pdf,
    )

    report_path = os.path.join(out_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md_lines))

    pdf_path = None
    if pdf:
        pdf_path = os.path.join(out_dir, "report.pdf")
        try:
            result = subprocess.run(
                [
                    "pandoc",
                    report_path,
                    "-o",
                    pdf_path,
                    "--resource-path",
                    out_dir,
                    "--standalone",
                    "--toc",
                    "--number-sections",
                    "-V",
                    "figure-placement=H",
                    "-V",
                    "geometry:margin=1in",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            if result.stderr.strip():
                print(f"[export] Pandoc warning: {result.stderr.strip()}")
        except FileNotFoundError:
            print("[export] Pandoc not found; PDF was not generated.")
            pdf_path = None
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or "").strip()
            if err:
                print(f"[export] Pandoc selhal: {err}")
            else:
                print(f"[export] Pandoc selhal: {exc}")
            pdf_path = None

    if pdf_path:
        print(f"[export] Summary → {json_out}, Markdown → {report_path}, PDF → {pdf_path}")
    else:
        print(f"[export] Summary → {json_out}, Markdown → {report_path}")
