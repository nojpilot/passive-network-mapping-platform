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

from .edge_summary import edge_source_label, top_service_edges
from .centrality import plan_betweenness
from .graph_projection import build_host_graph


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


def _host_id(record: Dict[str, Any]) -> str | None:
    value = record.get("ip") or record.get("id")
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _scope_status_by_host(
    graph: Dict[str, Any],
    hosts: List[Dict[str, Any]],
    criticality: List[Dict[str, Any]] | None = None,
) -> Dict[str, bool | None]:
    """Merge host scope markers, with any explicit ``False`` taking priority."""
    status: Dict[str, bool | None] = {}

    graph_hosts = [
        node
        for node in (graph.get("nodes") or [])
        if isinstance(node, dict) and node.get("type") == "host"
    ]
    for record in [*graph_hosts, *hosts, *(criticality or [])]:
        host_id = _host_id(record)
        if not host_id:
            continue
        status.setdefault(host_id, None)
        marker = record.get("in_scope")
        if marker is False:
            status[host_id] = False
        elif marker is True and status[host_id] is not False:
            status[host_id] = True
    return status


def _observed_bytes(host: Dict[str, Any]) -> int:
    """Return the canonical per-host traffic total."""
    if host.get("bytes_observed") is not None:
        return _as_int(host.get("bytes_observed"))
    # Backward-compatible fallback for inventory artifacts created before
    # bytes_observed was introduced.
    return _as_int(host.get("bytes_in")) + _as_int(host.get("bytes_out"))


def _portable_relative_path(path: str, start: str) -> str:
    """Return a relative path using POSIX separators for portable artifacts."""
    return os.path.relpath(path, start).replace("\\", "/")


def _load_figures_manifest(path: str | None, out_dir: str) -> List[Dict[str, str]]:
    """Load exactly the requested manifest without implicit stale fallback."""
    if not path or not os.path.isfile(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as fh:
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
            fig_path = _portable_relative_path(fig_path, out_dir)
        else:
            # A manifest produced on Windows may later be consumed elsewhere.
            fig_path = fig_path.replace("\\", "/")
        figures.append(
            {
                "path": fig_path,
                "caption": caption,
                "section": section,
            }
        )
    return figures


def _top_critical(crit: List[Dict[str, Any]], k: int = 10) -> List[Dict[str, Any]]:
    eligible = [record for record in crit if record.get("in_scope") is not False]
    if not eligible:
        return []
    return nlargest(k, eligible, key=lambda rec: _as_float(rec.get("score", 0.0)))


def _fingerprint_summary(enriched: List[Dict[str, Any]], k: int = 10) -> Dict[str, List[tuple[str, int]]]:
    from collections import Counter

    ja3 = Counter()
    ja3s = Counter()
    hassh_client = Counter()
    hassh_server = Counter()
    sni_requested = Counter()
    sni_served = Counter()
    cpe_hosts = Counter()
    for rec in enriched:
        for key, ctr in (
            ("client_ja3", ja3),
            ("server_ja3s", ja3s),
            ("hassh", hassh_client),
            ("server_hassh", hassh_server),
            ("sni_used", sni_requested),
            ("sni_served", sni_served),
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
        host_cpe_values: set[str] = set()
        for entry in rec.get("cpe") or []:
            if isinstance(entry, dict):
                val = entry.get("cpe")
            else:
                val = entry
            if val:
                host_cpe_values.add(str(val))
        for value in host_cpe_values:
            cpe_hosts[value] += 1

    def top(counter: Counter):
        return counter.most_common(k)

    return {
        "ja3": top(ja3),
        "ja3s": top(ja3s),
        "hassh_client": top(hassh_client),
        "hassh_server": top(hassh_server),
        "sni_requested": top(sni_requested),
        "sni_served": top(sni_served),
        "cpe_host_hypotheses": top(cpe_hosts),
    }


def _top_edges(graph: Dict[str, Any], k: int = 10) -> List[Dict[str, Any]]:
    return top_service_edges(graph, k=k)


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


def _host_metrics(
    graph: Dict[str, Any],
    hosts: List[Dict[str, Any]],
    criticality: List[Dict[str, Any]],
    excluded_host_ids: set[str] | None = None,
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Compute per-host metrics for reporting."""
    host_graph = build_host_graph(
        graph.get("nodes") or [],
        graph.get("edges") or [],
    )
    excluded = set(excluded_host_ids or ())
    excluded.update(
        str(node_id)
        for node_id, attrs in host_graph.nodes(data=True)
        if attrs.get("in_scope") is False
    )
    excluded.update(
        str(host.get("ip"))
        for host in hosts
        if host.get("ip") and host.get("in_scope") is False
    )
    removed_host_ids = excluded.intersection(str(node_id) for node_id in host_graph.nodes())
    host_graph.remove_nodes_from(removed_host_ids)
    n_nodes = host_graph.number_of_nodes()
    meta = {
        "nodes": n_nodes,
        "excluded_out_of_scope_hosts": len(removed_host_ids),
        "betweenness_sample_k": None,
        "betweenness_mode": "skipped",
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
    betweenness_plan = plan_betweenness(
        ug.number_of_nodes(),
        ug.number_of_edges(),
    )
    meta["betweenness_mode"] = betweenness_plan["mode"]
    meta["betweenness_plan"] = betweenness_plan
    if betweenness_plan["skipped_reason"]:
        meta["betweenness_skipped_reason"] = betweenness_plan["skipped_reason"]

    if betweenness_plan["mode"] != "skipped":
        betw_k = betweenness_plan["sample_k"]
        meta["betweenness_sample_k"] = betw_k
        betweenness = nx.betweenness_centrality(
            ug,
            normalized=True,
            weight=None,
            k=betw_k,
            seed=betweenness_plan["sample_seed"] if betw_k else None,
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
        bytes_observed = _observed_bytes(host)
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
                "bytes_observed": bytes_observed,
                "bytes_total": bytes_observed,
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


def _top_positive_items(
    metrics: List[Dict[str, Any]],
    key: str,
    k: int = 10,
) -> List[Dict[str, Any]]:
    """Return leaders only when the selected metric contains information."""
    leaders = _top_items(metrics, key, k=k)
    if not leaders or not any(_as_float(record.get(key)) for record in leaders):
        return []
    return leaders


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
    figures_manifest_label: str | None = None,
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
        ["Hosts (total)", _fmt_int(stats.get("hosts", 0))],
        ["Hosts (in scope)", _fmt_int(stats.get("hosts_in_scope", 0))],
        ["Hosts (external)", _fmt_int(stats.get("hosts_external", 0))],
        ["Hosts (scope unknown)", _fmt_int(stats.get("hosts_scope_unknown", 0))],
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
        has_measured_bytes = any(_observed_bytes(host) for host in hosts)
        if has_measured_bytes:
            md_lines.append(
                "Hosts are ranked by canonical observed traffic volume (`bytes_observed`)."
            )
        else:
            md_lines.append(
                "Measured byte volume is unavailable; hosts are ranked by observed flow count."
            )
        md_lines.append("")
        ranked_hosts = sorted(
            hosts,
            key=lambda h: (
                (
                    _observed_bytes(h)
                    if has_measured_bytes
                    else _as_int(h.get("flows_in", 0)) + _as_int(h.get("flows_out", 0))
                ),
                _as_int(h.get("flows_in", 0)) + _as_int(h.get("flows_out", 0)),
                str(h.get("ip", "")),
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
                    _fmt_int(_observed_bytes(host)),
                    _fmt_int(host.get("flows_in", 0)),
                    _fmt_int(host.get("flows_out", 0)),
                ]
            )
        _add_table(
            md_lines,
            ["Rank", "Host IP", "Roles", "Bytes Observed", "Flows In", "Flows Out"],
            ["r", "l", "l", "r", "r", "r"],
            host_rows,
        )

    if top_edges:
        md_lines.append(f"## Top Service Destinations (Top {top_k})")
        md_lines.append("")
        md_lines.append(
            "Client-to-service edges are aggregated by destination service to highlight repeated service hubs."
        )
        md_lines.append("")
        edge_rows = []
        for idx, edge in enumerate(top_edges, start=1):
            edge_rows.append(
                [
                    str(idx),
                    _md_escape(edge_source_label(edge)),
                    _md_escape(edge.get("dst", "")),
                    _fmt_int(edge.get("flows", 0)),
                    _fmt_int(edge.get("bytes", 0)),
                ]
            )
        _add_table(
            md_lines,
            ["Rank", "Sources", "Destination Service", "Flows", "Bytes"],
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
            skipped_reason = host_meta.get(
                "betweenness_skipped_reason",
                "resource policy",
            )
            notes_rows.append(
                ["Betweenness", f"Skipped ({skipped_reason.replace('_', ' ')})"]
            )
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
                "Observed Bytes",
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
            ("Observed Traffic Bytes", "bytes_total"),
            ("Traffic Flows", "flows_total"),
            ("Shortest-path Counts", "shortest_paths_total"),
        ):
            leaders = _top_items(host_metrics, key, k=top_k)
            if not leaders or not any(_as_float(item.get(key)) for item in leaders):
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
        md_lines.append(
            "Requested and served SNI observations are reported separately. "
            "CPE values are fingerprint-derived host hypotheses; their count is "
            "the number of distinct hosts carrying each hypothesis."
        )
        md_lines.append("")
        fp_groups = (
            ("SNI Requested", fp_summary.get("sni_requested") or []),
            ("SNI Served", fp_summary.get("sni_served") or []),
            ("JA3", fp_summary.get("ja3") or []),
            ("JA3S", fp_summary.get("ja3s") or []),
            ("HASSH Client", fp_summary.get("hassh_client") or []),
            ("HASSH Server", fp_summary.get("hassh_server") or []),
            ("CPE Host Hypotheses", fp_summary.get("cpe_host_hypotheses") or []),
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
    if figures_manifest_label:
        artifact_rows.append(
            ["Figures Manifest", f"`{_md_escape(figures_manifest_label)}`"]
        )
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
    if not os.path.isfile(hosts_path):
        raise FileNotFoundError(f"Hosts file '{hosts_path}' does not exist.")
    if not os.path.isfile(graph_path):
        raise FileNotFoundError(f"Graph file '{graph_path}' does not exist.")

    all_hosts = _load_jsonl(hosts_path)
    graph = _load_json(graph_path)
    if not graph:
        raise ValueError(f"Graph file '{graph_path}' is empty or invalid JSON.")
    if not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise ValueError(
            f"Graph file '{graph_path}' has an invalid structure; nodes and edges must be lists."
        )

    all_criticality = _load_jsonl(criticality_path) if criticality_path else []
    enriched = _load_jsonl(enriched_path) if enriched_path else []
    scope_status = _scope_status_by_host(graph, all_hosts, all_criticality)
    excluded_host_ids = {
        host_id for host_id, in_scope in scope_status.items() if in_scope is False
    }
    hosts = [
        host
        for host in all_hosts
        if _host_id(host) not in excluded_host_ids
        and host.get("in_scope") is not False
    ]
    criticality = [
        record
        for record in all_criticality
        if _host_id(record) not in excluded_host_ids
        and record.get("in_scope") is not False
    ]

    os.makedirs(out_dir, exist_ok=True)
    # Never leave a PDF from an earlier run masquerading as current output.
    # A fresh PDF is created below only when explicitly requested and Pandoc
    # succeeds.
    stale_pdf_path = os.path.join(out_dir, "report.pdf")
    if os.path.isfile(stale_pdf_path):
        os.remove(stale_pdf_path)
    top_k = max(1, int(top_k))
    default_manifest_path = os.path.join(out_dir, "figures_manifest.json")
    figures: List[Dict[str, str]] = []
    manifest_path_used: str | None = None
    if figures_manifest_path:
        # An explicit manifest is user-owned input. It is authoritative and
        # must never be overwritten by automatic chart generation.
        figures = _load_figures_manifest(figures_manifest_path, out_dir)
        if os.path.isfile(figures_manifest_path):
            manifest_path_used = figures_manifest_path
        if regenerate_figures:
            print(
                "[export] Explicit figure manifest supplied; "
                "automatic figure regeneration was skipped."
            )
    elif graph and regenerate_figures:
        # Remove the previous generated manifest before trying a new run. If
        # chart generation fails, the report must not silently reuse it.
        if os.path.isfile(default_manifest_path):
            os.remove(default_manifest_path)
        try:
            from .report_figures import generate_figures

            manifest_path = generate_figures(
                report_dir=out_dir,
                graph_path=graph_path,
                criticality_path=criticality_path,
                hosts_path=hosts_path if os.path.isfile(hosts_path) else None,
                top_k=top_k,
                manifest_path=None,
            )
            figures = _load_figures_manifest(manifest_path, out_dir)
            if os.path.isfile(manifest_path):
                manifest_path_used = manifest_path
            print(f"[export] Generated {len(figures)} figures for the report.")
        except Exception as exc:
            figures = []
            manifest_path_used = None
            if os.path.isfile(default_manifest_path):
                os.remove(default_manifest_path)
            print(f"[export] Figure generation failed: {exc}")
    elif not regenerate_figures and os.path.isfile(default_manifest_path):
        # Reuse of the default generated manifest is opt-in through
        # regenerate_figures=False.
        figures = _load_figures_manifest(default_manifest_path, out_dir)
        manifest_path_used = default_manifest_path

    graph_host_ids = {
        str(node.get("id"))
        for node in (graph.get("nodes") or [])
        if isinstance(node, dict) and node.get("type") == "host" and node.get("id")
    }
    hosts_in_scope = sum(
        scope_status.get(host_id) is True for host_id in graph_host_ids
    )
    hosts_external = sum(
        scope_status.get(host_id) is False for host_id in graph_host_ids
    )

    stats = {
        "hosts": len(graph_host_ids),
        "hosts_internal": hosts_in_scope,
        "hosts_in_scope": hosts_in_scope,
        "hosts_external": hosts_external,
        "hosts_scope_unknown": len(graph_host_ids) - hosts_in_scope - hosts_external,
        "services": len([n for n in (graph.get("nodes") or []) if n.get("type") == "service"]),
        "edges": len(graph.get("edges") or []),
    }
    fp_summary = _fingerprint_summary(enriched, k=top_k) if enriched else {}
    top_edges = _top_edges(graph, k=top_k) if graph else []
    host_metrics, host_meta = (
        _host_metrics(
            graph,
            hosts,
            criticality,
            excluded_host_ids=excluded_host_ids,
        )
        if graph
        else ([], {})
    )
    top_hosts = {
        "by_degree": _top_positive_items(host_metrics, "degree", k=top_k),
        "by_betweenness": _top_positive_items(host_metrics, "betweenness", k=top_k),
        "by_bytes": _top_positive_items(host_metrics, "bytes_total", k=top_k),
        "by_flows": _top_positive_items(host_metrics, "flows_total", k=top_k),
        "by_shortest_paths": _top_positive_items(
            host_metrics,
            "shortest_paths_total",
            k=top_k,
        ),
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
        "figures_manifest": (
            _portable_relative_path(manifest_path_used, out_dir)
            if manifest_path_used
            else None
        ),
    }

    json_out = os.path.join(out_dir, "summary.json")

    if host_metrics:
        metrics_path = os.path.join(out_dir, "host_metrics.jsonl")
        with open(metrics_path, "w", encoding="utf-8") as fh:
            for rec in host_metrics:
                fh.write(json.dumps(rec) + "\n")

    report_path = os.path.join(out_dir, "report.md")

    def write_markdown(pdf_generated: bool) -> None:
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
            pdf_enabled=pdf_generated,
            figures_manifest_label=summary.get("figures_manifest"),
        )
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(md_lines))

    # The provisional report never advertises a PDF. The artifact row is
    # added only after Pandoc succeeds and the output file is verified.
    write_markdown(pdf_generated=False)

    pdf_path = None
    if pdf:
        requested_pdf_path = os.path.join(out_dir, "report.pdf")
        try:
            result = subprocess.run(
                [
                    "pandoc",
                    report_path,
                    "-o",
                    requested_pdf_path,
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
            stderr = (getattr(result, "stderr", "") or "").strip()
            if stderr:
                print(f"[export] Pandoc warning: {stderr}")
            if (
                os.path.isfile(requested_pdf_path)
                and os.path.getsize(requested_pdf_path) > 0
            ):
                pdf_path = requested_pdf_path
            else:
                print(
                    "[export] Pandoc completed without creating report.pdf; "
                    "PDF was not generated."
                )
        except FileNotFoundError:
            print("[export] Pandoc not found; PDF was not generated.")
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or "").strip()
            if err:
                print(f"[export] Pandoc failed: {err}")
            else:
                print(f"[export] Pandoc failed: {exc}")
        if pdf_path is None and os.path.isfile(requested_pdf_path):
            os.remove(requested_pdf_path)

    if pdf_path:
        write_markdown(pdf_generated=True)

    summary["artifacts"] = {
        "summary_json": "summary.json",
        "report_markdown": "report.md",
        "report_pdf": "report.pdf" if pdf_path else None,
        "host_metrics": "host_metrics.jsonl" if host_metrics else None,
        "figures_manifest": summary.get("figures_manifest"),
    }
    with open(json_out, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    if pdf_path:
        print(f"[export] Summary -> {json_out}, Markdown -> {report_path}, PDF -> {pdf_path}")
    else:
        print(f"[export] Summary -> {json_out}, Markdown -> {report_path}")
