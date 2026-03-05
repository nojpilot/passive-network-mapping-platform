"""Interactive controls for stage-focused Jupyter notebooks."""

from __future__ import annotations

import json
from collections import Counter
from heapq import nlargest
from pathlib import Path
from typing import Iterable

from . import pipeline
from .notebook_common import display_table, ensure_exists, read_jsonl


def _load_widgets():
    try:
        import ipywidgets as widgets
        from IPython.display import clear_output
    except ImportError as exc:
        raise RuntimeError(
            "Missing ipywidgets. Install requirements and restart the kernel."
        ) from exc
    return widgets, clear_output


def _split_csv(value: str) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _as_path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _is_real_value_change(change: dict) -> bool:
    """Ignore widget initialization/sync events that can trigger duplicate previews."""
    if change.get("name") != "value":
        return False
    old = change.get("old")
    new = change.get("new")
    if old is None:
        return False
    return old != new


def create_artifact_overview_controls(run_dir: str | Path):
    widgets, clear_output = _load_widgets()
    run_path = Path(run_dir)

    btn_refresh = widgets.Button(
        description="Refresh Artifacts",
        button_style="info",
        icon="refresh",
    )
    output = widgets.Output(layout={"border": "1px solid #cfcfcf", "padding": "8px"})

    def _rows():
        return [
            {
                "artifact": "normalized",
                "exists": (run_path / "normalized" / "flows.jsonl").exists(),
                "path": str(run_path / "normalized" / "flows.jsonl"),
            },
            {
                "artifact": "inventory",
                "exists": (run_path / "inventory" / "hosts.jsonl").exists(),
                "path": str(run_path / "inventory" / "hosts.jsonl"),
            },
            {
                "artifact": "enriched",
                "exists": (run_path / "enriched" / "enriched_hosts.jsonl").exists(),
                "path": str(run_path / "enriched" / "enriched_hosts.jsonl"),
            },
            {
                "artifact": "graph",
                "exists": (run_path / "graph" / "graph.json").exists(),
                "path": str(run_path / "graph" / "graph.json"),
            },
            {
                "artifact": "criticality",
                "exists": (run_path / "criticality" / "criticality.jsonl").exists(),
                "path": str(run_path / "criticality" / "criticality.jsonl"),
            },
            {
                "artifact": "report",
                "exists": (run_path / "report" / "report.md").exists(),
                "path": str(run_path / "report" / "report.md"),
            },
            {
                "artifact": "report_pdf",
                "exists": (run_path / "report" / "report.pdf").exists(),
                "path": str(run_path / "report" / "report.pdf"),
            },
        ]

    def _refresh():
        with output:
            clear_output(wait=True)
            display_table(
                _rows(),
                [("artifact", "artifact"), ("exists", "exists"), ("path", "path")],
                "Current Artifacts",
                limit=20,
            )

    btn_refresh.on_click(lambda _: _refresh())
    _refresh()

    return widgets.VBox(
        [
            widgets.HTML("<b>Artifact status</b>"),
            btn_refresh,
            output,
        ]
    )


def create_normalize_controls(data_dir: str | Path, run_dir: str | Path):
    widgets, clear_output = _load_widgets()
    data_path = Path(data_dir)
    run_path = Path(run_dir)

    input_dir = widgets.Text(
        value=str(data_path / "ingested"),
        description="Input:",
        layout=widgets.Layout(width="700px"),
    )
    output_dir = widgets.Text(
        value=str(run_path / "normalized"),
        description="Output:",
        layout=widgets.Layout(width="700px"),
    )
    include = widgets.Text(
        value="",
        description="Include:",
        placeholder="comma-separated CIDRs",
        layout=widgets.Layout(width="700px"),
    )
    exclude = widgets.Text(
        value="",
        description="Exclude:",
        placeholder="comma-separated CIDRs",
        layout=widgets.Layout(width="700px"),
    )
    drop_outside = widgets.Checkbox(value=False, description="Drop outside scope")
    top_n = widgets.Dropdown(
        options=[5, 10, 20, 50],
        value=10,
        description="Preview N:",
    )

    btn_run = widgets.Button(description="Run Normalize", button_style="primary", icon="play")
    btn_preview = widgets.Button(description="Refresh Preview", button_style="info", icon="refresh")
    output = widgets.Output(layout={"border": "1px solid #cfcfcf", "padding": "8px"})

    def _run():
        in_dir = _as_path(input_dir.value)
        out_dir = _as_path(output_dir.value)
        pipeline.normalize(
            input_dir=str(in_dir),
            out_dir=str(out_dir),
            include_cidrs=_split_csv(include.value) or None,
            exclude_cidrs=_split_csv(exclude.value) or None,
            drop_outside=bool(drop_outside.value),
        )
        print("Normalize finished.")
        print("flows:", out_dir / "flows.jsonl")

    def _preview():
        import matplotlib.pyplot as plt

        flows_path = _as_path(output_dir.value) / "flows.jsonl"
        ensure_exists(flows_path, "Normalized flows")

        max_scan_rows = 200000
        rows = []
        proto_counter = Counter()
        count = 0
        truncated_scan = False
        with open(flows_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                count += 1
                proto_counter[str(rec.get("proto", "unknown"))] += 1
                if len(rows) < max(50, top_n.value):
                    rows.append(rec)
                if count >= max_scan_rows:
                    truncated_scan = True
                    break

        if truncated_scan:
            print(f"Scanned first {count:,} flows (preview limit).")
        else:
            print("Total flows:", count)
        display_table(
            rows,
            [
                ("ts", "ts"),
                ("src_ip", "src_ip"),
                ("src_port", "src_port"),
                ("dst_ip", "dst_ip"),
                ("dst_port", "dst_port"),
                ("proto", "proto"),
                ("bytes", "bytes"),
            ],
            "Sample Flows",
            limit=top_n.value,
        )
        proto_rows = [
            {"protocol": key, "flows": value}
            for key, value in proto_counter.most_common(top_n.value)
        ]
        display_table(
            proto_rows,
            [("protocol", "protocol"), ("flows", "flows")],
            "Top Protocols",
            limit=top_n.value,
        )
        if proto_rows:
            labels = [item["protocol"] for item in proto_rows]
            values = [item["flows"] for item in proto_rows]
            fig, ax = plt.subplots(figsize=(7, 4))
            ax.bar(labels, values, color="#1f77b4")
            ax.set_title(f"Most Frequent Protocols (showing {top_n.value})")
            ax.set_ylabel("Flows")
            ax.tick_params(axis="x", rotation=30)
            plt.show()

    def _exec(action):
        with output:
            clear_output(wait=True)
            try:
                action()
            except Exception as exc:
                print("Error:", exc)

    btn_run.on_click(lambda _: _exec(_run))
    btn_preview.on_click(lambda _: _exec(_preview))

    def _initial():
        with output:
            clear_output(wait=True)
            flows_path = _as_path(output_dir.value) / "flows.jsonl"
            if flows_path.exists():
                _preview()
            else:
                print("No normalized output yet.")
                print("Click 'Run Normalize' to create flows, then preview will appear here.")

    _initial()
    top_n.observe(
        lambda change: _exec(_preview) if _is_real_value_change(change) else None,
        names="value",
    )

    return widgets.VBox(
        [
            widgets.HTML("<h3>Normalize Controls</h3>"),
            widgets.HTML(
                "<i>Preview N affects only displayed tables/charts, not normalization output.</i>"
            ),
            input_dir,
            output_dir,
            include,
            exclude,
            widgets.HBox([drop_outside, top_n]),
            widgets.HBox([btn_run, btn_preview]),
            output,
        ]
    )


def create_inventory_controls(run_dir: str | Path):
    widgets, clear_output = _load_widgets()
    run_path = Path(run_dir)

    flows_path = widgets.Text(
        value=str(run_path / "normalized" / "flows.jsonl"),
        description="Flows:",
        layout=widgets.Layout(width="700px"),
    )
    output_dir = widgets.Text(
        value=str(run_path / "inventory"),
        description="Output:",
        layout=widgets.Layout(width="700px"),
    )
    top_n = widgets.Dropdown(options=[5, 10, 20, 50], value=10, description="Preview N:")

    btn_run = widgets.Button(description="Run Inventory", button_style="primary", icon="play")
    btn_preview = widgets.Button(description="Refresh Preview", button_style="info", icon="refresh")
    output = widgets.Output(layout={"border": "1px solid #cfcfcf", "padding": "8px"})

    def _run():
        pipeline.inventory(flows_path=str(_as_path(flows_path.value)), out_dir=str(_as_path(output_dir.value)))
        print("Inventory finished.")
        print("hosts:", _as_path(output_dir.value) / "hosts.jsonl")

    def _preview():
        import matplotlib.pyplot as plt

        hosts = _as_path(output_dir.value) / "hosts.jsonl"
        ensure_exists(hosts, "Inventory hosts")
        rows = read_jsonl(hosts)
        role_counter = Counter()

        for rec in rows:
            rec["bytes_total"] = int(rec.get("bytes_in", 0) or 0) + int(rec.get("bytes_out", 0) or 0)
            rec["flows_total"] = int(rec.get("flows_in", 0) or 0) + int(rec.get("flows_out", 0) or 0)
            rec["roles_joined"] = ",".join(rec.get("roles", [])) or "unknown"
            for role in rec.get("roles") or ["unknown"]:
                role_counter[str(role)] += 1

        print("Total hosts:", len(rows))
        rows_sorted = sorted(rows, key=lambda r: r["bytes_total"], reverse=True)
        display_table(
            rows_sorted,
            [("ip", "ip"), ("roles", "roles_joined"), ("bytes_total", "bytes_total"), ("flows_total", "flows_total")],
            "Top Hosts by Traffic",
            limit=top_n.value,
        )
        role_rows = [{"role": k, "hosts": v} for k, v in role_counter.most_common(top_n.value)]
        display_table(role_rows, [("role", "role"), ("hosts", "hosts")], "Role Distribution", limit=top_n.value)

        if rows_sorted:
            subset = rows_sorted[:top_n.value]
            labels = [item.get("ip", "") for item in subset]
            values = [item.get("bytes_total", 0) for item in subset]
            fig, ax = plt.subplots(figsize=(9, 4))
            ax.bar(labels, values, color="#2ca02c")
            ax.set_title(f"Top Hosts by Bytes (Top {top_n.value})")
            ax.set_ylabel("Bytes")
            ax.tick_params(axis="x", rotation=30)
            plt.show()

    def _exec(action):
        with output:
            clear_output(wait=True)
            try:
                action()
            except Exception as exc:
                print("Error:", exc)

    btn_run.on_click(lambda _: _exec(_run))
    btn_preview.on_click(lambda _: _exec(_preview))

    def _initial():
        with output:
            clear_output(wait=True)
            hosts = _as_path(output_dir.value) / "hosts.jsonl"
            if hosts.exists():
                _preview()
            else:
                print("No inventory output yet.")
                print("Click 'Run Inventory' to generate hosts and preview.")

    _initial()
    top_n.observe(
        lambda change: _exec(_preview) if _is_real_value_change(change) else None,
        names="value",
    )

    return widgets.VBox(
        [
            widgets.HTML("<h3>Inventory Controls</h3>"),
            widgets.HTML("<i>Preview N changes only displayed rows/charts, not generated inventory output.</i>"),
            flows_path,
            output_dir,
            top_n,
            widgets.HBox([btn_run, btn_preview]),
            output,
        ]
    )


def create_enrich_controls(run_dir: str | Path):
    widgets, clear_output = _load_widgets()
    run_path = Path(run_dir)

    flows_path = widgets.Text(
        value=str(run_path / "normalized" / "flows.jsonl"),
        description="Flows:",
        layout=widgets.Layout(width="700px"),
    )
    output_dir = widgets.Text(
        value=str(run_path / "enriched"),
        description="Output:",
        layout=widgets.Layout(width="700px"),
    )
    pcap_paths = widgets.Text(
        value="",
        description="PCAP:",
        placeholder="comma-separated paths (optional)",
        layout=widgets.Layout(width="700px"),
    )
    cpe_map = widgets.Text(
        value="",
        description="CPE map:",
        placeholder="optional path",
        layout=widgets.Layout(width="700px"),
    )
    p0f_bin = widgets.Text(value="p0f", description="p0f:", layout=widgets.Layout(width="350px"))
    top_n = widgets.Dropdown(options=[5, 10, 20, 50], value=10, description="Preview N:")

    btn_run = widgets.Button(description="Run Enrich", button_style="primary", icon="play")
    btn_preview = widgets.Button(description="Refresh Preview", button_style="info", icon="refresh")
    output = widgets.Output(layout={"border": "1px solid #cfcfcf", "padding": "8px"})

    def _run():
        pcap_inputs = _split_csv(pcap_paths.value)
        cpe_value = cpe_map.value.strip() or None
        pipeline.enrich(
            flows_path=str(_as_path(flows_path.value)),
            out_dir=str(_as_path(output_dir.value)),
            pcap_inputs=pcap_inputs,
            p0f_bin=p0f_bin.value.strip() or "p0f",
            cpe_map_path=cpe_value,
        )
        print("Enrich finished.")
        print("enriched:", _as_path(output_dir.value) / "enriched_hosts.jsonl")

    def _preview():
        enriched = _as_path(output_dir.value) / "enriched_hosts.jsonl"
        ensure_exists(enriched, "Enriched hosts")
        rows = read_jsonl(enriched)

        ja3 = Counter()
        sni = Counter()
        cpe = Counter()
        for rec in rows:
            rec["roles_joined"] = ",".join(rec.get("roles", [])) or "unknown"
            rec["fp_count"] = sum(
                len(rec.get(key) or [])
                for key in ["client_ja3", "server_ja3s", "hassh", "sni_used", "sni_served"]
            )
            for item in rec.get("client_ja3", []):
                if isinstance(item, dict) and item.get("value"):
                    ja3[str(item["value"])] += int(item.get("count", 1) or 1)
            for key in ("sni_used", "sni_served"):
                for item in rec.get(key, []):
                    if isinstance(item, dict) and item.get("value"):
                        sni[str(item["value"])] += int(item.get("count", 1) or 1)
            for item in rec.get("cpe", []):
                if isinstance(item, dict) and item.get("cpe"):
                    cpe[str(item["cpe"])] += int(item.get("count", 1) or 1)

        print("Total enriched hosts:", len(rows))
        hosts_sorted = sorted(rows, key=lambda r: r.get("fp_count", 0), reverse=True)
        display_table(
            hosts_sorted,
            [("ip", "ip"), ("roles", "roles_joined"), ("fingerprints", "fp_count")],
            "Hosts by Fingerprint Volume",
            limit=top_n.value,
        )
        display_table(
            [{"value": k, "count": v} for k, v in sni.most_common(top_n.value)],
            [("SNI", "value"), ("count", "count")],
            "Top SNI",
            limit=top_n.value,
        )
        display_table(
            [{"value": k, "count": v} for k, v in ja3.most_common(top_n.value)],
            [("JA3", "value"), ("count", "count")],
            "Top JA3",
            limit=top_n.value,
        )
        display_table(
            [{"value": k, "count": v} for k, v in cpe.most_common(top_n.value)],
            [("CPE", "value"), ("count", "count")],
            "Top CPE",
            limit=top_n.value,
        )

    def _exec(action):
        with output:
            clear_output(wait=True)
            try:
                action()
            except Exception as exc:
                print("Error:", exc)

    btn_run.on_click(lambda _: _exec(_run))
    btn_preview.on_click(lambda _: _exec(_preview))

    def _initial():
        with output:
            clear_output(wait=True)
            enriched = _as_path(output_dir.value) / "enriched_hosts.jsonl"
            if enriched.exists():
                _preview()
            else:
                print("No enrichment output yet.")
                print("Click 'Run Enrich' and then preview will be displayed here.")

    _initial()
    top_n.observe(
        lambda change: _exec(_preview) if _is_real_value_change(change) else None,
        names="value",
    )

    return widgets.VBox(
        [
            widgets.HTML("<h3>Enrichment Controls</h3>"),
            widgets.HTML("<i>Preview N changes only displayed rows, not enrichment output files.</i>"),
            flows_path,
            output_dir,
            pcap_paths,
            cpe_map,
            widgets.HBox([p0f_bin, top_n]),
            widgets.HBox([btn_run, btn_preview]),
            output,
        ]
    )


def create_graph_controls(run_dir: str | Path):
    widgets, clear_output = _load_widgets()
    run_path = Path(run_dir)

    flows_path = widgets.Text(
        value=str(run_path / "normalized" / "flows.jsonl"),
        description="Flows:",
        layout=widgets.Layout(width="700px"),
    )
    hosts_path = widgets.Text(
        value=str(run_path / "inventory" / "hosts.jsonl"),
        description="Hosts:",
        layout=widgets.Layout(width="700px"),
    )
    enriched_path = widgets.Text(
        value=str(run_path / "enriched" / "enriched_hosts.jsonl"),
        description="Enriched:",
        layout=widgets.Layout(width="700px"),
    )
    output_dir = widgets.Text(
        value=str(run_path / "graph"),
        description="Output:",
        layout=widgets.Layout(width="700px"),
    )
    min_flows = widgets.IntSlider(value=1, min=1, max=20, step=1, description="Min flows:")
    top_n = widgets.Dropdown(options=[5, 10, 20, 50], value=10, description="Preview N:")

    btn_run = widgets.Button(description="Run Graph Build", button_style="primary", icon="play")
    btn_preview = widgets.Button(description="Refresh Preview", button_style="info", icon="refresh")
    output = widgets.Output(layout={"border": "1px solid #cfcfcf", "padding": "8px"})

    def _run():
        host_path = _as_path(hosts_path.value)
        enr_path = _as_path(enriched_path.value)
        pipeline.analyze(
            flows_path=str(_as_path(flows_path.value)),
            out_dir=str(_as_path(output_dir.value)),
            hosts_path=str(host_path) if host_path.exists() else None,
            enriched_hosts_path=str(enr_path) if enr_path.exists() else None,
            min_flows=int(min_flows.value),
        )
        print("Graph build finished.")
        print("graph:", _as_path(output_dir.value) / "graph.json")

    def _preview():
        import matplotlib.pyplot as plt

        graph_path = _as_path(output_dir.value) / "graph.json"
        ensure_exists(graph_path, "Graph output")
        with open(graph_path, "r", encoding="utf-8") as fh:
            graph = json.load(fh)

        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        summary = [
            {
                "hosts": sum(1 for n in nodes if n.get("type") == "host"),
                "services": sum(1 for n in nodes if n.get("type") == "service"),
                "edges": len(edges),
            }
        ]
        display_table(summary, [("hosts", "hosts"), ("services", "services"), ("edges", "edges")], "Graph Summary", limit=1)

        top_edges = nlargest(top_n.value, edges, key=lambda e: (e.get("flows", 0), e.get("bytes", 0)))
        display_table(
            top_edges,
            [("src", "src"), ("dst", "dst"), ("flows", "flows"), ("bytes", "bytes")],
            "Top Edges",
            limit=top_n.value,
        )

        if top_edges:
            labels = [f"{e.get('src', '')} -> {e.get('dst', '')}" for e in top_edges]
            values = [int(e.get("flows", 0) or 0) for e in top_edges]
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.barh(labels[::-1], values[::-1], color="#9467bd")
            ax.set_title(f"Top Edges by Flows (Top {top_n.value})")
            ax.set_xlabel("Flows")
            plt.show()

    def _exec(action):
        with output:
            clear_output(wait=True)
            try:
                action()
            except Exception as exc:
                print("Error:", exc)

    btn_run.on_click(lambda _: _exec(_run))
    btn_preview.on_click(lambda _: _exec(_preview))

    def _initial():
        with output:
            clear_output(wait=True)
            graph = _as_path(output_dir.value) / "graph.json"
            if graph.exists():
                _preview()
            else:
                print("No graph output yet.")
                print("Click 'Run Graph Build' to generate graph and preview.")

    _initial()
    top_n.observe(
        lambda change: _exec(_preview) if _is_real_value_change(change) else None,
        names="value",
    )

    return widgets.VBox(
        [
            widgets.HTML("<h3>Graph Analysis Controls</h3>"),
            widgets.HTML("<i>Preview N changes only displayed graph preview, not saved graph artifacts.</i>"),
            flows_path,
            hosts_path,
            enriched_path,
            output_dir,
            widgets.HBox([min_flows, top_n]),
            widgets.HBox([btn_run, btn_preview]),
            output,
        ]
    )


def create_criticality_controls(run_dir: str | Path):
    widgets, clear_output = _load_widgets()
    run_path = Path(run_dir)

    graph_path = widgets.Text(
        value=str(run_path / "graph" / "graph.json"),
        description="Graph:",
        layout=widgets.Layout(width="700px"),
    )
    hosts_path = widgets.Text(
        value=str(run_path / "inventory" / "hosts.jsonl"),
        description="Hosts:",
        layout=widgets.Layout(width="700px"),
    )
    criticality_dir = widgets.Text(
        value=str(run_path / "criticality"),
        description="Crit out:",
        layout=widgets.Layout(width="700px"),
    )
    report_dir = widgets.Text(
        value=str(run_path / "report"),
        description="Report out:",
        layout=widgets.Layout(width="700px"),
    )
    title = widgets.Text(
        value="Passive Network Mapping Report",
        description="Title:",
        layout=widgets.Layout(width="700px"),
    )
    top_n = widgets.Dropdown(options=[5, 10, 20, 50], value=10, description="Top K:")
    pdf = widgets.Checkbox(value=True, description="Generate PDF")

    btn_run_crit = widgets.Button(description="Run Criticality", button_style="primary", icon="play")
    btn_preview = widgets.Button(description="Preview Top Critical", button_style="info", icon="refresh")
    btn_export = widgets.Button(description="Generate Charts + Export", button_style="success", icon="file-text")
    btn_run_all = widgets.Button(description="Run Criticality + Export", button_style="warning", icon="play")
    output = widgets.Output(layout={"border": "1px solid #cfcfcf", "padding": "8px"})

    def _crit_path() -> Path:
        return _as_path(criticality_dir.value) / "criticality.jsonl"

    def _run_criticality():
        host_path = _as_path(hosts_path.value)
        pipeline.criticality(
            graph_path=str(_as_path(graph_path.value)),
            out_dir=str(_as_path(criticality_dir.value)),
            hosts_path=str(host_path) if host_path.exists() else None,
            external_cmd=None,
            dump_input_path=None,
        )
        print("Criticality finished.")
        print("criticality:", _crit_path())

    def _preview():
        import matplotlib.pyplot as plt

        crit_path = _crit_path()
        ensure_exists(crit_path, "Criticality output")
        rows = read_jsonl(crit_path)
        def _score(row):
            try:
                return float(row.get("score", 0.0) or 0.0)
            except Exception:
                return 0.0
        top = sorted(
            rows,
            key=_score,
            reverse=True,
        )[: top_n.value]
        display_table(
            top,
            [("id", "id"), ("score", "score"), ("method", "method")],
            "Top Critical Nodes",
            limit=top_n.value,
        )
        if top:
            labels = [item.get("id", "") for item in top]
            values = [float(item.get("score", 0.0) or 0.0) for item in top]
            fig, ax = plt.subplots(figsize=(9, 5))
            ax.barh(labels[::-1], values[::-1], color="#d62728")
            ax.set_title(f"Top Critical Nodes (Top {top_n.value})")
            ax.set_xlabel("Score")
            plt.show()

    def _export():
        crit_path = _crit_path()
        ensure_exists(crit_path, "Criticality output")
        manifest = _as_path(report_dir.value) / "figures_manifest.json"
        pipeline.export(
            hosts_path=str(_as_path(hosts_path.value)),
            graph_path=str(_as_path(graph_path.value)),
            criticality_path=str(crit_path),
            out_dir=str(_as_path(report_dir.value)),
            title=title.value,
            pdf=bool(pdf.value),
            enriched_path=str(run_path / "enriched" / "enriched_hosts.jsonl")
            if (run_path / "enriched" / "enriched_hosts.jsonl").exists()
            else None,
            top_k=top_n.value,
            figures_manifest_path=str(manifest),
            regenerate_figures=True,
        )
        print("Export finished.")
        if manifest.exists():
            print("manifest:", manifest)
        print("report:", _as_path(report_dir.value) / "report.md")
        print("summary:", _as_path(report_dir.value) / "summary.json")
        if pdf.value:
            print("pdf:", _as_path(report_dir.value) / "report.pdf")

    def _exec(action):
        with output:
            clear_output(wait=True)
            try:
                action()
            except Exception as exc:
                print("Error:", exc)

    btn_run_crit.on_click(lambda _: _exec(_run_criticality))
    btn_preview.on_click(lambda _: _exec(_preview))
    btn_export.on_click(lambda _: _exec(_export))
    btn_run_all.on_click(lambda _: _exec(lambda: (_run_criticality(), _preview(), _export())))

    def _initial():
        with output:
            clear_output(wait=True)
            crit_path = _crit_path()
            if crit_path.exists():
                _preview()
                report_md = _as_path(report_dir.value) / "report.md"
                print()
                print("Report exists:", report_md.exists())
                if report_md.exists():
                    print("report:", report_md)
            else:
                print("No criticality output yet.")
                print("Click 'Run Criticality + Export' for a one-click full result.")

    _initial()
    top_n.observe(
        lambda change: _exec(_preview) if _is_real_value_change(change) else None,
        names="value",
    )

    return widgets.VBox(
        [
            widgets.HTML("<h3>Criticality + Export Controls</h3>"),
            widgets.HTML("<i>Top K affects both preview and exported report tables/figures.</i>"),
            graph_path,
            hosts_path,
            criticality_dir,
            report_dir,
            title,
            widgets.HBox([top_n, pdf]),
            widgets.HBox([btn_run_crit, btn_preview, btn_export, btn_run_all]),
            output,
        ]
    )
