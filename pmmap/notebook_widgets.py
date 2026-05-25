"""Interactive notebook controls for chart generation and report export."""

from __future__ import annotations

from pathlib import Path

from . import pipeline
from .report_figures import generate_figures


def create_report_dashboard(
    run_dir: str | Path,
    default_top_k: int = 10,
    default_title: str = "Passive Network Mapping Report",
):
    """Return an ipywidgets dashboard for generating report charts and PDF."""
    try:
        import ipywidgets as widgets
        from IPython.display import clear_output
    except ImportError as exc:
        raise RuntimeError(
            "Missing ipywidgets. Install dependencies from requirements.txt."
        ) from exc

    run_path = Path(run_dir)
    report_dir = run_path / "report"
    graph_path = run_path / "graph" / "graph.json"
    hosts_path = run_path / "inventory" / "hosts.jsonl"
    crit_path = run_path / "criticality" / "criticality.jsonl"
    enriched_path = run_path / "enriched" / "enriched_hosts.jsonl"
    manifest_path = report_dir / "figures_manifest.json"

    title = widgets.Text(
        value=default_title,
        description="Title:",
        layout=widgets.Layout(width="520px"),
    )
    top_k = widgets.IntSlider(
        value=max(1, int(default_top_k)),
        min=3,
        max=30,
        step=1,
        description="Top K:",
        continuous_update=False,
        layout=widgets.Layout(width="520px"),
    )
    make_pdf = widgets.Checkbox(value=True, description="Generate PDF")

    btn_graphs = widgets.Button(
        description="Generate Charts",
        button_style="info",
        tooltip="Create PNG charts and figures manifest",
        icon="bar-chart",
    )
    btn_export = widgets.Button(
        description="Export Report",
        button_style="success",
        tooltip="Generate report.md/summary.json/(optional)report.pdf",
        icon="file-text",
    )
    btn_all = widgets.Button(
        description="Generate + Export",
        button_style="warning",
        tooltip="Generate charts and export report in one click",
        icon="play",
    )
    output = widgets.Output(layout={"border": "1px solid #cfcfcf", "padding": "8px"})

    def _check_inputs() -> bool:
        missing = []
        if not graph_path.exists():
            missing.append(str(graph_path))
        if not hosts_path.exists():
            missing.append(str(hosts_path))
        if missing:
            print("Missing required inputs:")
            for item in missing:
                print("-", item)
            return False
        return True

    def _generate_charts() -> None:
        if not _check_inputs():
            return
        manifest = generate_figures(
            report_dir=str(report_dir),
            graph_path=str(graph_path),
            criticality_path=str(crit_path) if crit_path.exists() else None,
            hosts_path=str(hosts_path),
            top_k=top_k.value,
            manifest_path=str(manifest_path),
        )
        print("Charts generated.")
        print("Manifest:", manifest)

    def _export_report(regenerate_figures: bool = True) -> None:
        if not _check_inputs():
            return
        pipeline.export(
            hosts_path=str(hosts_path),
            graph_path=str(graph_path),
            criticality_path=str(crit_path) if crit_path.exists() else None,
            out_dir=str(report_dir),
            title=title.value,
            pdf=bool(make_pdf.value),
            enriched_path=str(enriched_path) if enriched_path.exists() else None,
            top_k=top_k.value,
            figures_manifest_path=str(manifest_path),
            regenerate_figures=bool(regenerate_figures),
        )
        print("Report export finished.")
        print("Report:", report_dir / "report.md")
        print("Summary:", report_dir / "summary.json")
        if manifest_path.exists():
            print("Manifest:", manifest_path)
        if make_pdf.value:
            print("PDF:", report_dir / "report.pdf")

    def _generate_then_export() -> None:
        _generate_charts()
        _export_report(regenerate_figures=False)

    def _wrap(action):
        with output:
            clear_output(wait=True)
            try:
                action()
            except Exception as exc:
                print(f"Error: {exc}")

    btn_graphs.on_click(lambda _: _wrap(_generate_charts))
    btn_export.on_click(lambda _: _wrap(lambda: _export_report(regenerate_figures=False)))
    btn_all.on_click(lambda _: _wrap(_generate_then_export))

    return widgets.VBox(
        [
            widgets.HTML("<h3>Report Dashboard</h3>"),
            widgets.HTML(
                f"<code>run_dir={run_path}</code><br/>"
                "Usage: <b>Export Report</b> uses existing figures; <b>Generate + Export</b> refreshes charts first."
            ),
            title,
            top_k,
            make_pdf,
            widgets.HBox([btn_graphs, btn_export, btn_all]),
            output,
        ]
    )
