import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmmap.export import _fingerprint_summary, run as export_run
from pmmap.notebook_common import report_pdf_message
from pmmap.report_figures import (
    _excluded_host_ids,
    _observed_bytes,
    _portable_relative_path,
)


class ExportEvidenceSummaryTests(unittest.TestCase):
    @staticmethod
    def _write_inputs(
        root: Path,
        hosts: list[dict],
        graph: dict,
        criticality: list[dict] | None = None,
    ) -> tuple[Path, Path, Path | None, Path]:
        hosts_path = root / "hosts.jsonl"
        graph_path = root / "graph.json"
        report_dir = root / "report"
        hosts_path.write_text(
            "".join(json.dumps(row) + "\n" for row in hosts),
            encoding="utf-8",
        )
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        criticality_path = None
        if criticality is not None:
            criticality_path = root / "criticality.jsonl"
            criticality_path.write_text(
                "".join(json.dumps(row) + "\n" for row in criticality),
                encoding="utf-8",
            )
        return hosts_path, graph_path, criticality_path, report_dir

    def test_sni_directions_are_separate_and_cpe_counts_hosts(self) -> None:
        cpe = "cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*"
        enriched = [
            {
                "ip": "10.0.0.1",
                "sni_used": [{"value": "example.test", "count": 2}],
                "sni_served": [],
                "cpe": [{"cpe": cpe}, {"cpe": cpe}],
            },
            {
                "ip": "10.0.0.2",
                "sni_used": [],
                "sni_served": [{"value": "example.test", "count": 2}],
                "cpe": [{"cpe": cpe}],
            },
        ]

        summary = _fingerprint_summary(enriched, k=10)

        self.assertEqual(summary["sni_requested"], [("example.test", 2)])
        self.assertEqual(summary["sni_served"], [("example.test", 2)])
        self.assertEqual(summary["cpe_host_hypotheses"], [(cpe, 2)])
        self.assertNotIn("sni", summary)
        self.assertNotIn("cpe", summary)

    def test_export_removes_stale_pdf_when_current_run_does_not_create_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_path = root / "hosts.jsonl"
            graph_path = root / "graph.json"
            report_dir = root / "report"
            report_dir.mkdir()
            hosts_path.write_text(
                json.dumps({"ip": "10.0.0.1"}) + "\n",
                encoding="utf-8",
            )
            graph_path.write_text(
                json.dumps(
                    {
                        "nodes": [{"id": "10.0.0.1", "type": "host"}],
                        "edges": [],
                    }
                ),
                encoding="utf-8",
            )
            stale_pdf = report_dir / "report.pdf"
            stale_pdf.write_bytes(b"stale")

            export_run(
                hosts_path=str(hosts_path),
                graph_path=str(graph_path),
                criticality_path=None,
                out_dir=str(report_dir),
                pdf=False,
                regenerate_figures=False,
            )

            self.assertFalse(stale_pdf.exists())

    def test_failed_pdf_conversion_is_removed_and_not_advertised(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_path, graph_path, _, report_dir = self._write_inputs(
                root,
                hosts=[{"ip": "10.0.0.1", "in_scope": True}],
                graph={
                    "nodes": [
                        {
                            "id": "10.0.0.1",
                            "type": "host",
                            "in_scope": True,
                        }
                    ],
                    "edges": [],
                },
            )

            def failed_pandoc(*args, **kwargs):
                report_dir.mkdir(parents=True, exist_ok=True)
                (report_dir / "report.pdf").write_bytes(b"partial")
                raise subprocess.CalledProcessError(
                    returncode=1,
                    cmd=args[0],
                    stderr="conversion failed",
                )

            with patch("pmmap.export.subprocess.run", side_effect=failed_pandoc):
                export_run(
                    hosts_path=str(hosts_path),
                    graph_path=str(graph_path),
                    criticality_path=None,
                    out_dir=str(report_dir),
                    pdf=True,
                    regenerate_figures=False,
                )

            report = (report_dir / "report.md").read_text(encoding="utf-8")
            summary = json.loads(
                (report_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("PDF Report", report)
            self.assertNotIn("`report.pdf`", report)
            self.assertFalse((report_dir / "report.pdf").exists())
            self.assertIsNone(summary["artifacts"]["report_pdf"])

    def test_automatic_generation_does_not_reuse_stale_default_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_path, graph_path, _, report_dir = self._write_inputs(
                root,
                hosts=[{"ip": "10.0.0.1"}],
                graph={
                    "nodes": [{"id": "10.0.0.1", "type": "host"}],
                    "edges": [],
                },
            )
            report_dir.mkdir()
            manifest = report_dir / "figures_manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "figures": [
                            {
                                "path": "assets/stale.png",
                                "caption": "stale figure",
                                "section": "Stale",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with patch(
                "pmmap.report_figures.generate_figures",
                side_effect=RuntimeError("plotting failed"),
            ):
                export_run(
                    hosts_path=str(hosts_path),
                    graph_path=str(graph_path),
                    criticality_path=None,
                    out_dir=str(report_dir),
                    regenerate_figures=True,
                )

            summary = json.loads(
                (report_dir / "summary.json").read_text(encoding="utf-8")
            )
            report = (report_dir / "report.md").read_text(encoding="utf-8")
            self.assertFalse(manifest.exists())
            self.assertEqual(summary["figures"], [])
            self.assertIsNone(summary["figures_manifest"])
            self.assertNotIn("stale figure", report)

    def test_explicit_custom_manifest_is_read_only_and_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_path, graph_path, _, report_dir = self._write_inputs(
                root,
                hosts=[{"ip": "10.0.0.1"}],
                graph={
                    "nodes": [{"id": "10.0.0.1", "type": "host"}],
                    "edges": [],
                },
            )
            custom_manifest = root / "custom_figures.json"
            original = json.dumps(
                {
                    "figures": [
                        {
                            "path": "custom.png",
                            "caption": "user supplied",
                            "section": "Custom",
                        }
                    ]
                },
                indent=2,
            ).encode("utf-8")
            custom_manifest.write_bytes(original)

            with patch("pmmap.report_figures.generate_figures") as generate:
                export_run(
                    hosts_path=str(hosts_path),
                    graph_path=str(graph_path),
                    criticality_path=None,
                    out_dir=str(report_dir),
                    figures_manifest_path=str(custom_manifest),
                    regenerate_figures=True,
                )

            summary = json.loads(
                (report_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(custom_manifest.read_bytes(), original)
            generate.assert_not_called()
            self.assertEqual(summary["figures"][0]["caption"], "user supplied")
            self.assertEqual(
                summary["figures_manifest"],
                "../custom_figures.json",
            )

    def test_windows_figure_paths_are_serialized_for_portable_reports(self) -> None:
        with patch(
            "pmmap.report_figures.os.path.relpath",
            return_value=r"assets\generated.png",
        ):
            self.assertEqual(
                _portable_relative_path("unused", "unused"),
                "assets/generated.png",
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_path, graph_path, _, report_dir = self._write_inputs(
                root,
                hosts=[{"ip": "10.0.0.1"}],
                graph={
                    "nodes": [{"id": "10.0.0.1", "type": "host"}],
                    "edges": [],
                },
            )
            manifest = root / "windows_figures.json"
            manifest.write_text(
                json.dumps(
                    {
                        "figures": [
                            {
                                "path": r"assets\generated.png",
                                "caption": "portable figure",
                                "section": "Portable",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            export_run(
                hosts_path=str(hosts_path),
                graph_path=str(graph_path),
                criticality_path=None,
                out_dir=str(report_dir),
                figures_manifest_path=str(manifest),
                regenerate_figures=False,
            )

            summary = json.loads(
                (report_dir / "summary.json").read_text(encoding="utf-8")
            )
            report = (report_dir / "report.md").read_text(encoding="utf-8")
            self.assertEqual(
                summary["figures"][0]["path"],
                "assets/generated.png",
            )
            self.assertIn("(assets/generated.png)", report)
            self.assertNotIn(r"assets\generated.png", report)
            self.assertEqual(
                summary["figures_manifest"],
                "../windows_figures.json",
            )

    def test_notebook_pdf_message_requires_a_nonempty_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pdf_path = Path(tmp) / "report.pdf"

            missing = report_pdf_message(pdf_path, requested=True)
            self.assertIn("PDF was not generated", missing)
            self.assertIn("Markdown report is available", missing)

            pdf_path.write_bytes(b"")
            empty = report_pdf_message(pdf_path, requested=True)
            self.assertIn("PDF was not generated", empty)

            pdf_path.write_bytes(b"%PDF-valid-fixture")
            self.assertEqual(
                report_pdf_message(pdf_path, requested=True),
                f"PDF: {pdf_path}",
            )

            pdf_path.unlink()
            self.assertEqual(
                report_pdf_message(pdf_path, requested=False),
                "PDF was not requested; a Markdown-only report was generated.",
            )

    def test_scope_filtering_and_bytes_observed_drive_report_rankings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts = [
                {
                    "ip": "10.0.0.1",
                    "in_scope": True,
                    "roles": ["client"],
                    "bytes_in": 900,
                    "bytes_out": 900,
                    "bytes_observed": 40,
                    "flows_out": 1,
                },
                {
                    "ip": "10.0.0.2",
                    "in_scope": True,
                    "roles": ["web_server"],
                    "bytes_in": 1,
                    "bytes_out": 1,
                    "bytes_observed": 80,
                    "flows_in": 2,
                },
                {
                    "ip": "203.0.113.9",
                    "in_scope": False,
                    "roles": ["external_role"],
                    "bytes_observed": 9999,
                    "flows_out": 99,
                },
            ]
            graph = {
                "nodes": [
                    {
                        "id": "10.0.0.1",
                        "type": "host",
                        "in_scope": True,
                    },
                    {
                        "id": "10.0.0.2",
                        "type": "host",
                        "in_scope": True,
                    },
                    {
                        "id": "203.0.113.9",
                        "type": "host",
                        "in_scope": False,
                    },
                    {
                        "id": "10.0.0.2:443/tcp",
                        "type": "service",
                        "ip": "10.0.0.2",
                        "port": 443,
                        "proto": "tcp",
                    },
                ],
                "edges": [
                    {
                        "src": "10.0.0.1",
                        "dst": "10.0.0.2:443/tcp",
                        "flows": 1,
                        "bytes": 40,
                    },
                    {
                        "src": "203.0.113.9",
                        "dst": "10.0.0.2:443/tcp",
                        "flows": 1,
                        "bytes": 9999,
                    },
                ],
            }
            criticality = [
                {"id": "10.0.0.1", "score": 1.0, "in_scope": True},
                {"id": "10.0.0.2", "score": 2.0, "in_scope": True},
                {"id": "203.0.113.9", "score": 999.0, "in_scope": False},
            ]
            hosts_path, graph_path, criticality_path, report_dir = self._write_inputs(
                root,
                hosts=hosts,
                graph=graph,
                criticality=criticality,
            )

            export_run(
                hosts_path=str(hosts_path),
                graph_path=str(graph_path),
                criticality_path=str(criticality_path),
                out_dir=str(report_dir),
                regenerate_figures=False,
            )

            summary = json.loads(
                (report_dir / "summary.json").read_text(encoding="utf-8")
            )
            metrics = [
                json.loads(line)
                for line in (report_dir / "host_metrics.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            report = (report_dir / "report.md").read_text(encoding="utf-8")

            self.assertEqual(summary["stats"]["hosts"], 3)
            self.assertEqual(summary["stats"]["hosts_internal"], 2)
            self.assertEqual(summary["stats"]["hosts_in_scope"], 2)
            self.assertEqual(summary["stats"]["hosts_external"], 1)
            self.assertEqual(summary["stats"]["hosts_scope_unknown"], 0)
            self.assertEqual(
                [row["id"] for row in summary["top_critical"]],
                ["10.0.0.2", "10.0.0.1"],
            )
            for group in summary["top_hosts"].values():
                self.assertNotIn("203.0.113.9", [row["id"] for row in group])
            self.assertEqual(summary["top_hosts"]["by_bytes"][0]["id"], "10.0.0.2")
            self.assertEqual(
                {row["id"]: row["bytes_total"] for row in metrics},
                {"10.0.0.1": 40, "10.0.0.2": 80},
            )
            self.assertIn("| Hosts (in scope) | 2 |", report)
            self.assertIn("| Hosts (external) | 1 |", report)
            self.assertIn("`bytes_observed`", report)

            excluded = _excluded_host_ids(graph, hosts, criticality)
            self.assertEqual(excluded, {"203.0.113.9"})
            self.assertEqual(_observed_bytes(hosts[0]), 40)


if __name__ == "__main__":
    unittest.main()
