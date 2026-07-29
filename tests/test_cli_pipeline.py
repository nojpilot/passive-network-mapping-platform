import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pmmap.export import run as export_run


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_BIN = sys.executable


def run_cli(*args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PYTHON_BIN, "main.py", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class CLIPipelineTests(unittest.TestCase):
    def test_config_yaml_matches_netfilter_shape(self) -> None:
        import yaml

        cfg = yaml.safe_load((REPO_ROOT / "config.yaml").read_text())
        self.assertIsInstance(cfg.get("network"), dict)
        self.assertEqual(cfg["network"].get("include_cidrs"), ["10.0.0.0/8", "192.168.0.0/16"])
        self.assertEqual(cfg["network"].get("exclude_cidrs"), [])
        self.assertIsInstance(cfg.get("filters"), dict)
        self.assertFalse(cfg["filters"].get("drop_outside_ranges"))

    def test_normalize_fails_on_missing_input_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            proc = run_cli(
                "normalize",
                "--input",
                str(Path(tmp) / "missing"),
                "--output",
                str(out_dir),
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("does not exist", (proc.stderr + proc.stdout).lower())

    def test_export_fails_on_missing_required_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "report"
            proc = run_cli(
                "export",
                "--hosts",
                str(Path(tmp) / "missing_hosts.jsonl"),
                "--graph",
                str(Path(tmp) / "missing_graph.json"),
                "--output",
                str(out_dir),
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("does not exist", (proc.stderr + proc.stdout).lower())

    def test_enrich_emits_rows_for_hosts_without_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            flows_path = tmp_path / "flows.jsonl"
            out_dir = tmp_path / "enriched"
            flows = [
                {
                    "ts": 1.0,
                    "src_ip": "10.0.0.1",
                    "src_port": 40000,
                    "dst_ip": "10.0.0.2",
                    "dst_port": 443,
                    "proto": "tcp",
                    "bytes": 100,
                    "pkts": 2,
                },
                {
                    "ts": 2.0,
                    "src_ip": "10.0.0.1",
                    "src_port": 40001,
                    "dst_ip": "10.0.0.3",
                    "dst_port": 53,
                    "proto": "udp",
                    "bytes": 80,
                    "pkts": 1,
                },
            ]
            flows_path.write_text("\n".join(json.dumps(row) for row in flows) + "\n")

            proc = run_cli("enrich", "--flows", str(flows_path), "--output", str(out_dir))
            self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)

            records = read_jsonl(out_dir / "enriched_hosts.jsonl")
            self.assertEqual([row["ip"] for row in records], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
            for row in records:
                self.assertEqual(row["client_ja3"], [])
                self.assertEqual(row["server_ja3s"], [])
                self.assertEqual(row["sni_served"], [])

    def test_export_summary_aggregates_top_edges_by_destination_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            hosts_path = tmp_path / "hosts.jsonl"
            graph_path = tmp_path / "graph.json"
            report_dir = tmp_path / "report"

            hosts = [
                {"ip": "10.0.0.1", "bytes_in": 0, "bytes_out": 10, "flows_in": 0, "flows_out": 1},
                {"ip": "10.0.0.2", "bytes_in": 0, "bytes_out": 20, "flows_in": 0, "flows_out": 1},
                {"ip": "10.0.0.3", "bytes_in": 0, "bytes_out": 100, "flows_in": 0, "flows_out": 1},
                {"ip": "198.51.100.1", "bytes_in": 30, "bytes_out": 0, "flows_in": 2, "flows_out": 0},
                {"ip": "198.51.100.2", "bytes_in": 100, "bytes_out": 0, "flows_in": 1, "flows_out": 0},
            ]
            hosts_path.write_text("\n".join(json.dumps(row) for row in hosts) + "\n")

            graph = {
                "nodes": [
                    {"id": "10.0.0.1", "type": "host"},
                    {"id": "10.0.0.2", "type": "host"},
                    {"id": "10.0.0.3", "type": "host"},
                    {"id": "198.51.100.1", "type": "host"},
                    {"id": "198.51.100.2", "type": "host"},
                    {
                        "id": "198.51.100.1:443/tcp",
                        "type": "service",
                        "ip": "198.51.100.1",
                        "port": 443,
                        "proto": "tcp",
                    },
                    {
                        "id": "198.51.100.2:443/tcp",
                        "type": "service",
                        "ip": "198.51.100.2",
                        "port": 443,
                        "proto": "tcp",
                    },
                ],
                "edges": [
                    {"src": "10.0.0.1", "dst": "198.51.100.1:443/tcp", "flows": 1, "bytes": 10},
                    {"src": "10.0.0.2", "dst": "198.51.100.1:443/tcp", "flows": 1, "bytes": 20},
                    {"src": "10.0.0.3", "dst": "198.51.100.2:443/tcp", "flows": 1, "bytes": 100},
                ],
            }
            graph_path.write_text(json.dumps(graph))

            export_run(
                hosts_path=str(hosts_path),
                graph_path=str(graph_path),
                criticality_path=None,
                out_dir=str(report_dir),
                top_k=2,
                regenerate_figures=False,
            )

            summary = json.loads((report_dir / "summary.json").read_text())
            self.assertEqual(summary["top_edges"][0]["dst"], "198.51.100.1:443/tcp")
            self.assertEqual(summary["top_edges"][0]["flows"], 2)
            self.assertEqual(summary["top_edges"][0]["bytes"], 30)
            self.assertEqual(summary["top_edges"][0]["source_count"], 2)
            self.assertEqual(summary["top_edges"][0]["aggregation"], "destination_service")
            self.assertIn("Top Service Destinations", (report_dir / "report.md").read_text())

    def test_demo_pipeline_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            in_dir = tmp_path / "input"
            run_dir = tmp_path / "run"
            in_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / "data" / "flows_demo.csv", in_dir / "flows_demo.csv")

            normalized_dir = run_dir / "normalized"
            inventory_dir = run_dir / "inventory"
            enriched_dir = run_dir / "enriched"
            graph_dir = run_dir / "graph"
            criticality_dir = run_dir / "criticality"
            report_dir = run_dir / "report"

            commands = [
                (
                    "normalize",
                    "--input",
                    str(in_dir),
                    "--output",
                    str(normalized_dir),
                ),
                (
                    "inventory",
                    "--flows",
                    str(normalized_dir / "flows.jsonl"),
                    "--output",
                    str(inventory_dir),
                ),
                (
                    "enrich",
                    "--flows",
                    str(normalized_dir / "flows.jsonl"),
                    "--output",
                    str(enriched_dir),
                    "--cpe-map",
                    str(REPO_ROOT / "data" / "cpe_map.sample.yaml"),
                ),
                (
                    "analyze",
                    "--flows",
                    str(normalized_dir / "flows.jsonl"),
                    "--output",
                    str(graph_dir),
                    "--hosts",
                    str(inventory_dir / "hosts.jsonl"),
                    "--enriched-hosts",
                    str(enriched_dir / "enriched_hosts.jsonl"),
                ),
                (
                    "criticality",
                    "--graph",
                    str(graph_dir / "graph.json"),
                    "--output",
                    str(criticality_dir),
                    "--hosts",
                    str(enriched_dir / "enriched_hosts.jsonl"),
                ),
                (
                    "export",
                    "--hosts",
                    str(inventory_dir / "hosts.jsonl"),
                    "--graph",
                    str(graph_dir / "graph.json"),
                    "--criticality",
                    str(criticality_dir / "criticality.jsonl"),
                    "--enriched",
                    str(enriched_dir / "enriched_hosts.jsonl"),
                    "--output",
                    str(report_dir),
                    "--top-k",
                    "5",
                ),
            ]

            for cmd in commands:
                proc = run_cli(*cmd)
                self.assertEqual(
                    proc.returncode,
                    0,
                    msg=f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
                )

            self.assertTrue((normalized_dir / "flows.jsonl").is_file())
            self.assertTrue((inventory_dir / "hosts.jsonl").is_file())
            self.assertTrue((enriched_dir / "enriched_hosts.jsonl").is_file())
            self.assertTrue((graph_dir / "graph.json").is_file())
            self.assertTrue((criticality_dir / "criticality.jsonl").is_file())
            self.assertTrue((report_dir / "summary.json").is_file())
            self.assertTrue((report_dir / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
