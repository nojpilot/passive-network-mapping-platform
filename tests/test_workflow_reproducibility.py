import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pmmap.workflow import run as workflow_run


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class WorkflowReproducibilityTests(unittest.TestCase):
    def test_one_command_run_writes_manifest_and_semantic_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            manifest_path = Path(
                workflow_run(
                    out_dir=str(run_dir),
                    input_path=str(REPO_ROOT / "data" / "flows_demo.csv"),
                    include_cidrs=["10.0.0.0/8", "192.168.0.0/16"],
                    title="Workflow regression report",
                    top_k=5,
                )
            )

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["input_mode"], "preprocessed")
            self.assertEqual(len(manifest["inputs"]), 1)
            self.assertEqual(len(manifest["inputs"][0]["sha256"]), 64)
            self.assertEqual(
                [stage["name"] for stage in manifest["stages"]],
                [
                    "prepare_input",
                    "normalize",
                    "inventory",
                    "enrich",
                    "analyze",
                    "criticality",
                    "export",
                ],
            )
            self.assertEqual(manifest["outputs"]["normalized_flows"], 8)
            self.assertEqual(manifest["outputs"]["normalization_accepted_flows"], 8)
            self.assertEqual(
                manifest["parameters"]["include_cidrs"],
                ["10.0.0.0/8", "192.168.0.0/16"],
            )
            self.assertEqual(
                manifest["parameters"]["network_scope_defaults_used"],
                {
                    "include_cidrs": False,
                    "exclude_cidrs": True,
                    "drop_outside": True,
                },
            )
            service_registry = manifest["resources"]["service_registry"]
            service_registry_path = Path(service_registry["path"])
            self.assertTrue(service_registry["loaded"])
            self.assertTrue(service_registry_path.is_file())
            self.assertEqual(
                service_registry_path.name,
                "iana-service-names-port-numbers.csv",
            )
            self.assertEqual(
                service_registry["sha256"],
                hashlib.sha256(service_registry_path.read_bytes()).hexdigest(),
            )
            self.assertGreater(service_registry["entries"], 0)
            self.assertEqual(service_registry["license"], "CC0-1.0")

            enrichment_manifest = json.loads(
                (run_dir / "enriched" / "enrichment_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(enrichment_manifest["cpe_mapping"]["enabled"])
            self.assertEqual(
                enrichment_manifest["matches"]["hypotheses_emitted"],
                0,
            )

            graph = json.loads(
                (run_dir / "graph" / "graph.json").read_text(encoding="utf-8")
            )
            service_ids = {
                node["id"] for node in graph["nodes"] if node.get("type") == "service"
            }
            self.assertIn("10.0.1.50:22/tcp", service_ids)
            self.assertNotIn("10.0.2.77:60222/tcp", service_ids)

            criticality = _read_jsonl(
                run_dir / "criticality" / "criticality.jsonl"
            )
            score_by_host = {row["id"]: row["score"] for row in criticality}
            self.assertGreater(
                score_by_host["10.0.5.20"],
                score_by_host["10.0.1.12"],
            )

            self.assertTrue((run_dir / "report" / "summary.json").is_file())
            self.assertTrue((run_dir / "report" / "report.md").is_file())
            figure_manifest = json.loads(
                (run_dir / "report" / "figures_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            figure_names = {
                Path(item["path"]).name for item in figure_manifest["figures"]
            }
            self.assertIn("communication_map.png", figure_names)
            self.assertTrue(
                (run_dir / "report" / "assets" / "communication_map.png").is_file()
            )

    def test_workflow_requires_exactly_one_input_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "exactly one input mode"):
                workflow_run(
                    out_dir=str(Path(tmp) / "run"),
                    input_path=str(REPO_ROOT / "data" / "flows_demo.csv"),
                    flows_path=str(REPO_ROOT / "data" / "flows_demo.csv"),
                )

    def test_drop_outside_requires_an_effective_include_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(
                ValueError,
                "requires at least one effective include CIDR",
            ):
                workflow_run(
                    out_dir=str(Path(tmp) / "run"),
                    input_path=str(REPO_ROOT / "data" / "flows_demo.csv"),
                    include_cidrs=[],
                    exclude_cidrs=[],
                    drop_outside=True,
                )

    def test_normalized_input_applies_declared_network_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flows = root / "source_flows.jsonl"
            records = [
                {
                    "ts": 1,
                    "src_ip": "10.0.0.1",
                    "src_port": 50000,
                    "dst_ip": "203.0.113.10",
                    "dst_port": 443,
                    "proto": "tcp",
                    "bytes": 10,
                    "pkts": 1,
                    "sni": "kept.example",
                },
                {
                    "ts": 2,
                    "src_ip": "192.0.2.1",
                    "src_port": 50001,
                    "dst_ip": "203.0.113.11",
                    "dst_port": 443,
                    "proto": "tcp",
                    "bytes": 20,
                    "pkts": 2,
                    "sni": "dropped.example",
                },
            ]
            flows.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            run_dir = root / "run"

            manifest_path = Path(
                workflow_run(
                    out_dir=str(run_dir),
                    flows_path=str(flows),
                    include_cidrs=["10.0.0.0/8"],
                    drop_outside=True,
                )
            )

            output = _read_jsonl(run_dir / "normalized" / "flows.jsonl")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(len(output), 1)
            self.assertEqual(output[0]["sni"], "kept.example")
            self.assertTrue(output[0]["src_in_scope"])
            self.assertFalse(output[0]["dst_in_scope"])
            self.assertEqual(manifest["outputs"]["normalization_filtered_outside"], 1)

    def test_reusing_run_directory_does_not_mix_preprocessed_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.csv"
            second = root / "second.csv"
            header = "ts,sa,sp,da,dp,pr,pkt,byt\n"
            first.write_text(
                header + "1,10.0.0.1,50000,10.0.0.2,443,tcp,1,10\n",
                encoding="utf-8",
            )
            second.write_text(
                header + "2,10.0.0.3,50001,10.0.0.4,53,udp,1,20\n",
                encoding="utf-8",
            )
            run_dir = root / "run"

            workflow_run(out_dir=str(run_dir), input_path=str(first))
            workflow_run(out_dir=str(run_dir), input_path=str(second))

            output = _read_jsonl(run_dir / "normalized" / "flows.jsonl")
            self.assertEqual(len(output), 1)
            self.assertEqual(output[0]["src_ip"], "10.0.0.3")

    def test_failed_stage_is_recorded_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            invalid_input = root / "invalid.csv"
            invalid_input.write_text(
                "ts,sa,sp,da,dp,pr,pkt,byt\n"
                "1,invalid,50000,also-invalid,443,tcp,-1,-1\n",
                encoding="utf-8",
            )
            run_dir = root / "run"

            with self.assertRaisesRegex(ValueError, "No valid flow records"):
                workflow_run(
                    out_dir=str(run_dir),
                    input_path=str(invalid_input),
                )

            manifest = json.loads(
                (run_dir / "run_manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["stages"][-1]["name"], "normalize")
            self.assertEqual(manifest["stages"][-1]["status"], "failed")
            self.assertEqual(
                manifest["stages"][-1]["error"]["type"],
                "ValueError",
            )


if __name__ == "__main__":
    unittest.main()
