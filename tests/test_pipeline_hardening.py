import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmmap.analyze import run as analyze_run
from pmmap.criticality import _run_external
from pmmap.criticality import run as criticality_run
from pmmap.endpoints import infer_endpoints
from pmmap.inventory import SERVICE_MAP
from pmmap.inventory import run as inventory_run
from pmmap.normalize import _map_zeek_conn_row
from pmmap.normalize import run_normalized
from pmmap.schema import Flow


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


class ZeekEvidenceHardeningTests(unittest.TestCase):
    def test_directional_zeek_counters_reach_inventory_without_double_counting(self) -> None:
        mapped = _map_zeek_conn_row(
            {
                "ts": "1.25",
                "uid": "zeek-direction",
                "id.orig_h": "10.0.0.1",
                "id.orig_p": "55000",
                "id.resp_h": "10.0.0.2",
                "id.resp_p": "443",
                "proto": "tcp",
                "orig_bytes": "1000",
                "resp_bytes": "200",
                "orig_pkts": "10",
                "resp_pkts": "4",
                "conn_state": "SF",
            }
        )

        self.assertEqual(mapped["bytes"], 1200)
        self.assertEqual(mapped["bytes_src_to_dst"], 1000)
        self.assertEqual(mapped["bytes_dst_to_src"], 200)
        self.assertEqual(mapped["pkts"], 14)
        self.assertEqual(mapped["pkts_src_to_dst"], 10)
        self.assertEqual(mapped["pkts_dst_to_src"], 4)
        self.assertEqual(mapped["traffic_directionality"], "bidirectional_split")
        self.assertTrue(mapped["service_response_observed"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flows_path = root / "flows.jsonl"
            _write_jsonl(flows_path, [Flow(**mapped).model_dump()])
            inventory_dir = root / "inventory"

            inventory_run(str(flows_path), str(inventory_dir))

            hosts = {
                row["ip"]: row
                for row in _read_jsonl(inventory_dir / "hosts.jsonl")
            }
            client = hosts["10.0.0.1"]
            server = hosts["10.0.0.2"]
            self.assertEqual(
                (client["bytes_out"], client["bytes_in"], client["bytes_observed"]),
                (1000, 200, 1200),
            )
            self.assertEqual(
                (server["bytes_out"], server["bytes_in"], server["bytes_observed"]),
                (200, 1000, 1200),
            )

    def test_unanswered_zeek_connection_is_not_reported_as_an_offered_service(self) -> None:
        mapped = _map_zeek_conn_row(
            {
                "ts": "2.0",
                "uid": "zeek-s0",
                "id.orig_h": "10.0.0.1",
                "id.orig_p": "55001",
                "id.resp_h": "10.0.0.2",
                "id.resp_p": "443",
                "proto": "tcp",
                "orig_bytes": "0",
                "resp_bytes": "0",
                "orig_pkts": "1",
                "resp_pkts": "0",
                "conn_state": "S0",
            }
        )
        endpoints = infer_endpoints(mapped, SERVICE_MAP)
        self.assertTrue(endpoints.service_identified)
        self.assertFalse(endpoints.service_observed)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flows_path = root / "flows.jsonl"
            _write_jsonl(flows_path, [Flow(**mapped).model_dump()])
            inventory_dir = root / "inventory"
            graph_dir = root / "graph"

            inventory_run(str(flows_path), str(inventory_dir))
            analyze_run(str(flows_path), str(graph_dir))

            hosts = {
                row["ip"]: row
                for row in _read_jsonl(inventory_dir / "hosts.jsonl")
            }
            self.assertEqual(hosts["10.0.0.2"]["services_offered"], [])
            graph = json.loads(
                (graph_dir / "graph.json").read_text(encoding="utf-8")
            )
            self.assertEqual(graph["edges"], [])
            self.assertFalse(
                any(node.get("type") == "service" for node in graph["nodes"])
            )
            stats = json.loads(
                (graph_dir / "analysis_stats.json").read_text(encoding="utf-8")
            )
            self.assertEqual(stats["unconfirmed_service_attempts"], 1)

    def test_dns_query_name_stays_edge_evidence_not_service_hostname(self) -> None:
        flow = Flow(
            ts=3.0,
            src_ip="10.0.0.1",
            src_port=55002,
            dst_ip="10.0.0.53",
            dst_port=53,
            proto="udp",
            bytes=80,
            pkts=2,
            src_is_initiator=True,
            orientation_source="zeek_orig_resp",
            service_response_observed=True,
            dns_qname="queried.example",
        ).model_dump()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flows_path = root / "flows.jsonl"
            graph_dir = root / "graph"
            _write_jsonl(flows_path, [flow])

            analyze_run(str(flows_path), str(graph_dir))

            graph = json.loads(
                (graph_dir / "graph.json").read_text(encoding="utf-8")
            )
            service = next(
                node for node in graph["nodes"] if node.get("type") == "service"
            )
            self.assertEqual(service["id"], "10.0.0.53:53/udp")
            self.assertEqual(service["hostnames"], [])
            self.assertEqual(graph["edges"][0]["dns_qnames"], ["queried.example"])


class ScopeAndCriticalityHardeningTests(unittest.TestCase):
    def test_scope_propagates_and_outside_hosts_do_not_affect_internal_scores(self) -> None:
        records = [
            {
                "ts": 1,
                "src_ip": "10.0.0.1",
                "src_port": 55000,
                "dst_ip": "10.0.0.2",
                "dst_port": 443,
                "proto": "tcp",
                "bytes": 10,
                "pkts": 1,
                "src_is_initiator": True,
                "orientation_source": "fixture",
                "service_response_observed": True,
            },
            {
                "ts": 2,
                "src_ip": "10.0.0.1",
                "src_port": 55001,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
                "proto": "tcp",
                "bytes": 9999,
                "pkts": 2,
                "src_is_initiator": True,
                "orientation_source": "fixture",
                "service_response_observed": True,
            },
            {
                "ts": 3,
                "src_ip": "192.0.2.1",
                "src_port": 55002,
                "dst_ip": "203.0.113.11",
                "dst_port": 443,
                "proto": "tcp",
                "bytes": 1000000,
                "pkts": 3,
                "src_is_initiator": True,
                "orientation_source": "fixture",
                "service_response_observed": True,
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.jsonl"
            normalized_dir = root / "normalized"
            inventory_dir = root / "inventory"
            graph_dir = root / "graph"
            criticality_dir = root / "criticality"
            _write_jsonl(source, records)

            run_normalized(
                str(source),
                str(normalized_dir),
                net_cfg={
                    "include_cidrs": ["10.0.0.0/8"],
                    "exclude_cidrs": [],
                    "drop_outside": True,
                },
            )
            flows_path = normalized_dir / "flows.jsonl"
            inventory_run(str(flows_path), str(inventory_dir))
            analyze_run(
                str(flows_path),
                str(graph_dir),
                hosts_path=str(inventory_dir / "hosts.jsonl"),
            )
            criticality_run(
                graph_path=str(graph_dir / "graph.json"),
                out_dir=str(criticality_dir),
                hosts_path=str(inventory_dir / "hosts.jsonl"),
            )

            normalized = _read_jsonl(flows_path)
            self.assertEqual(len(normalized), 2)
            self.assertEqual(
                [
                    (flow["src_in_scope"], flow["dst_in_scope"])
                    for flow in normalized
                ],
                [(True, True), (True, False)],
            )
            hosts = {
                row["ip"]: row
                for row in _read_jsonl(inventory_dir / "hosts.jsonl")
            }
            self.assertTrue(hosts["10.0.0.1"]["in_scope"])
            self.assertTrue(hosts["10.0.0.2"]["in_scope"])
            self.assertFalse(hosts["203.0.113.10"]["in_scope"])

            graph = json.loads(
                (graph_dir / "graph.json").read_text(encoding="utf-8")
            )
            graph_scope = {
                node["id"]: node.get("in_scope")
                for node in graph["nodes"]
                if node.get("type") == "host"
            }
            self.assertEqual(
                graph_scope,
                {
                    "10.0.0.1": True,
                    "10.0.0.2": True,
                    "203.0.113.10": False,
                },
            )

            scores = {
                row["id"]: row
                for row in _read_jsonl(
                    criticality_dir / "criticality.jsonl"
                )
            }
            self.assertEqual(set(scores), {"10.0.0.1", "10.0.0.2"})
            self.assertEqual(scores["10.0.0.1"]["metrics"]["degree"], 1)
            self.assertEqual(scores["10.0.0.1"]["metrics"]["bytes_total"], 10)

    def test_external_payload_and_dump_exclude_outside_scope(self) -> None:
        graph = {
            "nodes": [
                {"id": "10.0.0.1", "type": "host", "in_scope": True},
                {"id": "10.0.0.2", "type": "host", "in_scope": True},
                {
                    "id": "10.0.0.2:443/tcp",
                    "type": "service",
                    "ip": "10.0.0.2",
                    "port": 443,
                    "proto": "tcp",
                    "in_scope": True,
                },
                {"id": "203.0.113.10", "type": "host", "in_scope": False},
                {
                    "id": "203.0.113.10:443/tcp",
                    "type": "service",
                    "ip": "203.0.113.10",
                    "port": 443,
                    "proto": "tcp",
                    "in_scope": False,
                },
            ],
            "edges": [
                {
                    "src": "10.0.0.1",
                    "dst": "10.0.0.2:443/tcp",
                    "flows": 1,
                    "bytes": 10,
                },
                {
                    "src": "10.0.0.1",
                    "dst": "203.0.113.10:443/tcp",
                    "flows": 1,
                    "bytes": 9999,
                },
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path = root / "graph.json"
            output_dir = root / "criticality"
            dump_path = root / "external-input.json"
            graph_path.write_text(json.dumps(graph), encoding="utf-8")

            with patch(
                "pmmap.criticality._run_external",
                return_value=[
                    {"id": "10.0.0.1", "score": 0.5},
                    {"id": "10.0.0.2", "score": 0.75},
                ],
            ) as mocked:
                criticality_run(
                    graph_path=str(graph_path),
                    out_dir=str(output_dir),
                    external_cmd="external",
                    dump_input_path=str(dump_path),
                    external_timeout=2.5,
                )

            payload = mocked.call_args.args[1]
            payload_ids = {node["id"] for node in payload["nodes"]}
            self.assertEqual(
                payload_ids,
                {"10.0.0.1", "10.0.0.2", "10.0.0.2:443/tcp"},
            )
            self.assertEqual(
                [(edge["src"], edge["dst"]) for edge in payload["edges"]],
                [("10.0.0.1", "10.0.0.2:443/tcp")],
            )
            self.assertEqual(
                json.loads(dump_path.read_text(encoding="utf-8")),
                payload,
            )
            self.assertEqual(mocked.call_args.kwargs["timeout_seconds"], 2.5)


class ExternalCriticalityHardeningTests(unittest.TestCase):
    def test_external_result_requires_a_numeric_score(self) -> None:
        graph = {
            "nodes": [
                {"id": "10.0.0.1", "type": "host", "in_scope": True},
            ],
            "edges": [],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path = root / "graph.json"
            graph_path.write_text(json.dumps(graph), encoding="utf-8")

            for invalid_result, message in (
                ([{"id": "10.0.0.1"}], "missing score"),
                ([{"id": "10.0.0.1", "score": True}], "non-numeric score"),
                ([{"id": "10.0.0.1", "score": float("nan")}], "non-finite"),
            ):
                with (
                    self.subTest(result=invalid_result),
                    patch(
                        "pmmap.criticality._run_external",
                        return_value=invalid_result,
                    ),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    criticality_run(
                        graph_path=str(graph_path),
                        out_dir=str(root / "criticality"),
                        external_cmd="external",
                    )

    def test_invalid_external_result_fails_closed_and_removes_stale_outputs(self) -> None:
        graph = {
            "nodes": [
                {"id": "10.0.0.1", "type": "host", "in_scope": True},
            ],
            "edges": [],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path = root / "graph.json"
            output_dir = root / "criticality"
            output_dir.mkdir()
            graph_path.write_text(json.dumps(graph), encoding="utf-8")
            (output_dir / "criticality.jsonl").write_text(
                '{"id":"stale"}\n',
                encoding="utf-8",
            )
            (output_dir / "criticality_top.json").write_text(
                '[{"id":"stale"}]\n',
                encoding="utf-8",
            )

            with (
                patch(
                    "pmmap.criticality._run_external",
                    return_value=[{"id": "outside-or-unknown", "score": 1.0}],
                ),
                self.assertRaisesRegex(ValueError, "unknown or out-of-scope"),
            ):
                criticality_run(
                    graph_path=str(graph_path),
                    out_dir=str(output_dir),
                    external_cmd="external",
                )

            self.assertFalse((output_dir / "criticality.jsonl").exists())
            self.assertFalse((output_dir / "criticality_top.json").exists())

    def test_internal_rerun_removes_stale_default_external_payload(self) -> None:
        graph = {
            "nodes": [
                {"id": "10.0.0.1", "type": "host", "in_scope": True},
            ],
            "edges": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path = root / "graph.json"
            output_dir = root / "criticality"
            output_dir.mkdir()
            graph_path.write_text(json.dumps(graph), encoding="utf-8")
            stale_dump = output_dir / "criticality_input.json"
            stale_dump.write_text('{"stale": true}\n', encoding="utf-8")

            criticality_run(
                graph_path=str(graph_path),
                out_dir=str(output_dir),
            )

            self.assertFalse(stale_dump.exists())

    def test_external_timeout_is_bounded_and_fails_closed(self) -> None:
        with patch(
            "pmmap.criticality.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["external"], timeout=0.25),
        ) as mocked:
            with self.assertRaisesRegex(
                RuntimeError,
                "External criticality tool failed",
            ):
                _run_external(
                    "external",
                    {"nodes": [], "edges": []},
                    timeout_seconds=0.25,
                )

        self.assertEqual(mocked.call_args.kwargs["timeout"], 0.25)


if __name__ == "__main__":
    unittest.main()
