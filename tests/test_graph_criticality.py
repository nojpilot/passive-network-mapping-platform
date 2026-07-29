import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmmap.centrality import plan_betweenness
from pmmap.criticality import run as run_criticality
from pmmap.criticality import _internal_scores
from pmmap.export import _host_metrics
from pmmap.graph_projection import build_host_graph


def _service(service_id: str, ip: str, port: int = 443) -> dict:
    return {
        "id": service_id,
        "type": "service",
        "ip": ip,
        "port": port,
        "proto": "tcp",
    }


class HostGraphProjectionTests(unittest.TestCase):
    def test_projection_is_sorted_and_aggregates_service_evidence(self) -> None:
        nodes = [
            _service("10.0.0.2:8443/tcp", "10.0.0.2", 8443),
            {"id": "10.0.0.3", "type": "host"},
            {"id": "10.0.0.2", "type": "host", "roles": ["web_server"]},
            _service("10.0.0.2:443/tcp", "10.0.0.2"),
            {"id": "10.0.0.1", "type": "host"},
        ]
        edges = [
            {
                "src": "10.0.0.1",
                "dst": "10.0.0.2:8443/tcp",
                "flows": 2,
                "bytes": 200,
            },
            {
                "src": "10.0.0.1",
                "dst": "10.0.0.2:443/tcp",
                "flows": 1,
                "bytes": 100,
            },
        ]

        graph = build_host_graph(nodes, edges)

        self.assertEqual(list(graph.nodes()), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(list(graph.edges()), [("10.0.0.1", "10.0.0.2")])
        self.assertEqual(graph.nodes["10.0.0.2"]["roles"], ["web_server"])
        self.assertEqual(graph["10.0.0.1"]["10.0.0.2"]["flows"], 3)
        self.assertEqual(graph["10.0.0.1"]["10.0.0.2"]["bytes"], 300)
        self.assertEqual(
            graph["10.0.0.1"]["10.0.0.2"]["service_ids"],
            ("10.0.0.2:443/tcp", "10.0.0.2:8443/tcp"),
        )

    def test_internal_criticality_ranks_shared_server_above_clients(self) -> None:
        server = "10.0.0.10"
        service_id = f"{server}:443/tcp"
        clients = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        nodes = [
            *({"id": client, "type": "host"} for client in clients),
            {"id": server, "type": "host", "roles": ["web_server"]},
            _service(service_id, server),
        ]
        edges = [
            {"src": client, "dst": service_id, "flows": 2, "bytes": 100}
            for client in clients
        ]

        scores = _internal_scores(nodes, edges)
        by_id = {row["id"]: row for row in scores}

        self.assertEqual(scores[0]["id"], server)
        self.assertEqual(set(by_id), {*clients, server})
        self.assertNotIn(service_id, by_id)
        self.assertEqual(by_id[server]["metrics"]["degree"], 3)
        self.assertEqual(by_id[server]["metrics"]["in_degree"], 3)
        self.assertEqual(by_id[server]["metrics"]["out_degree"], 0)
        self.assertEqual(by_id[server]["metrics"]["bytes_total"], 300)
        self.assertEqual(by_id[server]["metrics"]["flows_total"], 6)
        self.assertAlmostEqual(by_id[server]["metrics"]["betweenness"], 1.0)
        self.assertEqual(
            by_id[server]["provenance"]["projection"],
            "host_to_host_via_service",
        )
        self.assertIsNone(by_id[server]["provenance"]["betweenness_weight"])
        self.assertEqual(by_id[server]["provenance"]["method_version"], 3)
        self.assertEqual(by_id[server]["provenance"]["betweenness_mode"], "exact")

    def test_unavailable_volume_signal_is_removed_and_weights_are_renormalized(self) -> None:
        server = "10.0.0.10"
        service_id = f"{server}:443/tcp"
        nodes = [
            {"id": "10.0.0.1", "type": "host"},
            {"id": "10.0.0.2", "type": "host"},
            {"id": server, "type": "host"},
            _service(service_id, server),
        ]
        edges = [
            {"src": "10.0.0.1", "dst": service_id, "flows": 1, "bytes": 0},
            {"src": "10.0.0.2", "dst": service_id, "flows": 1, "bytes": 0},
        ]

        scores = _internal_scores(nodes, edges)
        top = scores[0]

        self.assertEqual(top["id"], server)
        self.assertAlmostEqual(top["score"], 1.0)
        self.assertFalse(top["provenance"]["available_signals"]["bytes_total"])
        self.assertEqual(
            top["provenance"]["score_weights"]["bytes_total"],
            0.0,
        )
        self.assertAlmostEqual(
            sum(top["provenance"]["score_weights"].values()),
            1.0,
        )

    def test_bytes_are_not_used_as_shortest_path_distance(self) -> None:
        nodes = [
            {"id": host, "type": "host"}
            for host in ("a", "b", "c")
        ] + [
            _service("b:443/tcp", "b"),
            _service("c:443/tcp", "c"),
            _service("c:8443/tcp", "c", 8443),
        ]
        # Structurally this is a triangle. If bytes were interpreted as path
        # distance, b would lie on the cheaper a-b-c path instead of a-c.
        edges = [
            {"src": "a", "dst": "b:443/tcp", "flows": 1, "bytes": 1},
            {"src": "b", "dst": "c:443/tcp", "flows": 1, "bytes": 1},
            {"src": "a", "dst": "c:8443/tcp", "flows": 1, "bytes": 1000},
        ]

        by_id = {row["id"]: row for row in _internal_scores(nodes, edges)}

        self.assertEqual(by_id["b"]["metrics"]["betweenness"], 0.0)

    def test_work_policy_uses_exact_for_sparse_cesnet_sized_graph(self) -> None:
        plan = plan_betweenness(n_nodes=2145, n_edges=2000)

        self.assertEqual(plan["mode"], "exact")
        self.assertIsNone(plan["sample_k"])
        self.assertEqual(plan["estimated_exact_work"], 8_891_025)
        self.assertEqual(plan["work_model"], "sources * (nodes + edges)")

    def test_work_policy_retains_deterministic_sampled_and_skipped_modes(self) -> None:
        sampled = plan_betweenness(n_nodes=5000, n_edges=4999)
        skipped = plan_betweenness(n_nodes=100_000, n_edges=100_000)

        self.assertEqual(sampled["mode"], "sampled")
        self.assertEqual(sampled["sample_k"], 64)
        self.assertEqual(sampled["sample_seed"], 42)
        self.assertEqual(skipped["mode"], "skipped")
        self.assertEqual(
            skipped["skipped_reason"],
            "sampled_work_limit_exceeded",
        )

    def test_export_approximation_receives_sorted_node_order(self) -> None:
        node_ids = [f"host-{index:04d}" for index in range(4999, -1, -1)]
        graph = {
            "nodes": [{"id": node_id, "type": "host"} for node_id in node_ids],
            "edges": [],
        }
        captured_order: list[str] = []

        def fake_betweenness(network, **kwargs):
            captured_order.extend(network.nodes())
            return {node_id: 0.0 for node_id in network.nodes()}

        with patch("pmmap.export.nx.betweenness_centrality", side_effect=fake_betweenness) as mocked:
            metrics, meta = _host_metrics(graph, hosts=[], criticality=[])

        self.assertEqual(captured_order, sorted(node_ids))
        self.assertEqual([row["id"] for row in metrics], sorted(node_ids))
        self.assertEqual(meta["betweenness_sample_k"], 64)
        self.assertEqual(mocked.call_args.kwargs["k"], 64)
        self.assertEqual(mocked.call_args.kwargs["seed"], 42)

    def test_host_metadata_roles_are_merged_with_graph_roles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path = root / "graph.json"
            hosts_path = root / "hosts.jsonl"
            output_dir = root / "criticality"
            graph_path.write_text(
                json.dumps(
                    {
                        "nodes": [
                            {
                                "id": "10.0.0.1",
                                "type": "host",
                                "roles": ["web_server"],
                            }
                        ],
                        "edges": [],
                    }
                ),
                encoding="utf-8",
            )
            hosts_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "ip": "10.0.0.1",
                                "roles": ["dns_server"],
                            }
                        ),
                        json.dumps(
                            {
                                "ip": "10.0.0.1",
                                "roles": ["mail_server"],
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            run_criticality(
                graph_path=str(graph_path),
                out_dir=str(output_dir),
                hosts_path=str(hosts_path),
            )
            result = json.loads(
                (output_dir / "criticality.jsonl")
                .read_text(encoding="utf-8")
                .strip()
            )

        self.assertEqual(
            result["roles"],
            ["dns_server", "mail_server", "web_server"],
        )
        self.assertEqual(result["metrics"]["role_boost"], 0.05)

    def test_external_example_projects_services_and_scores_host_degree(self) -> None:
        payload = {
            "nodes": [
                {"id": "a", "type": "host"},
                {"id": "b", "type": "host"},
                {"id": "c", "type": "host"},
                _service("b:443/tcp", "b"),
                _service("c:443/tcp", "c"),
            ],
            "edges": [
                {
                    "src": "a",
                    "dst": "b:443/tcp",
                    "flows": 1,
                    "bytes": 1_000_000,
                },
                {
                    "src": "a",
                    "dst": "c:443/tcp",
                    "flows": 1,
                    "bytes": 1,
                },
            ],
        }
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "external_criticality_stub.py"
        )

        completed = subprocess.run(
            [sys.executable, str(script)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
        )
        results = json.loads(completed.stdout)
        by_id = {row["id"]: row for row in results}

        self.assertEqual([row["id"] for row in results], ["a", "b", "c"])
        self.assertEqual(by_id["a"]["degree"], 2)
        self.assertEqual(by_id["a"]["score"], 1.0)
        self.assertEqual(by_id["b"]["score"], 0.5)
        self.assertEqual(by_id["c"]["score"], 0.5)
        self.assertNotIn("bytes", by_id["a"])


if __name__ == "__main__":
    unittest.main()
