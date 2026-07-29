import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from pmmap.analyze import run as analyze_run
from pmmap.endpoints import infer_endpoints
from pmmap.inventory import run as inventory_run
from pmmap.normalize import (
    _map_common_zeek_fields,
    _map_zeek_ssh_row,
    _normalize_epoch,
    run as normalize_run,
)
from pmmap.schema import Flow
from pmmap import utils as utils_module


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class EndpointInferenceTests(unittest.TestCase):
    SERVICE_MAP = {
        ("tcp", 22): "ssh",
        ("tcp", 443): "https",
    }

    def test_known_service_and_ephemeral_port_infer_both_directions(self) -> None:
        forward = infer_endpoints(
            {
                "src_ip": "10.0.0.2",
                "src_port": 55000,
                "dst_ip": "10.0.0.10",
                "dst_port": 443,
                "proto": "TCP",
            },
            self.SERVICE_MAP,
        )
        self.assertEqual((forward.client_ip, forward.server_ip, forward.server_port), (
            "10.0.0.2",
            "10.0.0.10",
            443,
        ))
        self.assertFalse(forward.reversed)
        self.assertEqual(forward.method, "known_service_vs_ephemeral")
        self.assertEqual(forward.confidence, "high")

        reverse = infer_endpoints(
            {
                "src_ip": "10.0.0.10",
                "src_port": 22,
                "dst_ip": "10.0.0.2",
                "dst_port": 60222,
                "proto": "tcp",
            },
            self.SERVICE_MAP,
        )
        self.assertEqual((reverse.client_ip, reverse.server_ip, reverse.server_port), (
            "10.0.0.2",
            "10.0.0.10",
            22,
        ))
        self.assertTrue(reverse.reversed)
        self.assertEqual(reverse.confidence, "high")

    def test_explicit_orientation_wins_and_ambiguous_ports_are_not_services(self) -> None:
        explicit = infer_endpoints(
            {
                "src_ip": "2001:db8::1",
                "src_port": 40000,
                "dst_ip": "2001:db8::2",
                "dst_port": 40001,
                "proto": "tcp",
                "src_is_initiator": True,
                "orientation_source": "zeek_orig_resp",
            },
            self.SERVICE_MAP,
        )
        self.assertTrue(explicit.service_identified)
        self.assertEqual(explicit.server_ip, "2001:db8::2")
        self.assertEqual(explicit.method, "zeek_orig_resp")
        self.assertEqual(explicit.confidence, "high")

        ambiguous = infer_endpoints(
            {
                "src_ip": "10.0.0.3",
                "src_port": 40000,
                "dst_ip": "10.0.0.4",
                "dst_port": 40001,
                "proto": "tcp",
            },
            self.SERVICE_MAP,
        )
        self.assertFalse(ambiguous.service_identified)
        self.assertEqual(ambiguous.method, "ambiguous_ports")
        self.assertEqual(ambiguous.confidence, "none")

    def test_inventory_and_graph_share_reverse_direction_inference(self) -> None:
        flows = [
            {
                "ts": 1.0,
                "src_ip": "10.0.0.10",
                "src_port": 22,
                "dst_ip": "10.0.0.20",
                "dst_port": 60222,
                "proto": "tcp",
                "bytes": 100,
                "pkts": 2,
            },
            {
                "ts": 2.0,
                "src_ip": "10.0.0.30",
                "src_port": 40000,
                "dst_ip": "10.0.0.40",
                "dst_port": 40001,
                "proto": "tcp",
                "bytes": 50,
                "pkts": 1,
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flows_path = root / "flows.jsonl"
            flows_path.write_text(
                "\n".join(json.dumps(record) for record in flows) + "\n",
                encoding="utf-8",
            )
            inventory_dir = root / "inventory"
            graph_dir = root / "graph"

            inventory_run(str(flows_path), str(inventory_dir))
            analyze_run(str(flows_path), str(graph_dir))

            hosts = {row["ip"]: row for row in _read_jsonl(inventory_dir / "hosts.jsonl")}
            self.assertEqual(
                hosts["10.0.0.10"]["services_offered"],
                [{"proto": "tcp", "port": 22, "flows": 1}],
            )
            self.assertEqual(
                hosts["10.0.0.20"]["services_used"],
                [{"proto": "tcp", "port": 22, "flows": 1}],
            )
            self.assertEqual(hosts["10.0.0.20"]["services_offered"], [])
            self.assertEqual(hosts["10.0.0.40"]["services_offered"], [])

            graph = json.loads((graph_dir / "graph.json").read_text(encoding="utf-8"))
            self.assertEqual(len(graph["edges"]), 1)
            edge = graph["edges"][0]
            self.assertEqual(edge["src"], "10.0.0.20")
            self.assertEqual(edge["dst"], "10.0.0.10:22/tcp")
            self.assertEqual(
                edge["endpoint_inference_methods"],
                ["known_service_vs_ephemeral"],
            )
            service_ids = {
                node["id"] for node in graph["nodes"] if node["type"] == "service"
            }
            self.assertNotIn("10.0.0.40:40001/tcp", service_ids)


class NormalizationSemanticsTests(unittest.TestCase):
    def test_explicit_false_overrides_configured_drop_outside(self) -> None:
        configured = {"filters": {"drop_outside_ranges": True}}
        with mock.patch.object(
            utils_module,
            "_load_yaml_safe",
            return_value=configured,
        ):
            inherited = utils_module.NetFilter(drop_outside=None)
            overridden = utils_module.NetFilter(drop_outside=False)

        self.assertTrue(inherited.drop_outside)
        self.assertFalse(overridden.drop_outside)

    def test_drop_outside_keeps_flows_touching_scope_and_adds_flags(self) -> None:
        rows = [
            "ts,sa,sp,da,dp,pr,pkt,byt,td",
            "1700000000,10.0.0.1,55000,203.0.113.10,443,tcp,2,100,0.1",
            "1700000001,203.0.113.20,22,10.0.0.2,60000,tcp,2,200,0.1",
            "1700000002,203.0.113.30,55000,198.51.100.30,443,tcp,2,300,0.1",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "input"
            output_dir = root / "output"
            input_dir.mkdir()
            (input_dir / "flows.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")

            normalize_run(
                str(input_dir),
                str(output_dir),
                net_cfg={
                    "include_cidrs": ["10.0.0.0/8"],
                    "exclude_cidrs": [],
                    "drop_outside": True,
                },
            )

            flows = _read_jsonl(output_dir / "flows.jsonl")
            self.assertEqual(len(flows), 2)
            self.assertEqual(
                [(flow["src_in_scope"], flow["dst_in_scope"]) for flow in flows],
                [(True, False), (False, True)],
            )

    def test_explicit_exclusion_drops_records_touching_excluded_range(self) -> None:
        rows = [
            "ts,sa,sp,da,dp,pr,pkt,byt,td",
            "1700000000,10.0.0.1,55000,10.9.0.1,443,tcp,2,100,0.1",
            "1700000001,10.0.0.2,55000,203.0.113.1,443,tcp,2,100,0.1",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "input"
            output_dir = root / "output"
            input_dir.mkdir()
            (input_dir / "flows.csv").write_text(
                "\n".join(rows) + "\n",
                encoding="utf-8",
            )

            normalize_run(
                str(input_dir),
                str(output_dir),
                net_cfg={
                    "include_cidrs": ["10.0.0.0/8"],
                    "exclude_cidrs": ["10.9.0.0/16"],
                    "drop_outside": False,
                },
            )

            flows = _read_jsonl(output_dir / "flows.jsonl")
            self.assertEqual(len(flows), 1)
            self.assertEqual(flows[0]["src_ip"], "10.0.0.2")
            stats = json.loads(
                (output_dir / "normalization_stats.json").read_text(encoding="utf-8")
            )
            self.assertEqual(stats["filtered_excluded"], 1)

    def test_epoch_seconds_milliseconds_microseconds_and_nanoseconds(self) -> None:
        expected = 1_700_000_000.0
        self.assertEqual(_normalize_epoch(expected), expected)
        self.assertEqual(_normalize_epoch(1_700_000_000_000.0), expected)
        self.assertEqual(_normalize_epoch(1_700_000_000_000_000.0), expected)
        self.assertEqual(_normalize_epoch(1_700_000_000_000_000_000.0), expected)

    def test_zeek_orientation_and_server_hassh_are_preserved(self) -> None:
        common = _map_common_zeek_fields({
            "id.orig_h": "10.0.0.2",
            "id.orig_p": "55000",
            "id.resp_h": "10.0.0.10",
            "id.resp_p": "22",
            "proto": "tcp",
        })
        self.assertTrue(common["src_is_initiator"])
        self.assertEqual(common["orientation_source"], "zeek_orig_resp")

        ssh = _map_zeek_ssh_row({
            "id.orig_h": "10.0.0.2",
            "id.orig_p": "55000",
            "id.resp_h": "10.0.0.10",
            "id.resp_p": "22",
            "proto": "tcp",
            "hassh": "client-hash",
            "hasshServer": "server-hash",
        })
        self.assertEqual(ssh["hassh"], "client-hash")
        self.assertEqual(ssh["hassh_server"], "server-hash")

    def test_flow_rejects_invalid_addresses_ports_and_negative_counters(self) -> None:
        valid = {
            "ts": 1.0,
            "src_ip": "10.0.0.1",
            "src_port": 50000,
            "dst_ip": "10.0.0.2",
            "dst_port": 443,
            "proto": "tcp",
            "bytes": 100,
            "pkts": 2,
        }
        for field, invalid_value in (
            ("src_ip", "not-an-ip"),
            ("dst_port", 70000),
            ("bytes", -1),
            ("pkts", -1),
        ):
            record = dict(valid)
            record[field] = invalid_value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                Flow(**record)


if __name__ == "__main__":
    unittest.main()
