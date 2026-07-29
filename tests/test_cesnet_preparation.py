import csv
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from pmmap.schema import Flow
from scripts.prepare_cesnet import prepare
from scripts.run_cesnet import main as run_cesnet


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_source(path: Path) -> None:
    fields = [
        "string os_family",
        "string os_type",
        "string os_version",
        "string TLS_VERSION",
        "string TLS_ALPN",
        "bytes TLS_JA3",
        "string TLS_SNI",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "string os_family": "Linux",
                "string os_type": "desktop",
                "string os_version": "6.x",
                "string TLS_VERSION": "TLSv1.3",
                "string TLS_ALPN": "h2",
                "bytes TLS_JA3": "ja3-a",
                "string TLS_SNI": "example.test",
            }
        )
        writer.writerow(
            {
                "string os_family": "Android",
                "string os_type": "mobile",
                "string os_version": "14",
                "string TLS_VERSION": "TLSv1.3",
                "string TLS_ALPN": "h2",
                "bytes TLS_JA3": "ja3-b",
                "string TLS_SNI": "example.test",
            }
        )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CesnetPreparationTests(unittest.TestCase):
    def test_preparation_is_explicitly_synthetic_and_retains_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "merged_tls.csv"
            _write_source(source)

            flows_path = root / "flows.jsonl"
            truth_path = root / "ground_truth.jsonl"
            manifest_path = root / "preparation_manifest.json"
            manifest = prepare(
                source,
                flows_path,
                truth_path,
                manifest_path,
                limit=2,
                offset=0,
            )

            flows = _read_jsonl(flows_path)
            self.assertEqual(len(flows), 2)
            self.assertEqual({row["bytes"] for row in flows}, {0})
            self.assertEqual({row["pkts"] for row in flows}, {0})
            self.assertEqual({row["orientation_source"] for row in flows}, {
                "cesnet_dataset_adapter"
            })
            self.assertTrue(all(row["src_is_initiator"] for row in flows))
            self.assertEqual(flows[0]["dst_ip"], flows[1]["dst_ip"])
            Flow(**flows[0])

            truth = _read_jsonl(truth_path)
            self.assertEqual(
                [row["os_family"] for row in truth],
                ["Linux", "Android"],
            )
            self.assertEqual(truth[0]["tls_alpn"], "h2")
            self.assertEqual(manifest["dataset"]["record_doi"], "10.5281/zenodo.15004766")
            self.assertEqual(manifest["selection"]["records_written"], 2)
            self.assertEqual(len(manifest["source"]["sha256"]), 64)
            self.assertIn("ts", manifest["synthetic_fields"])
            self.assertTrue(manifest_path.is_file())

    def test_preparation_streams_merged_tls_from_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "merged_tls.csv"
            archive_path = root / "cesnet-idle-os-traffic.zip"
            _write_source(source)
            with zipfile.ZipFile(
                archive_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.write(source, "merged_tls.csv")

            manifest = prepare(
                archive_path,
                root / "flows.jsonl",
                root / "ground_truth.jsonl",
                root / "preparation_manifest.json",
                limit=2,
                offset=0,
            )

            self.assertEqual(manifest["selection"]["records_written"], 2)
            self.assertEqual(manifest["source"]["kind"], "zip_member")
            self.assertEqual(manifest["source"]["member"], "merged_tls.csv")
            self.assertEqual(manifest["source"]["member_size_bytes"], source.stat().st_size)
            self.assertEqual(len(manifest["source"]["sha256"]), 64)

    def test_scenario_preserves_prepared_input_and_verifiable_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "merged_tls.csv"
            output = root / "run"
            _write_source(source)
            legacy_truth = output / "normalized" / "cesnet_ground_truth.jsonl"
            legacy_manifest = (
                output / "normalized" / "cesnet_preparation_manifest.json"
            )
            legacy_truth.parent.mkdir(parents=True)
            legacy_truth.write_text("stale\n", encoding="utf-8")
            legacy_manifest.write_text("{}\n", encoding="utf-8")

            status = run_cesnet([
                "--input",
                str(source),
                "--output",
                str(output),
                "--limit",
                "2",
                "--no-pdf",
            ])

            self.assertEqual(status, 0)
            prepared_flows = output / "prepared" / "flows.jsonl"
            normalized_flows = output / "normalized" / "flows.jsonl"
            preparation_manifest = json.loads(
                (output / "prepared" / "cesnet_preparation_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            run_manifest = json.loads(
                (output / "run_manifest.json").read_text(encoding="utf-8")
            )
            prepared_input = next(
                item
                for item in run_manifest["inputs"]
                if Path(item["path"]) == prepared_flows.resolve()
            )

            self.assertTrue(prepared_flows.is_file())
            self.assertTrue(normalized_flows.is_file())
            self.assertFalse(legacy_truth.exists())
            self.assertFalse(legacy_manifest.exists())
            self.assertNotEqual(prepared_flows.resolve(), normalized_flows.resolve())
            self.assertEqual(
                preparation_manifest["outputs"]["flows"]["sha256"],
                _sha256(prepared_flows),
            )
            self.assertEqual(prepared_input["sha256"], _sha256(prepared_flows))


if __name__ == "__main__":
    unittest.main()
