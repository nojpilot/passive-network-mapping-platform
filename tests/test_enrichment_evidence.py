import json
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmmap.cpe import CPEMapper, CPEMapValidationError
from pmmap.enrich import run as enrich_run


SAMPLE_JA3 = "20ab9bbd3c036476e32abecc348ea1ec"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _records_by_ip(path: Path) -> dict[str, dict]:
    return {record["ip"]: record for record in _read_jsonl(path)}


class EnrichmentEvidenceTests(unittest.TestCase):
    def test_cesnet_sample_entries_are_marked_as_illustrative(self) -> None:
        mapper = CPEMapper.from_file(REPO_ROOT / "data" / "cpe_map.sample.yaml")
        cesnet_fingerprints = [
            evidence
            for evidence in mapper.mapping["ja3"]
            if len(evidence) == 32
            and all(character in "0123456789abcdef" for character in evidence)
        ]
        self.assertEqual(len(cesnet_fingerprints), 10)
        for evidence in cesnet_fingerprints:
            with self.subTest(evidence=evidence):
                hypotheses = mapper.match_hypotheses("ja3", evidence)
                self.assertEqual(len(hypotheses), 1)
                self.assertEqual(hypotheses[0]["confidence"], "illustrative")
                self.assertIn(
                    "not an independent classifier",
                    hypotheses[0]["mapping_entry_provenance"],
                )

    def test_environment_mapping_is_not_loaded_implicitly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flows_path = root / "flows.jsonl"
            mapping_path = root / "mapping.json"
            out_dir = root / "enriched"
            _write_jsonl(
                flows_path,
                [
                    {
                        "src_ip": "10.0.0.1",
                        "dst_ip": "10.0.0.2",
                        "ja3": SAMPLE_JA3,
                    }
                ],
            )
            mapping_path.write_text(
                json.dumps(
                    {
                        "ja3": {
                            SAMPLE_JA3: (
                                "cpe:2.3:o:google:android:-:*:*:*:*:*:*:*"
                            )
                        }
                    }
                ),
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {"PMMAP_CPE_MAP": str(mapping_path)},
                clear=False,
            ):
                enrich_run(str(flows_path), str(out_dir))

            records = _records_by_ip(out_dir / "enriched_hosts.jsonl")
            self.assertNotIn("cpe", records["10.0.0.1"])
            manifest = json.loads(
                (out_dir / "enrichment_manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["cpe_mapping"]["enabled"])
            self.assertIsNone(manifest["cpe_mapping"]["path"])
            self.assertIsNone(manifest["cpe_mapping"]["sha256"])
            self.assertEqual(manifest["matches"]["hypotheses_emitted"], 0)

    def test_sni_is_retained_as_observation_but_never_mapped_to_host_cpe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flows_path = root / "flows.jsonl"
            mapping_path = root / "mapping.json"
            out_dir = root / "enriched"
            _write_jsonl(
                flows_path,
                [
                    {
                        "src_ip": "10.0.0.1",
                        "dst_ip": "198.51.100.10",
                        "sni": "openpgpkey.archlinux.org",
                    }
                ],
            )
            mapping_path.write_text(
                json.dumps(
                    {
                        "ja3": {
                            "unused-valid-fingerprint": (
                                "cpe:2.3:o:archlinux:arch_linux:*:*:*:*:*:*:*:*"
                            )
                        }
                    }
                ),
                encoding="utf-8",
            )

            enrich_run(
                str(flows_path),
                str(out_dir),
                cpe_map_path=str(mapping_path),
            )

            records = _records_by_ip(out_dir / "enriched_hosts.jsonl")
            self.assertEqual(
                records["10.0.0.1"]["sni_used"],
                [{"value": "openpgpkey.archlinux.org", "count": 1}],
            )
            self.assertEqual(
                records["198.51.100.10"]["sni_served"],
                [{"value": "openpgpkey.archlinux.org", "count": 1}],
            )
            self.assertNotIn("cpe", records["10.0.0.1"])
            self.assertNotIn("cpe", records["198.51.100.10"])

    def test_fingerprint_hypotheses_keep_endpoint_and_mapping_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flows_path = root / "flows.jsonl"
            mapping_path = root / "mapping.json"
            out_dir = root / "enriched"
            _write_jsonl(
                flows_path,
                [
                    {
                        "src_ip": "10.0.0.1",
                        "dst_ip": "198.51.100.10",
                        "ja3": "client-ja3",
                        "ja3s": "server-ja3s",
                        "hassh": "client-hassh",
                        "hassh_server": "server-hassh",
                    }
                ],
            )
            mapping_path.write_text(
                json.dumps(
                    {
                        "ja3": {
                            "client-ja3": {
                                "cpe": "cpe:2.3:a:example:client:*:*:*:*:*:*:*:*",
                                "confidence": "medium",
                                "provenance": "curated-test-entry",
                            }
                        },
                        "ja3s": {
                            "server-ja3s": "cpe:2.3:a:example:server:*:*:*:*:*:*:*:*"
                        },
                        "hassh": {
                            "client-hassh": "cpe:2.3:a:example:ssh_client:*:*:*:*:*:*:*:*",
                            "server-hassh": "cpe:2.3:a:example:ssh_server:*:*:*:*:*:*:*:*",
                        },
                    }
                ),
                encoding="utf-8",
            )

            enrich_run(
                str(flows_path),
                str(out_dir),
                cpe_map_path=str(mapping_path),
            )

            records = _records_by_ip(out_dir / "enriched_hosts.jsonl")
            client = records["10.0.0.1"]
            server = records["198.51.100.10"]
            self.assertEqual(client["hassh"], [{"value": "client-hassh", "count": 1}])
            self.assertEqual(server["server_hassh"], [{"value": "server-hassh", "count": 1}])

            client_hypotheses = {(entry["source"], entry["endpoint_role"]): entry for entry in client["cpe"]}
            server_hypotheses = {(entry["source"], entry["endpoint_role"]): entry for entry in server["cpe"]}
            self.assertEqual(set(client_hypotheses), {("ja3", "client"), ("hassh", "client")})
            self.assertEqual(set(server_hypotheses), {("ja3s", "server"), ("hassh", "server")})

            ja3_hypothesis = client_hypotheses[("ja3", "client")]
            self.assertEqual(ja3_hypothesis["confidence"], "medium")
            self.assertEqual(
                ja3_hypothesis["provenance"]["mapping_entry"],
                "curated-test-entry",
            )
            self.assertEqual(
                Path(ja3_hypothesis["provenance"]["mapping_source"]),
                mapping_path.resolve(),
            )
            self.assertEqual(
                ja3_hypothesis["provenance"]["mapping_sha256"],
                hashlib.sha256(mapping_path.read_bytes()).hexdigest(),
            )

            for hypothesis in client["cpe"] + server["cpe"]:
                self.assertIn("confidence", hypothesis)
                self.assertEqual(
                    hypothesis["provenance"]["method"],
                    "configured_fingerprint_lookup",
                )

            manifest = json.loads(
                (out_dir / "enrichment_manifest.json").read_text(encoding="utf-8")
            )
            expected_sha256 = hashlib.sha256(mapping_path.read_bytes()).hexdigest()
            self.assertEqual(
                Path(manifest["cpe_mapping"]["path"]),
                mapping_path.resolve(),
            )
            self.assertEqual(
                manifest["cpe_mapping"]["sha256"],
                expected_sha256,
            )
            self.assertEqual(
                manifest["cpe_mapping"]["entries_by_section"],
                {"ja3": 1, "ja3s": 1, "hassh": 2},
            )
            self.assertEqual(manifest["matches"]["hosts_with_hypotheses"], 2)
            self.assertEqual(manifest["matches"]["hypotheses_emitted"], 4)
            self.assertEqual(
                manifest["matches"]["unique_evidence_values_matched"],
                4,
            )
            self.assertEqual(
                manifest["matches"]["hypotheses_by_source"],
                {"ja3": 1, "ja3s": 1, "hassh": 2},
            )

    def test_invalid_explicit_mapping_fails_with_context(self) -> None:
        invalid_cases = [
            (
                "unsupported-section",
                {"sni": {}},
                "unsupported section",
            ),
            (
                "invalid-section-value",
                {"ja3": []},
                "section 'ja3' must be a non-empty object",
            ),
            (
                "invalid-entry",
                {"ja3": {"fingerprint": {"confidence": "high"}}},
                "must contain exactly one of 'cpe' or 'value'",
            ),
            (
                "invalid-cpe",
                {"ja3": {"fingerprint": "not-a-cpe"}},
                "invalid CPE 2.3 value",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, payload, message in invalid_cases:
                with self.subTest(name=name):
                    mapping_path = root / f"{name}.json"
                    mapping_path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(CPEMapValidationError, message):
                        CPEMapper.from_file(mapping_path)

            malformed_json = root / "malformed.json"
            malformed_json.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(
                CPEMapValidationError,
                "could not be parsed",
            ):
                CPEMapper.from_file(malformed_json)

            with self.assertRaisesRegex(FileNotFoundError, "does not exist"):
                CPEMapper.from_file(root / "missing.yaml")


if __name__ == "__main__":
    unittest.main()
