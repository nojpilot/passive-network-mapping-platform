import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate_cesnet_fingerprints import evaluate


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


class CesnetFingerprintEvaluationTests(unittest.TestCase):
    def test_reports_coverage_and_conditional_label_match_rate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            truth_path = root / "truth.jsonl"
            enriched_path = root / "enriched.jsonl"
            label_map_path = root / "labels.json"
            output_path = root / "report.json"
            _write_jsonl(
                truth_path,
                [
                    {
                        "synthetic_src_ip": "10.0.0.1",
                        "os_family": "android",
                        "tls_ja3": "a",
                    },
                    {
                        "synthetic_src_ip": "10.0.0.2",
                        "os_family": "linux",
                        "tls_ja3": "b",
                    },
                    {
                        "synthetic_src_ip": "10.0.0.3",
                        "os_family": "windows",
                        "tls_ja3": "c",
                    },
                ],
            )
            _write_jsonl(
                enriched_path,
                [
                    {
                        "ip": "10.0.0.1",
                        "cpe": [
                            {
                                "cpe": "cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
                                "endpoint_role": "client",
                            }
                        ],
                    },
                    {
                        "ip": "10.0.0.2",
                        "cpe": [
                            {
                                "cpe": "cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
                                "endpoint_role": "client",
                            },
                            {
                                "cpe": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                "endpoint_role": "client",
                            },
                        ],
                    },
                    {"ip": "10.0.0.3"},
                ],
            )
            label_map_path.write_text(
                json.dumps(
                    {
                        "cpe_prefix_to_os_families": {
                            "cpe:2.3:o:google:android": ["android"]
                        }
                    }
                ),
                encoding="utf-8",
            )

            report = evaluate(
                truth_path,
                enriched_path,
                label_map_path,
                output_path,
            )

            self.assertEqual(
                report["counts"]["rows_with_scored_os_cpe_hypothesis"],
                2,
            )
            self.assertEqual(report["counts"]["correct_os_family_rows"], 1)
            self.assertAlmostEqual(
                report["metrics"]["os_prediction_coverage"],
                2 / 3,
            )
            self.assertAlmostEqual(
                report["metrics"][
                    "os_prediction_label_match_rate_on_covered_rows"
                ],
                0.5,
            )
            self.assertIn(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                report["application_hypotheses_not_scored_as_os"],
            )
            self.assertTrue(output_path.is_file())


if __name__ == "__main__":
    unittest.main()
