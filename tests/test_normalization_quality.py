import json
import tempfile
import unittest
from pathlib import Path

from pmmap.normalize import run as normalize_run


class NormalizationQualityTests(unittest.TestCase):
    def test_quality_report_counts_accepted_missing_and_invalid_rows(self) -> None:
        rows = [
            "ts,sa,sp,da,dp,pr,pkt,byt,td",
            "1700000000,10.0.0.1,55000,10.0.0.2,443,tcp,2,100,0.1",
            "1700000001,not-an-ip,55000,10.0.0.2,443,tcp,2,100,0.1",
            "1700000002,10.0.0.1,55000,10.0.0.2,443,tcp,2,-1,0.1",
            "1700000003,10.0.0.1,55000,,443,tcp,2,100,0.1",
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
                    "include_cidrs": [],
                    "exclude_cidrs": [],
                    "drop_outside": False,
                },
            )

            stats = json.loads(
                (output_dir / "normalization_stats.json").read_text(encoding="utf-8")
            )
            self.assertEqual(stats["input_records_seen"], 4)
            self.assertEqual(stats["accepted_flows"], 1)
            self.assertEqual(stats["invalid_records"], 2)
            self.assertEqual(stats["missing_required_fields"], 1)
            self.assertEqual(stats["filtered_outside_scope"], 0)
            self.assertTrue(stats["validation_errors"])

    def test_no_valid_records_fails_but_keeps_quality_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "input"
            output_dir = root / "output"
            input_dir.mkdir()
            (input_dir / "invalid.csv").write_text(
                "ts,sa,sp,da,dp,pr,pkt,byt\n"
                "1,invalid,1,also-invalid,2,tcp,-1,-1\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "No valid flow records"):
                normalize_run(
                    str(input_dir),
                    str(output_dir),
                    net_cfg={
                        "include_cidrs": [],
                        "exclude_cidrs": [],
                        "drop_outside": False,
                    },
                )
            self.assertTrue((output_dir / "normalization_stats.json").is_file())


if __name__ == "__main__":
    unittest.main()
