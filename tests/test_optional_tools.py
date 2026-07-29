import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmmap import ingest
from pmmap.criticality import _run_external
from pmmap.enrich import _parse_p0f_log


class IngestToolTests(unittest.TestCase):
    def test_ingest_handles_multiple_pcaps_and_standard_nfcapd_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap_a = root / "a.pcap"
            pcap_b = root / "b.pcap"
            netflow = root / "nfcapd.202607280000"
            for path in (pcap_a, pcap_b, netflow):
                path.write_bytes(b"fixture")
            output = root / "ingest"
            calls: list[tuple[list[str], str | None]] = []

            def fake_run(command, **kwargs):
                calls.append((list(command), kwargs.get("cwd")))
                if command[0] == "C:\\tools\\nfdump.exe":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=(
                            "ts,sa,sp,da,dp,pr,pkt,byt\n"
                            "1,10.0.0.1,50000,10.0.0.2,443,tcp,1,10\n"
                        ),
                        stderr="",
                    )
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            def fake_which(name):
                return {
                    "zeek-test": "C:\\tools\\zeek.exe",
                    "nfdump-test": "C:\\tools\\nfdump.exe",
                }.get(name)

            with (
                patch("pmmap.ingest.shutil.which", side_effect=fake_which),
                patch("pmmap.ingest.subprocess.run", side_effect=fake_run),
            ):
                ingest.run(
                    out_dir=str(output),
                    pcap_inputs=[str(pcap_a), str(pcap_b)],
                    netflow_inputs=[str(netflow)],
                    zeek_bin="zeek-test",
                    nfdump_bin="nfdump-test",
                )

            zeek_calls = [call for call in calls if call[0][0].endswith("zeek.exe")]
            nfdump_calls = [call for call in calls if call[0][0].endswith("nfdump.exe")]
            self.assertEqual(len(zeek_calls), 2)
            self.assertEqual(len(nfdump_calls), 1)
            self.assertTrue(all(call[0].count("-r") == 1 for call in zeek_calls))
            self.assertNotEqual(zeek_calls[0][1], zeek_calls[1][1])
            exported = list((output / "nfdump").glob("*.csv"))
            self.assertEqual(len(exported), 1)
            self.assertIn("nfcapd_202607280000", exported[0].name)
            self.assertIn("10.0.0.1", exported[0].read_text(encoding="utf-8"))

    def test_ingest_clears_stale_outputs_before_a_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "fresh.pcap"
            pcap.write_bytes(b"fixture")
            output = root / "ingest"
            stale_zeek = output / "zeek" / "old" / "conn.log"
            stale_nfdump = output / "nfdump" / "old.csv"
            stale_zeek.parent.mkdir(parents=True)
            stale_nfdump.parent.mkdir(parents=True)
            stale_zeek.write_text("stale", encoding="utf-8")
            stale_nfdump.write_text("stale", encoding="utf-8")

            with (
                patch("pmmap.ingest.shutil.which", return_value="zeek"),
                patch(
                    "pmmap.ingest.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        ["zeek"],
                        0,
                        stdout="",
                        stderr="",
                    ),
                ),
            ):
                ingest.run(out_dir=str(output), pcap_inputs=[str(pcap)])

            self.assertFalse(stale_zeek.exists())
            self.assertFalse(stale_nfdump.exists())


class OptionalIntegrationTests(unittest.TestCase):
    def test_p0f_parser_attaches_subject_os_to_client_address(self) -> None:
        parsed = _parse_p0f_log(
            "mod=syn+ack|cli=10.0.0.1/50000|srv=10.0.0.2/443|"
            "subj=cli|os=Windows 11 or newer\n"
        )
        self.assertEqual(parsed["10.0.0.1"]["Windows 11 or newer"], 1)

    def test_external_criticality_json_is_read_from_stdout(self) -> None:
        payload = {"nodes": [{"id": "a"}], "edges": []}
        with patch(
            "pmmap.criticality.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["external"],
                0,
                stdout=json.dumps([{"id": "a", "score": 0.75}]),
                stderr="",
            ),
        ) as mocked:
            output = _run_external("external --json", payload)

        self.assertEqual(output, [{"id": "a", "score": 0.75}])
        self.assertEqual(json.loads(mocked.call_args.kwargs["input"]), payload)


if __name__ == "__main__":
    unittest.main()
