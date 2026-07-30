import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest.mock import patch

from scripts import build_submission_archive as builder


class SubmissionArchiveTests(unittest.TestCase):
    def test_repository_root_forms_include_wsl_mount_for_windows_path(self) -> None:
        forms = builder._repository_root_forms(
            PureWindowsPath("C:/Users/example/project")
        )

        self.assertIn("/mnt/c/Users/example/project", forms)
        reverse_forms = builder._repository_root_forms(
            PurePosixPath("/mnt/c/Users/example/project")
        )
        self.assertIn(r"C:\Users\example\project", reverse_forms)
        self.assertIn("C:/Users/example/project", reverse_forms)

    def test_portable_artifact_hash_chain_is_repaired(self) -> None:
        enriched_path = "data/run/cesnet/enriched/enriched_hosts.jsonl"
        fingerprint_path = "data/run/cesnet/fingerprint_validation.json"
        run_manifest_path = "data/run/cesnet/run_manifest.json"
        payloads = {
            enriched_path: b'{"mapping_source":"${REPOSITORY_ROOT}"}\n',
            fingerprint_path: json.dumps(
                {
                    "inputs": {
                        "enriched_hosts": {
                            "sha256": "stale",
                        }
                    }
                }
            ).encode(),
            run_manifest_path: json.dumps(
                {
                    "post_evaluations": [
                        {
                            "name": "cesnet_os_fingerprint_validation",
                            "output_sha256": "stale",
                        }
                    ]
                }
            ).encode(),
        }

        builder._repair_packaged_checksum_references(payloads)

        fingerprint = json.loads(payloads[fingerprint_path])
        run_manifest = json.loads(payloads[run_manifest_path])
        self.assertEqual(
            fingerprint["inputs"]["enriched_hosts"]["sha256"],
            hashlib.sha256(payloads[enriched_path]).hexdigest(),
        )
        self.assertEqual(
            run_manifest["post_evaluations"][0]["output_sha256"],
            hashlib.sha256(payloads[fingerprint_path]).hexdigest(),
        )

    def test_archive_is_deterministic_and_contains_only_selected_dataset_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_file = root / "README.md"
            project_file.write_text(
                f"# Test project\n\nLocal root: {root.resolve()}\n",
                encoding="utf-8",
            )

            source_archive = root / "cesnet.zip"
            with zipfile.ZipFile(source_archive, "w") as source:
                for index, member in enumerate(builder.DATASET_MEMBERS):
                    source.writestr(member, f"fixture-{index}\n".encode())
                source.writestr("unused/large-capture.pcap", b"not selected")

            expected_md5 = hashlib.md5(source_archive.read_bytes()).hexdigest()
            output_a = root / "appendix-a.zip"
            output_b = root / "appendix-b.zip"
            with (
                patch.object(builder, "EXPECTED_DATASET_MD5", expected_md5),
                patch.object(builder, "_project_files", return_value=[project_file]),
            ):
                result_a = builder.build_archive(root, source_archive, output_a)
                result_b = builder.build_archive(root, source_archive, output_b)

            self.assertEqual(result_a["sha256"], result_b["sha256"])
            self.assertEqual(output_a.read_bytes(), output_b.read_bytes())

            prefix = f"{builder.ARCHIVE_PREFIX}/"
            with zipfile.ZipFile(output_a) as built:
                names = set(built.namelist())
                self.assertTrue(
                    all(info.create_system == 3 for info in built.infolist())
                )
                self.assertIn(f"{prefix}APPENDIX_MANIFEST.json", names)
                self.assertIn(f"{prefix}data/evaluation/cesnet/merged_tls.csv", names)
                self.assertIn(
                    f"{prefix}data/evaluation/cesnet/debian10_traffic_sample.pcap",
                    names,
                )
                self.assertNotIn(f"{prefix}unused/large-capture.pcap", names)
                packaged_readme = built.read(f"{prefix}README.md").decode()
                manifest = json.loads(
                    built.read(f"{prefix}APPENDIX_MANIFEST.json")
                )

            self.assertIn("${REPOSITORY_ROOT}", packaged_readme)
            self.assertNotIn(str(root.resolve()), packaged_readme)
            self.assertFalse(manifest["dataset"]["full_archive_included"])
            self.assertEqual(
                manifest["dataset"]["evaluation_selection"],
                "first 2000 rows of merged_tls.csv in source order",
            )

    def test_output_cannot_overwrite_the_source_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_file = root / "README.md"
            project_file.write_text("# Test\n", encoding="utf-8")
            source_archive = root / "cesnet.zip"
            source_archive.write_bytes(b"source")

            with patch.object(
                builder,
                "_project_files",
                return_value=[project_file],
            ):
                with self.assertRaisesRegex(ValueError, "must not overwrite"):
                    builder.build_archive(
                        root,
                        source_archive,
                        source_archive,
                    )


if __name__ == "__main__":
    unittest.main()
