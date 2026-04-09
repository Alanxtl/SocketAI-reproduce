from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from typer.testing import CliRunner

from socketai_reproduce.analysis.models import CodeQLResult, PackageSummary, RunMetadata, RunMetrics, RunResult
from socketai_reproduce.cli import app, build_batch_progress_description
from socketai_reproduce.config import build_run_id, utc_now_iso
from socketai_reproduce.prescreener import CodeQLSetupError
from socketai_reproduce.reporting.exporters import export_run_result


class AlwaysFailWorkflow:
    def detect(self, input_path: Path, output_root: Path):  # noqa: ANN201
        del input_path, output_root
        raise CodeQLSetupError("CodeQL missing in test")


class AlwaysOSErrorWorkflow:
    def detect(self, input_path: Path, output_root: Path):  # noqa: ANN201
        del input_path, output_root
        raise OSError("Path too long in test")


class FirstSuccessThenInterruptWorkflow:
    def __init__(self) -> None:
        self.calls = 0

    def detect(self, input_path: Path, output_root: Path):  # noqa: ANN201
        self.calls += 1
        if self.calls == 1:
            run_id = build_run_id(input_path)
            run_dir = Path(output_root) / run_id
            result = RunResult(
                run_meta=RunMetadata(
                    run_id=run_id,
                    timestamp_utc=utc_now_iso(),
                    input_path=str(input_path.resolve()),
                    output_dir=str(run_dir),
                    model="fake-model",
                    provider="fake-provider",
                    temperature=0.0,
                    threshold=0.5,
                    use_codeql=False,
                    package_name=input_path.stem,
                    package_root=str(input_path.resolve()),
                ),
                package_summary=PackageSummary(
                    package_name=input_path.stem,
                    package_version=None,
                    input_path=str(input_path.resolve()),
                    package_root=str(input_path.resolve()),
                    run_id=run_id,
                    label="benign",
                    threshold=0.5,
                    max_file_score=0.1,
                    flagged_file_count=0,
                    top_k_suspicious_files=[],
                    decision_reason="checkpoint test",
                    total_files=0,
                    analyzed_files=0,
                    status="success",
                ),
                files=[],
                codeql=CodeQLResult(enabled=False, status="disabled"),
                metrics=RunMetrics(),
            )
            export_run_result(result, run_dir)
            return result
        raise KeyboardInterrupt("Simulated interruption after first completed sample.")


class CliBatchTests(unittest.TestCase):
    def test_batch_writes_setup_error_instead_of_aborting(self) -> None:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp) / "pkg"
            package_root.mkdir()
            (package_root / "package.json").write_text(json.dumps({"name": "demo"}), encoding="utf-8")

            manifest = Path(tmp) / "manifest.jsonl"
            manifest.write_text(
                json.dumps({"input": str(package_root)}) + "\n",
                encoding="utf-8",
            )

            with mock.patch("socketai_reproduce.cli.build_workflow", return_value=AlwaysFailWorkflow()):
                result = runner.invoke(
                    app,
                    [
                        "batch",
                        "--manifest",
                        str(manifest),
                        "--model",
                        "fake-model",
                        "--output-dir",
                        str(Path(tmp) / "batch-output"),
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.stdout)
            package_level_exports = list((Path(tmp) / "batch-output").rglob("package_level.csv"))
            self.assertTrue(package_level_exports)
            with package_level_exports[0].open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["status"], "setup_error")

    def test_batch_writes_oserror_as_sample_error_instead_of_aborting(self) -> None:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp) / "pkg"
            package_root.mkdir()
            (package_root / "package.json").write_text(json.dumps({"name": "demo"}), encoding="utf-8")

            manifest = Path(tmp) / "manifest.jsonl"
            manifest.write_text(
                json.dumps({"input": str(package_root)}) + "\n",
                encoding="utf-8",
            )

            with mock.patch("socketai_reproduce.cli.build_workflow", return_value=AlwaysOSErrorWorkflow()):
                result = runner.invoke(
                    app,
                    [
                        "batch",
                        "--manifest",
                        str(manifest),
                        "--model",
                        "fake-model",
                        "--output-dir",
                        str(Path(tmp) / "batch-output"),
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.stdout)
            package_level_exports = list((Path(tmp) / "batch-output").rglob("package_level.csv"))
            self.assertTrue(package_level_exports)
            with package_level_exports[0].open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["status"], "error")
            self.assertEqual(rows[0]["error_type"], "workflow_error")

    def test_batch_checkpoints_completed_results_before_interrupt(self) -> None:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            package_one = Path(tmp) / "pkg-one"
            package_two = Path(tmp) / "pkg-two"
            package_one.mkdir()
            package_two.mkdir()
            (package_one / "package.json").write_text(json.dumps({"name": "one"}), encoding="utf-8")
            (package_two / "package.json").write_text(json.dumps({"name": "two"}), encoding="utf-8")

            manifest = Path(tmp) / "manifest.jsonl"
            manifest.write_text(
                "\n".join(
                    [
                        json.dumps({"input": str(package_one)}),
                        json.dumps({"input": str(package_two)}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            workflow = FirstSuccessThenInterruptWorkflow()
            with mock.patch("socketai_reproduce.cli.build_workflow", return_value=workflow):
                result = runner.invoke(
                    app,
                    [
                        "batch",
                        "--manifest",
                        str(manifest),
                        "--model",
                        "fake-model",
                        "--output-dir",
                        str(Path(tmp) / "batch-output"),
                    ],
                )

            self.assertEqual(result.exit_code, 130)

            batch_meta_files = list((Path(tmp) / "batch-output").rglob("batch_meta.json"))
            self.assertTrue(batch_meta_files)
            batch_meta = json.loads(batch_meta_files[0].read_text(encoding="utf-8"))
            self.assertEqual(batch_meta["status"], "running")
            self.assertEqual(batch_meta["packages_completed"], 1)
            self.assertEqual(batch_meta["packages_total"], 2)

            package_level_exports = list((Path(tmp) / "batch-output").rglob("package_level.csv"))
            self.assertTrue(package_level_exports)
            with package_level_exports[0].open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["package_name"], "pkg-one")

    def test_load_manifest_entries_accepts_utf8_bom_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.jsonl"
            manifest.write_text(
                '\ufeff{"input": "C:/tmp/sample.tgz"}\n',
                encoding="utf-8",
            )

            from socketai_reproduce.cli import load_manifest_entries

            rows = load_manifest_entries(manifest)

            self.assertEqual(rows, [{"input": "C:/tmp/sample.tgz"}])

    def test_build_batch_progress_description_truncates_long_names(self) -> None:
        description = build_batch_progress_description(
            Path("C:/tmp/" + "a" * 80 + ".tgz"),
            max_length=20,
        )

        self.assertTrue(description.startswith("Analyzing "))
        self.assertTrue(description.endswith("..."))


if __name__ == "__main__":
    unittest.main()
