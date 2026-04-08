from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from typer.testing import CliRunner

from socketai_reproduce.cli import app
from socketai_reproduce.prescreener import CodeQLSetupError


class AlwaysFailWorkflow:
    def detect(self, input_path: Path, output_root: Path):  # noqa: ANN201
        del input_path, output_root
        raise CodeQLSetupError("CodeQL missing in test")


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


if __name__ == "__main__":
    unittest.main()
