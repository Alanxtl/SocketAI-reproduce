from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import json
from pathlib import Path
from unittest import mock

import pandas as pd


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "plot_batch_results.py"


def load_plot_module(module_name: str, fake_home: Path):
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Unable to load module spec for {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(Path, "home", return_value=fake_home):
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(fake_home / "missing_codex")}, clear=False):
            spec.loader.exec_module(module)
    return module


class PlotBatchResultsTests(unittest.TestCase):
    def test_import_uses_builtin_visualization_fallback_without_skill_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module = load_plot_module("plot_batch_results_fallback", Path(tmp))

        self.assertEqual(module.OKABE_ITO_LIST[0], "#E69F00")
        self.assertTrue(callable(module.apply_publication_style))
        self.assertTrue(callable(module.save_publication_figure))

    def test_resolve_cohort_totals_uses_package_rows_when_manifest_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module = load_plot_module("plot_batch_results_cohorts", Path(tmp))

        package_df = pd.DataFrame({"cohort": ["p0-100", "p0-33", "p0-100", "unknown"]})

        self.assertEqual(
            module.resolve_cohort_totals({}, package_df),
            {"p0-33": 1, "p0-100": 2, "unknown": 1},
        )

    def test_load_rows_accepts_gb18030_jsonl_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module = load_plot_module("plot_batch_results_encodings", Path(tmp))
            labels_path = Path(tmp) / "labels.jsonl"
            row = {
                "archive_name": "sample.tgz",
                "bin_label": "p0-33",
                "annotation": {
                    "verdict": "malicious",
                    "reason": "contains 中文 label text",
                },
            }
            labels_path.write_bytes((json.dumps(row, ensure_ascii=False) + "\n").encode("gb18030"))

            rows = module.load_rows(labels_path)

            self.assertEqual(rows[0]["archive_name"], "sample.tgz")
            self.assertEqual(rows[0]["annotation"]["verdict"], "malicious")


if __name__ == "__main__":
    unittest.main()
