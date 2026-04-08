from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from socketai_reproduce.prescreener.codeql import (
    CodeQLPrescreener,
    CodeQLSetupError,
    build_sanitized_codeql_env,
    parse_sarif_findings,
    sanitize_proxy_value,
)


class CodeQLPrescreenerTests(unittest.TestCase):
    def test_missing_codeql_binary_raises_setup_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp) / "pkg"
            package_root.mkdir()
            with mock.patch("socketai_reproduce.prescreener.codeql.resolve_codeql_bin", return_value=None):
                prescreener = CodeQLPrescreener()
                with self.assertRaises(CodeQLSetupError):
                    prescreener.screen(package_root, Path(tmp) / "out")

    def test_parse_sarif_findings_maps_to_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp) / "pkg"
            package_root.mkdir()
            target = package_root / "scripts" / "postinstall.js"
            target.parent.mkdir()
            target.write_text("console.log('hi')", encoding="utf-8")
            sarif_path = Path(tmp) / "results.sarif"
            sarif_path.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "results": [
                                    {
                                        "ruleId": "socketai/js/suspicious-exec",
                                        "message": {"text": "Potential execution"},
                                        "level": "warning",
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "scripts/postinstall.js"},
                                                    "region": {"startLine": 1, "startColumn": 1},
                                                }
                                            }
                                        ],
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            findings = parse_sarif_findings(sarif_path, package_root)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].file_path, "scripts/postinstall.js")
            self.assertEqual(findings[0].rule_id, "socketai/js/suspicious-exec")

    def test_screen_uses_absolute_paths_for_database_and_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            package_root = repo_root / "artifacts" / "pkg"
            package_root.mkdir(parents=True)
            query_root = repo_root / "queries"
            query_root.mkdir()
            (query_root / "qlpack.yml").write_text(
                "name: test/queries\nversion: 0.0.1\ndependencies:\n  codeql/javascript-all: \"*\"\n",
                encoding="utf-8",
            )
            (query_root / "suite.qls").write_text("- query: demo.ql\n", encoding="utf-8")
            relative_output_dir = Path("result") / "runs" / "sample-run" / "codeql"
            recorded_commands: list[list[str]] = []

            with mock.patch(
                "socketai_reproduce.prescreener.codeql.resolve_codeql_bin",
                return_value="codeql",
            ):
                prescreener = CodeQLPrescreener(query_suite=query_root / "suite.qls")

                def fake_run(command: list[str], cwd: Path) -> None:
                    recorded_commands.append(command)
                    if command[1:3] == ["pack", "install"]:
                        self.assertEqual(cwd, query_root.resolve())
                    else:
                        self.assertEqual(cwd, package_root.resolve())

                with mock.patch.object(prescreener, "_run_command", side_effect=fake_run):
                    result = prescreener.screen(package_root, relative_output_dir)

            self.assertEqual(len(recorded_commands), 3)
            self.assertEqual(recorded_commands[0][1:3], ["pack", "install"])
            self.assertTrue(Path(recorded_commands[0][4]).is_absolute())
            database_arg = Path(recorded_commands[1][3])
            analyze_database_arg = Path(recorded_commands[2][3])
            output_arg = next(
                part.split("=", 1)[1]
                for part in recorded_commands[2]
                if part.startswith("--output=")
            )
            self.assertTrue(database_arg.is_absolute())
            self.assertTrue(analyze_database_arg.is_absolute())
            self.assertTrue(Path(output_arg).is_absolute())
            self.assertEqual(Path(result.database_path), database_arg)
            self.assertEqual(Path(result.results_path), Path(output_arg))

    def test_sanitize_proxy_value_strips_smart_quotes(self) -> None:
        self.assertEqual(
            sanitize_proxy_value("“http://127.0.0.1:10808”"),
            "http://127.0.0.1:10808",
        )
        self.assertIsNone(sanitize_proxy_value("not-a-valid-proxy"))

    def test_build_sanitized_codeql_env_removes_invalid_proxy_values(self) -> None:
        env = build_sanitized_codeql_env(
            {
                "HTTP_PROXY": "“http://127.0.0.1:10808”",
                "HTTPS_PROXY": "bad proxy",
                "PATH": "C:\\tools",
            }
        )
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:10808")
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertEqual(env["PATH"], "C:\\tools")


if __name__ == "__main__":
    unittest.main()
