from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from socketai_reproduce.prescreener.codeql import (
    CodeQLPrescreener,
    CodeQLSetupError,
    parse_sarif_findings,
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


if __name__ == "__main__":
    unittest.main()
