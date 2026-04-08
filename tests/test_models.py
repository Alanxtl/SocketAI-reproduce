from __future__ import annotations

import unittest

from socketai_reproduce.analysis.models import CriticalFileAssessment


class AnalysisModelTests(unittest.TestCase):
    def test_critical_file_assessment_accepts_string_changes_made(self) -> None:
        assessment = CriticalFileAssessment.model_validate(
            {
                "label": "malicious",
                "score": 0.9,
                "confidence": 0.8,
                "suspicious_behaviors": "exec",
                "reasoning_summary": "Downloads and executes content.",
                "changes_made": "Raised the score after reconsidering the evidence.",
            }
        )

        self.assertEqual(assessment.suspicious_behaviors, ["exec"])
        self.assertEqual(
            assessment.changes_made,
            ["Raised the score after reconsidering the evidence."],
        )


if __name__ == "__main__":
    unittest.main()
