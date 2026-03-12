from __future__ import annotations

import sys
from pathlib import Path
import unittest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from review_pipeline import review_source


class ReviewPipelineTests(unittest.TestCase):
    def test_review_source_returns_three_stage_payload(self) -> None:
        result = review_source(
            code='query = "SELECT * FROM users WHERE id=" + user_input\n',
            filename="demo.py",
            language="python",
        )

        stage_ids = [stage["id"] for stage in result["review_stages"]]
        self.assertEqual(
            stage_ids,
            [
                "stage_1_statistical_analysis",
                "stage_2_gemini_ai_review",
                "stage_3_owasp_correlation",
            ],
        )
        self.assertGreaterEqual(result["total_vulnerabilities"], 1)
        self.assertIn("average_confidence", result)
        self.assertGreaterEqual(result["statistics"]["average_confidence"], 0)


if __name__ == "__main__":
    unittest.main()
