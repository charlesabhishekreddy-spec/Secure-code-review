from __future__ import annotations

import sys
from pathlib import Path
import unittest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from scanner import scan_code_with_metadata


class ScannerTests(unittest.TestCase):
    def test_python_scan_merges_regex_and_ast_evidence(self) -> None:
        payload = scan_code_with_metadata(
            code='query = "SELECT * FROM users WHERE id=" + user_input\n',
            filename="demo.py",
            language="python",
        )

        findings = payload["findings"]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["type"], "SQL Injection")
        self.assertIn("regex", finding["detection_methods"])
        self.assertIn("python-ast", finding["detection_methods"])
        self.assertGreater(finding["confidence"], 88)

    def test_javascript_flow_heuristics_detect_tainted_xss(self) -> None:
        payload = scan_code_with_metadata(
            code="const value = req.query.name;\nelement.innerHTML = value;\n",
            filename="demo.js",
            language="javascript",
        )

        finding_types = [finding["type"] for finding in payload["findings"]]
        self.assertIn("Cross Site Scripting (XSS)", finding_types)


if __name__ == "__main__":
    unittest.main()
