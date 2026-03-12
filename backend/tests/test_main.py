from __future__ import annotations

import sys
from pathlib import Path
import unittest

from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import main


class MainApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_api_token = main.API_TOKEN
        self.client = TestClient(main.app)

    def tearDown(self) -> None:
        main.API_TOKEN = self.original_api_token

    def test_parse_github_url_supports_tree_branch(self) -> None:
        owner, repo, branch = main._parse_github_url("https://github.com/octocat/Hello-World/tree/feature/demo")
        self.assertEqual(owner, "octocat")
        self.assertEqual(repo, "Hello-World")
        self.assertEqual(branch, "feature/demo")

    def test_api_token_is_enforced_when_configured(self) -> None:
        main.API_TOKEN = "topsecret"

        unauthorized = self.client.post("/scan", json={"code": "print('hello')"})
        self.assertEqual(unauthorized.status_code, 401)

        authorized = self.client.post(
            "/scan",
            json={"code": "print('hello')"},
            headers={"Authorization": "Bearer topsecret"},
        )
        self.assertEqual(authorized.status_code, 200)

    def test_create_scan_job_returns_queued_status(self) -> None:
        scheduled: dict[str, bool] = {}
        original_schedule = main._schedule_scan_task
        main.API_TOKEN = ""

        def fake_schedule_scan_task(coroutine) -> None:
            scheduled["called"] = True
            coroutine.close()

        try:
            main._schedule_scan_task = fake_schedule_scan_task
            response = self.client.post(
                "/scan-github/jobs",
                json={"repo_url": "https://github.com/octocat/Hello-World", "branch": "main"},
            )
        finally:
            main._schedule_scan_task = original_schedule

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "queued")
        self.assertEqual(payload["kind"], "github_repository_scan")
        self.assertTrue(scheduled["called"])


if __name__ == "__main__":
    unittest.main()
