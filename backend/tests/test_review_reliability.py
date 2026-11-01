import unittest

from fastapi.testclient import TestClient

from app.scanner_api import app as scanner_app
from app.webhook_main import app as webhook_app


class ReliabilityTests(unittest.TestCase):
    def test_public_webhook_app_exposes_no_operator_routes(self):
        client = TestClient(webhook_app)
        self.assertEqual(client.get("/docs").status_code, 404)
        self.assertEqual(client.get("/openapi.json").status_code, 404)
        self.assertEqual(client.get("/health").status_code, 404)
        response = client.get("/api/v1/manual-reviews/00000000-0000-0000-0000-000000000000")
        self.assertEqual(response.status_code, 404)
        self.assertIn(client.post("/api/v1/webhooks/github").status_code, (401, 503))

    def test_scanner_service_rejects_arbitrary_directory(self):
        client = TestClient(scanner_app)
        response = client.post(
            "/scan",
            json={"directory": "../backend", "paths": ["app.py"], "commit_sha": "a" * 40},
        )
        self.assertEqual(response.status_code, 422)

if __name__ == "__main__":
    unittest.main()
