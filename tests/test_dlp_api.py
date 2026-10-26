import atexit
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

_BOOT = tempfile.TemporaryDirectory()
atexit.register(_BOOT.cleanup)
os.environ.setdefault("LOGMASK_DATA", _BOOT.name)
os.environ.setdefault("LOGMASK_ADMIN_PASSWORD", "Dlp-Bootstrap-Password-2026!")

import app as webapp
from auth import AuthStore


class DlpApiTests(unittest.TestCase):
    ADMIN_PASSWORD = "Dlp-Temporary-Password-2026!"
    PERSONAL_PASSWORD = "Dlp-Personal-Password-2026!"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        webapp.DATA = root
        webapp.KEY_PATH = root / "master.key"
        webapp.VAULT_PATH = root / "vault.db"
        webapp.TENANTS_DIR = root / "tenants"
        webapp.AUTH_PATH = root / "auth.db"
        webapp.BOOTSTRAP_FILE = root / "bootstrap-admin.txt"
        webapp.MASTER = b"D" * 32
        webapp.AUTH = AuthStore(root / "auth.db")
        webapp.AUTH.bootstrap_admin("admin", self.ADMIN_PASSWORD, webapp.BOOTSTRAP_FILE)
        self.client = TestClient(webapp.app)
        login = self.client.post("/api/login", json={"username": "admin", "password": self.ADMIN_PASSWORD})
        self.assertEqual(login.status_code, 200, login.text)
        changed = self.post("/api/change-password", {
            "current_password": self.ADMIN_PASSWORD,
            "new_password": self.PERSONAL_PASSWORD,
        })
        self.assertEqual(changed.status_code, 200, changed.text)

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, path, payload):
        return self.client.post(
            path,
            headers={"X-CSRF-Token": self.client.cookies.get(webapp.CSRF_COOKIE)},
            json=payload,
        )

    def test_metadata_endpoint(self):
        response = self.client.get("/api/dlp-categories")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertIn("credentials", {item["id"] for item in body["categories"]})
        self.assertEqual(set(body["actions"]), {"pseudonymize", "redact", "block", "keep"})

    def test_default_policy_redacts_and_pseudonymizes(self):
        response = self.post("/api/anonymize", {
            "tenant": "cliente-dlp",
            "text": "nome: Mario Rossi password=SuperSecret123! iban: IT60X0542811101000000123456",
            "format": "text",
            "safe_mode": True,
            "ip_mode": "all",
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertFalse(body["blocked"])
        self.assertIn("person-", body["output"])
        self.assertIn("iban-", body["output"])
        self.assertIn("[ELIDED]", body["output"])
        self.assertNotIn("SuperSecret123!", body["output"])
        self.assertEqual(body["dlp"]["actions"]["redact"], 1)
        self.assertGreaterEqual(body["dlp"]["actions"]["pseudonymize"], 2)

    def test_block_action_blocks_output(self):
        key = "-----BEGIN PRIVATE KEY-----\nQUJDREVGRw==\n-----END PRIVATE KEY-----"
        response = self.post("/api/anonymize", {
            "tenant": "cliente-dlp",
            "text": key,
            "format": "text",
            "safe_mode": True,
            "dlp_policy": {"private_key": "block"},
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["blocked"])
        self.assertEqual(body["output"], key)
        self.assertEqual(body["dlp"]["blocked"]["private_key"], 1)

    def test_keep_action_allows_iban(self):
        iban = "IT60X0542811101000000123456"
        response = self.post("/api/anonymize", {
            "tenant": "cliente-dlp",
            "text": "iban: " + iban,
            "format": "text",
            "safe_mode": True,
            "dlp_policy": {"iban": "keep"},
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertFalse(body["blocked"])
        self.assertIn(iban, body["output"])

    def test_unknown_category_returns_400(self):
        response = self.post("/api/anonymize", {
            "tenant": "cliente-dlp",
            "text": "test",
            "format": "text",
            "dlp_policy": {"not-a-category": "redact"},
        })
        self.assertEqual(response.status_code, 400, response.text)


if __name__ == "__main__":
    unittest.main()
