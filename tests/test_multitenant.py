import atexit
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

_BOOT_DATA = tempfile.TemporaryDirectory()
atexit.register(_BOOT_DATA.cleanup)
os.environ["LOGMASK_DATA"] = _BOOT_DATA.name
os.environ["LOGMASK_ADMIN_PASSWORD"] = "Bootstrap-Password-2026!"

import app as webapp
from auth import AuthStore
from logmask import (
    ORDER,
    Anonymizer,
    Deanonymizer,
    LEGACY_TENANT,
    Options,
    Vault,
    derive_tenant_master,
    normalize_tenant_id,
    tenant_vault_path,
)


class TenantPrimitiveTests(unittest.TestCase):
    def test_tenant_validation_rejects_path_traversal(self):
        for value in ("", "a", "../client", ".hidden", "client/other", "CLIENT SPACE"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_tenant_id(value)

    def test_same_value_is_isolated_between_tenants(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            master = b"M" * 32
            outputs = {}
            for tenant in ("cliente-a", "cliente-b"):
                path = tenant_vault_path(root / "vault.db", tenant)
                vault = Vault(path, derive_tenant_master(master, tenant))
                anon = Anonymizer(vault, set(ORDER), Options())
                outputs[tenant] = anon.process("user=mrossi email=mrossi@example.com")
                vault.commit()
                vault.db.close()
            self.assertNotEqual(outputs["cliente-a"], outputs["cliente-b"])
            vault_a = Vault(tenant_vault_path(root / "vault.db", "cliente-a"), derive_tenant_master(master, "cliente-a"))
            vault_b = Vault(tenant_vault_path(root / "vault.db", "cliente-b"), derive_tenant_master(master, "cliente-b"))
            self.addCleanup(vault_a.db.close)
            self.addCleanup(vault_b.db.close)
            self.assertIn("mrossi", Deanonymizer(vault_a, Options()).process(outputs["cliente-a"]))
            self.assertEqual(Deanonymizer(vault_b, Options()).process(outputs["cliente-a"]), outputs["cliente-a"])

    def test_legacy_keeps_original_vault_and_master(self):
        base = Path("/tmp/example/vault.db")
        master = b"L" * 32
        self.assertEqual(tenant_vault_path(base, LEGACY_TENANT), base)
        self.assertEqual(derive_tenant_master(master, LEGACY_TENANT), master)


class TenantApiTests(unittest.TestCase):
    ADMIN_PASSWORD = "Bootstrap-Testing-Password-2026!"

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        root = Path(self.tmpdir.name)
        webapp.DATA = root
        webapp.KEY_PATH = root / "master.key"
        webapp.VAULT_PATH = root / "vault.db"
        webapp.TENANTS_DIR = root / "tenants"
        webapp.AUTH_PATH = root / "auth.db"
        webapp.BOOTSTRAP_FILE = root / "bootstrap-admin.txt"
        webapp.MASTER = b"A" * 32
        webapp.AUTH = AuthStore(root / "auth.db")
        webapp.AUTH.bootstrap_admin("admin", self.ADMIN_PASSWORD, webapp.BOOTSTRAP_FILE)
        self.client = TestClient(webapp.app)
        self.login("admin", self.ADMIN_PASSWORD)
        self.change_password(self.ADMIN_PASSWORD, "Personal-Secure-Password-2026!")

    def tearDown(self):
        self.tmpdir.cleanup()

    def csrf(self):
        return self.client.cookies.get(webapp.CSRF_COOKIE)

    def post(self, path, json):
        return self.client.post(path, json=json, headers={"X-CSRF-Token": self.csrf()})

    def patch(self, path, json):
        return self.client.patch(path, json=json, headers={"X-CSRF-Token": self.csrf()})

    def login(self, username, password):
        response = self.client.post("/api/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def change_password(self, current, new):
        response = self.post("/api/change-password", {"current_password": current, "new_password": new})
        self.assertEqual(response.status_code, 200, response.text)

    def anonymize(self, tenant: str):
        response = self.post(
            "/api/anonymize",
            {
                "tenant": tenant,
                "text": "user=mrossi email mrossi@example.com host srv-01.example.com",
                "format": "text",
                "safe_mode": True,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()


    def test_server_enforces_configured_upload_limit(self):
        previous = webapp.MAX_FILE_BYTES
        webapp.MAX_FILE_BYTES = 16
        try:
            response = self.post(
                "/api/anonymize",
                {
                    "tenant": "cliente-limit",
                    "text": "user=mrossi and more data",
                    "format": "text",
                    "source": "upload:.txt",
                },
            )
            self.assertEqual(response.status_code, 413, response.text)
        finally:
            webapp.MAX_FILE_BYTES = previous

    def test_me_advertises_file_and_body_limits(self):
        payload = self.client.get("/api/me").json()
        self.assertEqual(payload["max_file_bytes"], webapp.MAX_FILE_BYTES)
        self.assertEqual(payload["max_body_bytes"], webapp.MAX_BODY_BYTES)
        self.assertGreater(payload["max_body_bytes"], payload["max_file_bytes"])

    def test_csv_upload_round_trip_through_api(self):
        source = 'user_email,description\nmrossi@example.com,"hello, world"\n'
        masked = self.post(
            "/api/anonymize",
            {
                "tenant": "cliente-csv",
                "text": source,
                "format": "csv",
                "safe_mode": True,
                "source": "upload:.csv",
            },
        )
        self.assertEqual(masked.status_code, 200, masked.text)
        restored = self.post(
            "/api/deanonymize",
            {"tenant": "cliente-csv", "text": masked.json()["output"], "format": "csv"},
        )
        self.assertEqual(restored.status_code, 200, restored.text)
        import csv
        import io
        rows = list(csv.reader(io.StringIO(restored.json()["output"])))
        self.assertEqual(rows[1], ["mrossi@example.com", "hello, world"])

    def test_api_internal_ip_policy_masks_only_internal_addresses(self):
        response = self.post(
            "/api/anonymize",
            {
                "tenant": "cliente-ip-policy",
                "text": "src=192.168.1.10 dst=8.8.8.8 ipv6=fd12::10 public6=2001:4860:4860::8888",
                "format": "text",
                "ip_mode": "internal",
                "safe_mode": True,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["ip_mode"], "internal")
        self.assertNotIn("192.168.1.10", payload["output"])
        self.assertNotIn("fd12::10", payload["output"])
        self.assertIn("8.8.8.8", payload["output"])
        self.assertIn("2001:4860:4860::8888", payload["output"])
        self.assertEqual(payload["policy_kept"], 2)
        self.assertFalse(payload["blocked"])

    def test_api_prevents_cross_tenant_reverse(self):
        alpha = self.anonymize("cliente-alpha")
        beta = self.anonymize("cliente-beta")
        self.assertNotEqual(alpha["output"], beta["output"])
        correct = self.post("/api/deanonymize", {"tenant": "cliente-alpha", "text": alpha["output"]})
        self.assertEqual(correct.status_code, 200)
        self.assertIn("mrossi", correct.json()["output"])
        wrong = self.post("/api/deanonymize", {"tenant": "cliente-beta", "text": alpha["output"]})
        self.assertEqual(wrong.status_code, 200)
        self.assertEqual(wrong.json()["output"], alpha["output"])

    def test_stats_for_unknown_tenant_does_not_create_vault(self):
        response = self.client.get("/api/stats", params={"tenant": "cliente-nuovo"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["kinds"], [])
        self.assertFalse((webapp.TENANTS_DIR / "cliente-nuovo" / "vault.db").exists())

    def test_operator_is_tenant_scoped_and_cannot_reverse(self):
        created = self.post(
            "/api/admin/users",
            {
                "username": "operatore",
                "password": "Temporary-Access-Password-2026!",
                "role": "operator",
                "tenants": ["cliente-alpha"],
            },
        )
        self.assertEqual(created.status_code, 200, created.text)
        self.post("/api/logout", {})
        self.login("operatore", "Temporary-Access-Password-2026!")
        self.change_password("Temporary-Access-Password-2026!", "Personal-Access-Password-2026!")

        allowed = self.post(
            "/api/anonymize",
            {"tenant": "cliente-alpha", "text": "user=mrossi", "format": "text"},
        )
        self.assertEqual(allowed.status_code, 200, allowed.text)
        denied_tenant = self.post(
            "/api/anonymize",
            {"tenant": "cliente-beta", "text": "user=mrossi", "format": "text"},
        )
        self.assertEqual(denied_tenant.status_code, 403)
        denied_reverse = self.post(
            "/api/deanonymize",
            {"tenant": "cliente-alpha", "text": allowed.json()["output"]},
        )
        self.assertEqual(denied_reverse.status_code, 403)
        denied_stats = self.client.get("/api/stats", params={"tenant": "cliente-alpha"})
        self.assertEqual(denied_stats.status_code, 403)

    def test_reverse_is_written_to_immutable_audit(self):
        masked = self.anonymize("cliente-alpha")["output"]
        reversed_response = self.post("/api/deanonymize", {"tenant": "cliente-alpha", "text": masked})
        self.assertEqual(reversed_response.status_code, 200)
        events = self.client.get("/api/admin/audit", params={"limit": 50}).json()["events"]
        reverse = next(e for e in events if e["action"] == "reverse")
        self.assertTrue(reverse["success"])
        self.assertEqual(reverse["tenant"], "cliente-alpha")
        self.assertGreater(reverse["details"]["resolved"], 0)
        import sqlite3
        db = sqlite3.connect(webapp.AUTH_PATH)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE audit SET success=0 WHERE id=?", (reverse["id"],))
        db.close()

    def test_csrf_is_required(self):
        response = self.client.post(
            "/api/anonymize",
            json={"tenant": "cliente-alpha", "text": "user=mrossi", "format": "text"},
        )
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_endpoints_are_closed(self):
        anonymous = TestClient(webapp.app)
        self.assertEqual(anonymous.get("/api/tenants").status_code, 401)
        response = anonymous.post(
            "/api/anonymize",
            json={"tenant": "cliente-alpha", "text": "user=mrossi", "format": "text"},
        )
        self.assertEqual(response.status_code, 401)

    def test_logout_revokes_session(self):
        response = self.post("/api/logout", {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/me").status_code, 401)


if __name__ == "__main__":
    unittest.main()
