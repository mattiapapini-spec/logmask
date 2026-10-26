"""v0.21.0 — azzeramento del vault di un tenant.

Il vault e' l'unica cosa che rende reversibili gli export gia' condivisi:
azzerarlo per sbaglio significa non poter piu' risalire da uno pseudonimo al
valore originale. Per questo il file viene ARCHIVIATO con un timestamp, non
cancellato, e l'operazione richiede di ripetere il nome del tenant.
"""
import tempfile
import unittest
from pathlib import Path


class VaultResetEndpointTests(unittest.TestCase):
    ADMIN_PASSWORD = "Bootstrap-Reset-Root-2026!"

    def setUp(self):
        from fastapi.testclient import TestClient
        import app as webapp
        from auth import AuthStore
        self.webapp = webapp
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
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
        self.client.post("/api/login",
                         json={"username": "admin", "password": self.ADMIN_PASSWORD})
        self.client.post("/api/change-password", headers={"X-CSRF-Token": self._csrf()},
                         json={"current_password": self.ADMIN_PASSWORD,
                               "new_password": "Reset-Personal-Password-2026!"})

    def tearDown(self):
        self.tmp.cleanup()

    def _csrf(self):
        return self.client.cookies.get(self.webapp.CSRF_COOKIE)

    def _anonymize(self, tenant="acme"):
        return self.client.post("/api/anonymize", headers={"X-CSRF-Token": self._csrf()},
                                json={"tenant": tenant, "text": "user=mrossi host=web01",
                                      "format": "text"})

    def _reset(self, tenant, confirm):
        return self.client.post("/api/admin/vault/reset",
                                headers={"X-CSRF-Token": self._csrf()},
                                json={"tenant": tenant, "confirm": confirm})

    def test_confirmation_must_match(self):
        self._anonymize()
        r = self._reset("acme", "sbagliato")
        self.assertEqual(r.status_code, 400)

    def test_vault_is_archived_not_deleted(self):
        self._anonymize()
        vault_path = self.webapp.TENANTS_DIR / "acme" / "vault.db"
        self.assertTrue(vault_path.exists())
        r = self._reset("acme", "acme")
        self.assertEqual(r.status_code, 200, r.text)
        archived = r.json()["archived_as"]
        self.assertTrue(archived and archived.startswith("vault-"))
        self.assertFalse(vault_path.exists())                  # spostato
        self.assertTrue((vault_path.parent / archived).exists())  # ma recuperabile

    def test_tokens_stay_stable_after_reset(self):
        """La derivazione e' deterministica: dopo l'azzeramento lo stesso valore
        produce lo stesso token, quindi la correlazione con gli export
        precedenti non si perde. Si perde solo la reversibilita'."""
        before = self._anonymize().json()["output"]
        self._reset("acme", "acme")
        after = self._anonymize().json()["output"]
        self.assertEqual(before, after)

    def test_reverse_no_longer_possible_after_reset(self):
        masked = self._anonymize().json()["output"]
        self._reset("acme", "acme")
        r = self.client.post("/api/deanonymize", headers={"X-CSRF-Token": self._csrf()},
                             json={"tenant": "acme", "text": masked, "format": "text"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["resolved"], 0)

    def test_requires_admin(self):
        from fastapi.testclient import TestClient
        self.webapp.AUTH.create_user(username="an1", password="Analyst-Password-2026!",
                                     role="analyst", tenants=["acme"],
                                     must_change_password=False)
        other = TestClient(self.webapp.app)
        other.post("/api/login", json={"username": "an1", "password": "Analyst-Password-2026!"})
        r = other.post("/api/admin/vault/reset",
                       headers={"X-CSRF-Token": other.cookies.get(self.webapp.CSRF_COOKIE)},
                       json={"tenant": "acme", "confirm": "acme"})
        self.assertEqual(r.status_code, 403)

    def test_requires_csrf(self):
        r = self.client.post("/api/admin/vault/reset",
                             json={"tenant": "acme", "confirm": "acme"})
        self.assertIn(r.status_code, (401, 403))

    def test_audited(self):
        self._anonymize()
        self._reset("acme", "acme")
        events = self.client.get("/api/admin/audit?limit=20").json()["events"]
        self.assertIn("vault_reset", [e["action"] for e in events])

    def test_reset_without_existing_vault_is_harmless(self):
        r = self._reset("acme", "acme")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(r.json()["archived_as"])


if __name__ == "__main__":
    unittest.main()
