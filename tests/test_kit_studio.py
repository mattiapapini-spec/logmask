"""v0.14.0 — kit studio: CRUD dei kit utente da API con validazione,
hot reload, RBAC admin e filename hardening."""
import tempfile
import unittest
from pathlib import Path

import vendor_kits as vk

GOOD_KIT = """id: studio_edr
label: Studio EDR
fingerprints:
  - {pattern: '^studio_agent_id$', weight: 8}
rules:
  - {pattern: '.*_ip$', action: mask, kind: ip}
  - {pattern: '^user$', action: mask, kind: user}
"""


class KitStudioApiTests(unittest.TestCase):
    ADMIN_PASSWORD = "Bootstrap-Studio-Root-2026!"

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
        self._orig_dir = vk.USER_KITS_DIR
        vk.USER_KITS_DIR = root / "kits"
        vk.force_reload()
        self.client = TestClient(webapp.app)
        self.client.post("/api/login", json={"username": "admin", "password": self.ADMIN_PASSWORD})
        self._csrf_change("Studio-Personal-Password-2026!")

    def tearDown(self):
        vk.USER_KITS_DIR = self._orig_dir
        vk.force_reload()
        self.tmp.cleanup()

    # -- helpers ------------------------------------------------------------
    def _csrf(self):
        return self.client.cookies.get(self.webapp.CSRF_COOKIE)

    def _csrf_change(self, new):
        self.client.post("/api/change-password", headers={"X-CSRF-Token": self._csrf()},
                         json={"current_password": self.ADMIN_PASSWORD, "new_password": new})

    def _put(self, name, content):
        return self.client.put(f"/api/kits/files/{name}", headers={"X-CSRF-Token": self._csrf()},
                               json={"content": content})

    # -- tests --------------------------------------------------------------
    def test_full_lifecycle_write_detect_delete(self):
        r = self._put("studio_edr.yaml", GOOD_KIT)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["report"]["ok"])
        # listed
        j = self.client.get("/api/kits/files").json()
        self.assertIn("studio_edr.yaml", [f["name"] for f in j["user_files"]])
        self.assertIn("studio_edr", [k["id"] for k in j["effective"]])
        # hot reload proves through dry-run detection
        d = self.client.post("/api/kit-dry-run", headers={"X-CSRF-Token": self._csrf()},
                             json={"columns": ["studio_agent_id", "src_ip", "user"]}).json()
        self.assertEqual(d["detected"]["id"], "studio_edr")
        # read back
        g = self.client.get("/api/kits/files/studio_edr.yaml")
        self.assertEqual(g.status_code, 200)
        self.assertIn("studio_agent_id", g.json()["content"])
        # delete -> gone from registry
        rd = self.client.delete("/api/kits/files/studio_edr.yaml",
                                headers={"X-CSRF-Token": self._csrf()})
        self.assertEqual(rd.status_code, 200, rd.text)
        self.assertNotIn("studio_edr", vk.KITS)

    def test_invalid_yaml_rejected_not_written(self):
        r = self._put("broken.yaml", "id: [unclosed")
        self.assertEqual(r.status_code, 400)
        self.assertFalse((Path(self.tmp.name) / "kits" / "broken.yaml").exists())

    def test_missing_id_rejected(self):
        r = self._put("noid.yaml", "rules: [{pattern: '^a$', action: keep}]")
        self.assertEqual(r.status_code, 400)

    def test_warnings_do_not_block_save(self):
        r = self._put("warn.yaml", "id: warnkit\nfingerprints: [{pattern: '^warn_fp$', weight: 8}]\n"
                                   "rules:\n  - {pattern: '^ok$', action: keep}\n"
                                   "  - {pattern: '^bad$', action: boom}\n")
        self.assertEqual(r.status_code, 200, r.text)
        rep = r.json()["report"]
        self.assertTrue(rep["warnings"])
        self.assertEqual(rep["kit"]["rules_kept"], 1)

    def test_filename_hardening(self):
        for bad in ("../evil.yaml", "..%2Fevil.yaml", "EVIL.yaml", "kit.txt", ".yaml", "a b.yaml"):
            r = self._put(bad, GOOD_KIT)
            self.assertIn(r.status_code, (400, 404), bad)
        base = Path(self.tmp.name)
        self.assertFalse(list(base.glob("**/evil.yaml")), "traversal wrote outside kits dir")

    def test_bundled_readonly_endpoints(self):
        g = self.client.get("/api/kits/bundled/cortex")
        self.assertEqual(g.status_code, 200)
        self.assertIn("id: cortex", g.json()["content"])
        # bundled file cannot be overwritten via the user endpoint (separate dir)
        self._put("cortex.yaml", "id: cortex\nmode: replace\nrules: [{pattern: '.*', action: keep}]")
        bundled = (vk.BUNDLED_KITS_DIR / "cortex.yaml").read_text(encoding="utf-8")
        self.assertNotIn("mode: replace", bundled)
        self.client.delete("/api/kits/files/cortex.yaml", headers={"X-CSRF-Token": self._csrf()})

    def test_validate_endpoint_reports_without_writing(self):
        r = self.client.post("/api/kits/validate", headers={"X-CSRF-Token": self._csrf()},
                             json={"content": "id: [unclosed"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["ok"])
        self.assertFalse(list((Path(self.tmp.name) / "kits").glob("*")) if
                         (Path(self.tmp.name) / "kits").exists() else [])

    def test_operator_forbidden(self):
        self.webapp.AUTH.create_user(username="op1", password="Operator-Password-2026!",
                                     role="operator", tenants=["acme"],
                                     must_change_password=False)
        from fastapi.testclient import TestClient
        op = TestClient(self.webapp.app)
        op.post("/api/login", json={"username": "op1", "password": "Operator-Password-2026!"})
        csrf = op.cookies.get(self.webapp.CSRF_COOKIE)
        self.assertEqual(op.get("/api/kits/files").status_code, 403)
        r = op.put("/api/kits/files/x.yaml", headers={"X-CSRF-Token": csrf},
                   json={"content": GOOD_KIT})
        self.assertEqual(r.status_code, 403)

    def test_audit_written(self):
        self._put("audited.yaml", GOOD_KIT)
        j = self.client.get("/api/admin/audit?limit=20").json()
        actions = [e["action"] for e in j["events"]]
        self.assertIn("kit_write", actions)


if __name__ == "__main__":
    unittest.main()
