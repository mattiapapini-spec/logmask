"""v0.12.0 — kits loaded from YAML: bundled defaults + user add/extend/replace,
validation, ReDoS rejection, and the dry-run helper."""
import tempfile
import textwrap
import unittest
from pathlib import Path

import vendor_kits as vk
from logmask import kit_dry_run


def _write_user_kits(files: dict) -> Path:
    d = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (d / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return d


class KitYamlLoaderTests(unittest.TestCase):
    def setUp(self):
        self._orig = vk.USER_KITS_DIR

    def tearDown(self):
        vk.USER_KITS_DIR = self._orig
        vk.KITS, vk.ALIASES = vk._build_registry()

    def _load(self, files):
        vk.USER_KITS_DIR = _write_user_kits(files)
        vk.KITS, vk.ALIASES = vk._build_registry()

    def test_bundled_kits_present(self):
        vk.KITS, vk.ALIASES = vk._build_registry()
        for kid in ("cortex", "microsoft_entra", "elastic_ecs", "bitdefender", "fortinet"):
            self.assertIn(kid, vk.KITS)

    def test_new_user_kit_detected_and_classifies(self):
        self._load({"myedr.yaml": """
            id: myedr
            label: My EDR
            fingerprints:
              - {pattern: "^myedr_agent_id$", weight: 8}
            rules:
              - {pattern: ".*_ip$", action: mask, kind: ip}
              - {pattern: "^user$", action: mask, kind: user}
        """})
        self.assertIn("myedr", vk.KITS)
        self.assertEqual(vk.detect_vendor_kit(["myedr_agent_id", "user", "src_ip"])["id"], "myedr")
        r, _ = vk.match_rule("src_ip", "myedr")
        self.assertEqual((r.action, r.kind), ("mask", "ip"))

    def test_extend_existing_kit_user_rule_wins(self):
        self._load({"cortex_extra.yaml": """
            id: cortex
            mode: extend
            rules:
              - {pattern: "^my_secret_col$", action: mask, kind: opaque}
        """})
        r, _ = vk.match_rule("my_secret_col", "cortex")
        self.assertEqual((r.action, r.kind), ("mask", "opaque"))
        r2, _ = vk.match_rule("auth_identity", "cortex")   # existing rules intact
        self.assertEqual(r2.action, "mask")

    def test_replace_mode(self):
        self._load({"cortex_replace.yaml": """
            id: cortex
            mode: replace
            fingerprints:
              - {pattern: "^only_this$", weight: 8}
            rules:
              - {pattern: ".*", action: keep}
        """})
        self.assertEqual(len(vk.KITS["cortex"].rules), 1)

    def test_invalid_action_and_kind_dropped(self):
        self._load({"bad.yaml": """
            id: badkit
            fingerprints: [{pattern: "^bad_fp$", weight: 8}]
            rules:
              - {pattern: "^a$", action: nonsense, kind: user}
              - {pattern: "^b$", action: mask, kind: notakind}
              - {pattern: "^c$", action: keep}
        """})
        self.assertEqual([r.pattern for r in vk.KITS["badkit"].rules], ["^c$"])

    def test_redos_pattern_rejected(self):
        self._load({"evil.yaml": """
            id: evilkit
            fingerprints: [{pattern: "^evil_fp$", weight: 8}]
            rules:
              - {pattern: "(a+)+$", action: keep}
              - {pattern: "^safe$", action: keep}
        """})
        pats = [r.pattern for r in vk.KITS["evilkit"].rules]
        self.assertNotIn("(a+)+$", pats)
        self.assertIn("^safe$", pats)

    def test_malformed_yaml_skipped_good_survives(self):
        self._load({
            "broken.yaml": "id: broken\n  bad: [unclosed",
            "good.yaml": """
                id: goodkit
                fingerprints: [{pattern: "^good_fp$", weight: 8}]
                rules: [{pattern: "^x$", action: keep}]
            """})
        self.assertIn("goodkit", vk.KITS)
        self.assertNotIn("broken", vk.KITS)

    def test_dry_run_reflects_user_kit(self):
        self._load({"myedr.yaml": """
            id: myedr
            fingerprints:
              - {pattern: "^myedr_agent_id$", weight: 8}
            rules:
              - {pattern: ".*_ip$", action: mask, kind: ip}
              - {pattern: "^host$", action: mask, kind: endpoint}
        """})
        vk._KITS_MTIME = object()   # force reload_kits_if_changed to rebuild
        res = kit_dry_run(["myedr_agent_id", "src_ip", "host", "weird_col"])
        self.assertEqual(res["detected"]["id"], "myedr")
        by = {f["column"]: (f["action"], f["kind"]) for f in res["fields"]}
        self.assertEqual(by["src_ip"], ("mask", "ip"))
        self.assertEqual(by["host"], ("mask", "endpoint"))
        self.assertIn("weird_col", res["elided"])   # unknown -> fail-closed


class KitDryRunEndpointTests(unittest.TestCase):
    """v0.12.0 — POST /api/kit-dry-run classifies a header without masking."""
    ADMIN_PASSWORD = "Bootstrap-DryRun-Root-2026!"

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
        self.client.post("/api/login", json={"username": "admin", "password": self.ADMIN_PASSWORD})
        csrf = self.client.cookies.get(webapp.CSRF_COOKIE)
        self.client.post("/api/change-password", headers={"X-CSRF-Token": csrf},
                         json={"current_password": self.ADMIN_PASSWORD,
                               "new_password": "DryRun-Personal-Password-2026!"})

    def tearDown(self):
        self.tmp.cleanup()

    def _post(self, payload):
        csrf = self.client.cookies.get(self.webapp.CSRF_COOKIE)
        return self.client.post("/api/kit-dry-run",
                                headers={"X-CSRF-Token": csrf}, json=payload)

    def test_dry_run_detects_and_classifies(self):
        r = self._post({"columns": ["auth_service", "auth_identity", "auth_client", "n"]})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["detected"]["id"], "cortex")
        by = {f["column"]: f["action"] for f in body["fields"]}
        self.assertEqual(by["auth_identity"], "mask")   # username -> masked
        self.assertNotIn("auth_service", body["elided"])  # detected kit, nothing elided

    def test_dry_run_masks_nothing_and_rejects_empty(self):
        r = self._post({"columns": ["   ", ""]})
        self.assertEqual(r.status_code, 400, r.text)

    def test_dry_run_requires_csrf(self):
        r = self.client.post("/api/kit-dry-run", json={"columns": ["a"]})
        self.assertIn(r.status_code, (401, 403))


if __name__ == "__main__":
    unittest.main()
