import atexit
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

_BOOT = tempfile.TemporaryDirectory()
atexit.register(_BOOT.cleanup)
os.environ.setdefault("LOGMASK_DATA", _BOOT.name)
os.environ.setdefault("LOGMASK_ADMIN_PASSWORD", "Workflow-Bootstrap-Password-2026!")

import app as webapp
from auth import AuthStore
from workflows import workflow_profile, workflow_profiles


class WorkflowPrimitiveTests(unittest.TestCase):
    def test_profiles_cover_required_soc_workflows(self):
        ids = {p["id"] for p in workflow_profiles()}
        self.assertEqual(ids, {"customer-ticket", "ai-analysis", "field-quality", "threat-hunting", "report"})
        for profile in workflow_profiles():
            self.assertIn("settings", profile)
            self.assertIn(profile["settings"]["ip_mode"], {"none", "internal", "all"})
            self.assertTrue(profile["settings"]["safe_mode"])
            self.assertIn("credentials", profile["settings"]["dlp_policy"])
            self.assertEqual(profile["settings"]["dlp_policy"]["credentials"], "redact")

    def test_ai_profile_redacts_more_than_internal_hunting(self):
        ai = workflow_profile("ai-analysis")
        hunting = workflow_profile("threat-hunting")
        # v0.26.1: il default e' "maschera tutto". Il preset per LLM esterni
        # non fa eccezione: mandare fuori un IP pubblico in chiaro perche' "e'
        # un IOC" e' una scelta che deve essere esplicita, non un default.
        self.assertEqual(ai["settings"]["ip_mode"], "all")
        self.assertEqual(ai["settings"]["url_mode"], "all")
        self.assertEqual(hunting["settings"]["ip_mode"], "none")
        self.assertEqual(ai["settings"]["dlp_policy"]["iban"], "redact")
        self.assertEqual(hunting["settings"]["dlp_policy"]["iban"], "pseudonymize")



    def test_field_quality_profile_is_for_audit_not_incident_analysis(self):
        profile = workflow_profile("field-quality")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["template"], "field_quality")
        self.assertEqual(profile["settings"]["ip_mode"], "all")
        self.assertTrue(profile["settings"]["safe_mode"])
        self.assertEqual(profile["settings"]["dlp_policy"]["credentials"], "redact")


class WorkflowApiTests(unittest.TestCase):
    ADMIN_PASSWORD = "Workflow-Temporary-Password-2026!"
    PERSONAL_PASSWORD = "Workflow-Personal-Password-2026!"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        webapp.DATA = root
        webapp.KEY_PATH = root / "master.key"
        webapp.VAULT_PATH = root / "vault.db"
        webapp.TENANTS_DIR = root / "tenants"
        webapp.AUTH_PATH = root / "auth.db"
        webapp.BOOTSTRAP_FILE = root / "bootstrap-admin.txt"
        webapp.MASTER = b"W" * 32
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

    def test_workflow_profiles_endpoint(self):
        response = self.client.get("/api/workflow-profiles")
        self.assertEqual(response.status_code, 200, response.text)
        ids = {p["id"] for p in response.json()["profiles"]}
        self.assertIn("ai-analysis", ids)
        self.assertIn("customer-ticket", ids)

    def test_workflow_profile_endpoint_rejects_unknown(self):
        response = self.client.get("/api/workflow-profiles/nope")
        self.assertEqual(response.status_code, 404)

    def test_workflow_profile_can_drive_anonymize_request_and_audit(self):
        profile = workflow_profile("ai-analysis")
        response = self.post("/api/anonymize", {
            "tenant": "cliente-workflow",
            "text": "src=192.168.1.10 dst=8.8.8.8 iban: IT60X0542811101000000123456 password=Secret12345",
            "format": "text",
            "safe_mode": profile["settings"]["safe_mode"],
            "ip_mode": profile["settings"]["ip_mode"],
            "workflow_profile": profile["id"],
            "dlp_policy": profile["settings"]["dlp_policy"],
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        # Con ip_mode="all" anche l'IP pubblico viene mascherato.
        self.assertNotIn("8.8.8.8", body["output"])
        self.assertNotIn("192.168.1.10", body["output"])
        self.assertNotIn("192.168.1.10", body["output"])
        self.assertNotIn("IT60X", body["output"])
        self.assertNotIn("Secret12345", body["output"])
        audit = self.client.get("/api/admin/audit?limit=5")
        self.assertEqual(audit.status_code, 200, audit.text)
        self.assertTrue(any((e.get("details") or {}).get("workflow_profile") == "ai-analysis" for e in audit.json()["events"]))

    def test_frontend_exposes_workflow_controls(self):
        html = (Path(__file__).parents[1] / "static" / "index.html").read_text(encoding="utf-8")
        for token in (
            'id="workflow-profile"',
            "loadWorkflowProfiles",
            "generateWorkflowTemplate",
            "renderCompare",
            "approveAmbiguousFields",
            "Archivio temporaneo sessione",
            "Non analizzare l'incidente come FP/TP",
            "logmask-workflow-profile",
        ):
            self.assertIn(token, html)


if __name__ == "__main__":
    unittest.main()
