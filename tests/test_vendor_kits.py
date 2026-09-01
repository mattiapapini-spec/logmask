import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import app as webapp
from auth import AuthStore
from logmask import Anonymizer, Options, ORDER, Vault, default_policy, apply_safe_policy
from structured import anonymize_structured
from vendor_kits import KITS, detect_vendor_kit, match_rule


DETECTION_SAMPLES = {
    "cortex": ["agent_hostname", "action_local_ip", "actor_effective_username", "severity"],
    "crowdstrike": ["event_simpleName", "aid", "ComputerName", "SHA256HashData"],
    "wazuh": ["rule.description", "agent.name", "manager.name", "full_log"],
    "microsoft_sentinel": ["TimeGenerated", "CompromisedEntity", "AlertSeverity", "SystemAlertId"],
    "splunk_cim": ["_time", "sourcetype", "_raw", "dest_ip", "src_ip"],
    "okta": ["actor.alternateId", "outcome.result", "client.ipAddress", "eventType"],
    "proofpoint": ["phishScore", "spamScore", "headerFrom", "quarantineFolder"],
    "zscaler": ["urlsupercategory", "urlcategory", "dlpengine", "clientIP"],
    "aws_cloudtrail": ["userIdentity.arn", "recipientAccountId", "eventSource", "sourceIPAddress"],
    "microsoft_defender": ["DeviceName", "ActionType", "RemoteIP", "AccountUpn"],
    "trend_vision_one": ["endpointName", "endpointGUID", "objectFilePath", "detectionName"],
    "elastic_ecs": ["@timestamp", "event.dataset", "source.ip", "host.name", "ecs.version"],
    "fortinet": ["srcip", "dstip", "devname", "logid", "policyid"],
    "sentinelone": ["agentComputerName", "agentUuid", "storylineId", "threatId"],
    "sophos": ["endpoint_hostname", "endpoint_id", "threat_name", "customer_id"],
    "cisco_secure_endpoint": ["connector_guid", "computer_hostname", "event_type_id", "detection"],
    # v0.25.2: kit separati. Darktrace conserva i suoi fingerprint; Exabeam ha
    # i suoi, verificati sul Common Information Model ufficiale.
    "darktrace": ["modelName", "breachScore", "deviceId", "modelUuid"],
    "exabeam": ["dest_user_entity_id", "dest_device_entity_id", "triggered_rules",
                "activity_type"],
    "acronis": ["machine_id", "machine_name", "alert_type", "tenant_uuid"],
    "bitdefender": ["alert.att&ck_subtechnique_id", "other.sensor_name",
                    "network.container_id", "other.detection_class"],
    "microsoft_entra": ["accesso_condizionale", "requisito_per_l'autenticazione",
                        "numero_del_sistema_autonomo", "contrassegnato_per_la_revisione"],
}


class VendorKitPrimitiveTests(unittest.TestCase):
    def test_all_supported_kits_are_detected_from_distinctive_fields(self):
        self.assertEqual(set(DETECTION_SAMPLES), set(KITS))
        for expected, fields in DETECTION_SAMPLES.items():
            with self.subTest(expected=expected):
                result = detect_vendor_kit(fields)
                self.assertEqual(result["id"], expected)
                self.assertGreaterEqual(result["confidence"], 0.5)

    def test_vendor_rules_cover_mask_text_and_operational_keep(self):
        cases = [
            ("cortex", "agent_hostname", "mask", "endpoint"),
            ("microsoft_defender", "ProcessCommandLine", "text", None),
            ("trend_vision_one", "detectionName", "keep", None),
            ("elastic_ecs", "source.ip", "mask", "ip"),
            ("fortinet", "policyid", "keep", None),
            ("sentinelone", "storylineId", "mask", "opaque"),
            ("sophos", "endpoint_hostname", "mask", "endpoint"),
            ("cisco_secure_endpoint", "computer_ip", "mask", "ip"),
            ("darktrace", "breachScore", "keep", None),
            ("exabeam", "event_code", "keep", None),
            ("acronis", "machine_name", "mask", "endpoint"),
            ("bitdefender", "other.sensor_name", "mask", "endpoint"),
            ("bitdefender", "alert.att&ck_tactic", "keep", None),
            ("bitdefender", "registry.key", "text", None),
        ]
        for kit, field, action, kind in cases:
            with self.subTest(kit=kit, field=field):
                rule, canonical = match_rule(field.lower(), kit)
                self.assertEqual(canonical, kit)
                self.assertIsNotNone(rule)
                self.assertEqual(rule.action, action)
                self.assertEqual(rule.kind, kind)

    def test_customer_and_unique_identifiers_are_not_kept_in_clear(self):
        cases = [
            ("cortex", "sensor_name", "mask"),
            ("cortex", "tenant", "mask"),
            ("cortex", "alert_id", "mask"),
            ("cortex", "xdr_url", "text"),
            ("microsoft_defender", "ReportId", "mask"),
            ("trend_vision_one", "policyName", "mask"),
            ("elastic_ecs", "event.id", "mask"),
            ("fortinet", "vdom", "mask"),
            ("fortinet", "sessionid", "mask"),
            ("sentinelone", "storylineId", "mask"),
            ("sophos", "event_id", "mask"),
            ("darktrace", "session_id", "mask"),
            ("exabeam", "dest_user_sid", "mask"),
            ("acronis", "alert_id", "mask"),
        ]
        for kit, field, expected_action in cases:
            with self.subTest(kit=kit, field=field):
                rule, _ = match_rule(field.lower(), kit)
                self.assertIsNotNone(rule)
                self.assertEqual(rule.action, expected_action)

    def test_vendor_keep_rules_survive_safe_policy(self):
        columns = ["DeviceName", "ActionType", "FileName", "AccountUpn", "MysteryCustomerRef"]
        samples = {
            "DeviceName": ["pc01.contoso.local"],
            "ActionType": ["ProcessCreated"],
            "FileName": ["cmd.exe"],
            "AccountUpn": ["m.rossi@contoso.com"],
            "MysteryCustomerRef": ["customer-7788"],
        }
        policy = apply_safe_policy(default_policy(columns, samples, "microsoft_defender"), samples)
        self.assertEqual(policy["columns"]["ActionType"]["action"], "keep")
        self.assertEqual(policy["columns"]["FileName"]["action"], "keep")
        self.assertEqual(policy["columns"]["DeviceName"]["action"], "mask")
        self.assertEqual(policy["columns"]["AccountUpn"]["action"], "mask")
        self.assertEqual(policy["columns"]["MysteryCustomerRef"]["action"], "redact")

    def test_structured_json_auto_detects_microsoft_and_elides_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            vault = Vault(Path(td) / "vault.db", b"V" * 32)
            anon = Anonymizer(vault, set(ORDER), Options())
            source = json.dumps({
                "DeviceName": "pc01.contoso.local",
                "ActionType": "ProcessCreated",
                "RemoteIP": "8.8.8.8",
                "AccountUpn": "m.rossi@contoso.com",
                "MysteryCustomerRef": "customer-7788",
            })
            result = anonymize_structured("json", source, anon, vault, safe=True, source="vendor-test")
            parsed = json.loads(result.output)
            self.assertEqual(result.catalog, "microsoft_defender")
            self.assertEqual(parsed["ActionType"], "ProcessCreated")
            self.assertTrue(parsed["DeviceName"].startswith("host-"))
            self.assertTrue(parsed["AccountUpn"].startswith("usr-"))
            self.assertEqual(parsed["MysteryCustomerRef"], "[ELIDED]")
            vault.db.close()


    def test_ecs_operational_dotted_values_do_not_trigger_global_false_positive(self):
        with tempfile.TemporaryDirectory() as td:
            vault = Vault(Path(td) / "vault.db", b"E" * 32)
            anon = Anonymizer(vault, set(ORDER), Options())
            source = json.dumps({
                "@timestamp": "2026-07-12T20:00:00Z",
                "ecs": {"version": "9.4.0"},
                "event": {"dataset": "windows.security", "action": "logon-failed"},
                "source": {"ip": "10.0.0.15", "port": 51422},
                "host": {"name": "pc01.contoso.local"},
            })
            result = anonymize_structured("json", source, anon, vault, safe=True, source="ecs-test")
            self.assertEqual(result.catalog, "elastic_ecs")
            self.assertFalse(result.blocked)
            self.assertEqual(json.loads(result.output)["event"]["dataset"], "windows.security")
            vault.db.close()

    def test_vendor_opaque_identifiers_are_reversible(self):
        with tempfile.TemporaryDirectory() as td:
            vault = Vault(Path(td) / "vault.db", b"O" * 32)
            anon = Anonymizer(vault, set(ORDER), Options())
            original_id = "11111111-2222-4333-8444-555555555555"
            source = json.dumps({
                "DeviceName": "pc01.contoso.local",
                "ActionType": "ProcessCreated",
                "DeviceId": original_id,
                "AccountObjectId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            })
            result = anonymize_structured(
                "json", source, anon, vault, safe=True, source="opaque-test", family="microsoft_defender"
            )
            parsed = json.loads(result.output)
            self.assertTrue(parsed["DeviceId"].startswith("id-"))
            self.assertTrue(parsed["AccountObjectId"].startswith("id-"))
            vault.commit()
            from logmask import Deanonymizer
            from structured import deanonymize_structured
            restored = deanonymize_structured("json", result.output, Deanonymizer(vault, Options()))
            self.assertEqual(json.loads(restored)["DeviceId"], original_id)
            vault.db.close()

    def test_cef_header_detection_keeps_cef_fallback_fields(self):
        with tempfile.TemporaryDirectory() as td:
            vault = Vault(Path(td) / "vault.db", b"C" * 32)
            anon = Anonymizer(vault, set(ORDER), Options())
            source = "CEF:0|Palo Alto|Cortex|1.0|100|Login|7|src=192.168.1.2 suser=mrossi dhost=srv01.local action=login"
            result = anonymize_structured("cef", source, anon, vault, safe=True, source="cef-vendor")
            self.assertEqual(result.catalog, "cortex")
            self.assertIn("suser=usr-", result.output)
            self.assertIn("dhost=host-", result.output)
            vault.db.close()



    def test_trend_indicator_values_are_text_not_blindly_elided(self):
        with tempfile.TemporaryDirectory() as td:
            vault = Vault(Path(td) / "vault.db", b"T" * 32)
            anon = Anonymizer(vault, set(ORDER), Options())
            source = json.dumps({
                "event": {"dataset": "trend_micro_vision_one.alert", "module": "trend_micro_vision_one"},
                "trend_micro_vision_one": {"alert": {
                    "indicators": [
                        {"field": "processCmd", "type": "command_line", "value": r"C:\Users\mrossi\AppData\Local\Temp\PDFConvertSetup.exe /S"},
                        {"field": "processFileOriginalName", "type": "filename", "value": "cleanmgr.exe"},
                    ],
                    "description": "Detects possible masquerading behavior technique.",
                    "matched_rule": [{"filter": [{"name": "Possible Masquerading Behavior"}], "name": "Possible Masquerading Behavior", "id": "rule-123"}],
                    "workbench_link": "https://console.example.invalid/index.html#/workbench/alerts/WB-23990-20260706-00001?ref=abcdef123456",
                }}
            })
            result = anonymize_structured("json", source, anon, vault, safe=True, source="ai-analysis:vendor-test")
            parsed = json.loads(result.output)
            value = parsed["trend_micro_vision_one"]["alert"]["indicators"][0]["value"]
            self.assertNotEqual(value, "[ELIDED]")
            self.assertIn("PDFConvertSetup.exe", value)
            self.assertNotIn("mrossi", value)
            desc = parsed["trend_micro_vision_one"]["alert"]["description"]
            self.assertIn("masquerading behavior", desc.lower())
            self.assertNotIn("host-", desc)
            link = parsed["trend_micro_vision_one"]["alert"]["workbench_link"]
            self.assertNotIn("WB-23990", link)
            self.assertIn("id-", link)
            self.assertIn("ref=[ELIDED]", link)
            vault.db.close()

    def test_ai_workflow_pseudonymizes_data_stream_namespace(self):
        with tempfile.TemporaryDirectory() as td:
            vault = Vault(Path(td) / "vault.db", b"N" * 32)
            anon = Anonymizer(vault, set(ORDER), Options())
            source = json.dumps({
                "@timestamp": "2026-07-13T00:00:00Z",
                "ecs": {"version": "9.4.0"},
                "event": {"dataset": "trend_micro_vision_one.alert", "module": "trend_micro_vision_one"},
                "data_stream": {"type": "logs", "dataset": "trend_micro_vision_one.alert", "namespace": "master"},
            })
            result = anonymize_structured("json", source, anon, vault, safe=True, source="ai-analysis:paste")
            parsed = json.loads(result.output)
            self.assertEqual(parsed["data_stream"]["type"], "logs")
            self.assertEqual(parsed["data_stream"]["dataset"], "trend_micro_vision_one.alert")
            self.assertTrue(parsed["data_stream"]["namespace"].startswith("id-"))
            vault.db.close()


class VendorKitApiTests(unittest.TestCase):
    ADMIN_PASSWORD = "Vendor-Kit-Bootstrap-2026!"

    def setUp(self):
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
        login = self.client.post("/api/login", json={"username": "admin", "password": self.ADMIN_PASSWORD})
        self.assertEqual(login.status_code, 200, login.text)
        csrf = self.client.cookies.get(webapp.CSRF_COOKIE)
        changed = self.client.post(
            "/api/change-password",
            headers={"X-CSRF-Token": csrf},
            json={"current_password": self.ADMIN_PASSWORD, "new_password": "Vendor-Kit-Personal-2026!"},
        )
        self.assertEqual(changed.status_code, 200, changed.text)

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, path, payload):
        return self.client.post(path, headers={"X-CSRF-Token": self.client.cookies.get(webapp.CSRF_COOKIE)}, json=payload)

    def test_vendor_kit_endpoint_lists_all_kits(self):
        response = self.client.get("/api/vendor-kits")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual({item["id"] for item in response.json()["kits"]}, set(KITS))

    def test_csv_auto_detection_returns_coverage_and_unknown_fields(self):
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["DeviceName", "ActionType", "RemoteIP", "AccountUpn", "MysteryCustomerRef"])
        writer.writerow(["pc01.contoso.local", "ConnectionSuccess", "8.8.8.8", "m.rossi@contoso.com", "customer-7788"])
        response = self.post("/api/anonymize", {
            "tenant": "microsoft-test",
            "text": buf.getvalue(),
            "format": "csv",
            "safe_mode": True,
            "ip_mode": "all",
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["vendor_kit"]["id"], "microsoft_defender")
        self.assertEqual(body["catalog"], "microsoft_defender")
        self.assertIn("MysteryCustomerRef", body["unknown_fields"])
        self.assertGreater(body["coverage"]["vendor_percent"], 50)
        self.assertFalse(body["blocked"])
        self.assertIn("[ELIDED]", body["output"])

    def test_forced_vendor_kit_is_reported(self):
        response = self.post("/api/anonymize", {
            "tenant": "forced-kit",
            "text": '{"machine_name":"host-01","alert_type":"malware","source_ip":"10.0.0.2"}',
            "format": "json",
            "catalog": "acronis",
            "safe_mode": True,
            "ip_mode": "all",
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["vendor_kit"]["id"], "acronis")
        self.assertTrue(body["vendor_kit"]["forced"])
        self.assertFalse(body["blocked"])


if __name__ == "__main__":
    unittest.main()
