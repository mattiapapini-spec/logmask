import json
import os
import tempfile
import importlib
import unittest

from fastapi.testclient import TestClient


class BugHuntRegressions(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.old_env = {k: os.environ.get(k) for k in ["LOGMASK_DATA", "LOGMASK_ADMIN_PASSWORD"]}
        os.environ["LOGMASK_DATA"] = self.td.name
        os.environ["LOGMASK_ADMIN_PASSWORD"] = "Bootstrap-Password-2026!"
        import app
        importlib.reload(app)
        self.app = app
        self.client = TestClient(app.app)
        r = self.client.post("/api/login", json={"username": "admin", "password": "Bootstrap-Password-2026!"})
        self.assertEqual(r.status_code, 200, r.text)
        csrf = self.client.cookies.get(app.CSRF_COOKIE)
        r = self.client.post(
            "/api/change-password",
            json={"current_password": "Bootstrap-Password-2026!", "new_password": "New-Strong-Password-2026!"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.csrf = self.client.cookies.get(app.CSRF_COOKIE)

    def tearDown(self):
        for k, v in self.old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.td.cleanup()

    def anonymize(self, text, fmt):
        r = self.client.post(
            "/api/anonymize",
            json={
                "tenant": "soc-test",
                "text": text,
                "format": fmt,
                "safe_mode": True,
                "preserve_subnet": True,
                "ip_mode": "all",
                "dlp_policy": {},
            },
            headers={"X-CSRF-Token": self.csrf},
        )
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_ecs_event_dataset_is_operational_metadata_not_fqdn_json(self):
        j = self.anonymize('{"event":{"dataset":"windows.security","module":"windows","provider":"Microsoft-Windows-Security-Auditing"}}', "json")
        data = json.loads(j["output"])
        self.assertEqual(data["event"]["dataset"], "windows.security")
        self.assertEqual(data["event"]["module"], "windows")
        self.assertEqual(data["event"]["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertFalse(j["blocked"])
        self.assertEqual(j["failed"], 0)

    def test_ecs_event_dataset_is_operational_metadata_not_fqdn_csv(self):
        j = self.anonymize("event.dataset,event.module,event.provider\nwindows.security,windows,Microsoft-Windows-Security-Auditing\n", "csv")
        self.assertIn("windows.security", j["output"])
        self.assertNotIn("host-", j["output"])
        self.assertFalse(j["blocked"])


if __name__ == "__main__":
    unittest.main()

class ElasticTrendWrapperRegressions(BugHuntRegressions):
    def test_trend_payload_inside_elastic_signal_masks_account_and_keeps_operational_metadata(self):
        source = json.dumps({
            "_source": {
                "event": {"dataset": "trend_micro_vision_one.alert", "module": "trend_micro_vision_one"},
                "data_stream": {"dataset": "logs-trend_micro_vision_one.alert", "type": "logs"},
                "agent": {"type": "filebeat", "name": "neteye01.internal.local"},
                "trend_micro_vision_one": {"alert": {
                    "impact_scope": {"entities": [{"value": {"account_value": "acidrt\\\\sv21237", "ips": ["10.157.16.38"]}}]},
                    "incident_id": "WB-23990-20260706-00001",
                    "schema_version": "1.22",
                    "investigation_status": "New"
                }},
                "kibana": {"alert": {"rule": {"updated_by": "m.verdi"}}},
                "url": {"original": "https://10.157.16.38/index.html?ref=0c12e642ca5b7ed4436e5f23f568ae10066608d3"}
            }
        })
        j = self.anonymize(source, "json")
        out = json.loads(j["output"])
        src = out["_source"]
        self.assertEqual(src["event"]["dataset"], "trend_micro_vision_one.alert")
        self.assertEqual(src["data_stream"]["type"], "logs")
        self.assertEqual(src["agent"]["type"], "filebeat")
        self.assertNotIn("acidrt\\\\sv21237", j["output"])
        self.assertIn("DOM-", src["trend_micro_vision_one"]["alert"]["impact_scope"]["entities"][0]["value"]["account_value"])
        self.assertNotEqual(src["kibana"]["alert"]["rule"]["updated_by"], "m.verdi")
        self.assertTrue(src["trend_micro_vision_one"]["alert"]["incident_id"].startswith("id-"))
        self.assertIn("ref=[ELIDED]", src["url"]["original"])
        self.assertFalse(j["blocked"])
        self.assertGreater(j["coverage"]["vendor_percent"], 30.0)
