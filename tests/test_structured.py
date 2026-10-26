import atexit
import json
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

_BOOT_DATA = tempfile.TemporaryDirectory()
atexit.register(_BOOT_DATA.cleanup)
os.environ.setdefault("LOGMASK_DATA", _BOOT_DATA.name)
os.environ.setdefault("LOGMASK_ADMIN_PASSWORD", "Bootstrap-Structured-Password-2026!")

import app as webapp
from auth import AuthStore
from logmask import ORDER, Anonymizer, Deanonymizer, Options, Vault
from structured import (
    anonymize_structured,
    deanonymize_structured,
    detect_structured_format,
    parse_cef,
    parse_leef,
    parse_syslog_kv,
)


class StructuredPrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.vault = Vault(self.root / "vault.db", b"S" * 32)
        self.anon = Anonymizer(self.vault, set(ORDER), Options(preserve_subnet=True))

    def tearDown(self):
        self.vault.db.close()
        self.tmp.cleanup()

    def test_json_nested_fields_and_arrays_are_preserved(self):
        source = json.dumps(
            {
                "source": {"ip": "192.168.10.5"},
                "user": {"name": "mrossi"},
                "related": {"ip": ["192.168.10.6", "192.168.10.7"]},
                "event": {"action": "login", "severity": "high"},
                "unknown_reference": "customer-7788",
            }
        )
        result = anonymize_structured("json", source, self.anon, self.vault, safe=True, source="json-test")
        parsed = json.loads(result.output)
        self.assertNotEqual(parsed["source"]["ip"], "192.168.10.5")
        self.assertNotEqual(parsed["user"]["name"], "mrossi")
        self.assertEqual(len(parsed["related"]["ip"]), 2)
        self.assertTrue(all(value.startswith("198.18.") for value in parsed["related"]["ip"]))
        self.assertEqual(parsed["event"]["action"], "login")
        self.assertEqual(parsed["unknown_reference"], "[ELIDED]")
        self.assertFalse(result.blocked)

    def test_json_round_trip_handles_quotes(self):
        source = json.dumps({"user": {"name": 'mrossi"test'}, "source": {"ip": "10.0.0.2"}})
        result = anonymize_structured("json", source, self.anon, self.vault, safe=True, source="json-test")
        self.vault.commit()
        restored = deanonymize_structured("json", result.output, Deanonymizer(self.vault, Options()))
        self.assertEqual(json.loads(restored), json.loads(source))

    def test_ndjson_keeps_record_boundaries(self):
        source = (
            '{"source_ip":"192.168.1.10","severity":"high"}\n'
            '{"source_ip":"192.168.1.11","severity":"low"}\n'
        )
        result = anonymize_structured("ndjson", source, self.anon, self.vault, safe=True, source="ndjson-test")
        self.assertEqual(result.records, 2)
        self.assertTrue(result.output.endswith("\n"))
        rows = [json.loads(line) for line in result.output.splitlines()]
        self.assertEqual([row["severity"] for row in rows], ["high", "low"])
        self.assertTrue(all(row["source_ip"].startswith("198.18.") for row in rows))

    def test_cef_header_and_extension_round_trip(self):
        source = (
            "CEF:0|Palo Alto|Cortex|1.0|100|Login user=mrossi|7|"
            "src=192.168.1.2 suser=mrossi dhost=srv-01.example.com action=login"
        )
        result = anonymize_structured("cef", source, self.anon, self.vault, safe=True, source="cef-test")
        self.assertTrue(result.output.startswith("CEF:0|Palo Alto|Cortex|1.0|100|"))
        header, pairs = parse_cef(result.output)
        values = dict((key, value) for key, value, _quoted in pairs)
        self.assertNotIn("mrossi", header[5])
        self.assertTrue(values["src"].startswith("198.18."))
        self.assertTrue(values["suser"].startswith("usr-"))
        self.assertTrue(values["dhost"].startswith("host-"))
        self.vault.commit()
        restored = deanonymize_structured("cef", result.output, Deanonymizer(self.vault, Options()))
        restored_header, restored_pairs = parse_cef(restored)
        self.assertIn("mrossi", restored_header[5])
        self.assertEqual(dict((k, v) for k, v, _q in restored_pairs)["src"], "192.168.1.2")

    def test_leef_standard_and_custom_delimiters(self):
        standard = "LEEF:1.0|Vendor|Product|1.0|100|src=192.168.1.2\tusrName=mrossi\tsev=5"
        custom = "LEEF:2.0|Vendor|Product|1.0|100|^|src=192.168.1.2^usrName=mrossi^sev=5"
        for source, expected_delim in ((standard, "\t"), (custom, "^")):
            with self.subTest(source=source):
                result = anonymize_structured("leef", source, self.anon, self.vault, safe=True, source="leef-test")
                _header, pairs, delimiter = parse_leef(result.output)
                values = dict((key, value) for key, value, _quoted in pairs)
                self.assertEqual(delimiter, expected_delim)
                self.assertTrue(values["src"].startswith("198.18."))
                self.assertTrue(values["usrName"].startswith("usr-"))
                self.assertEqual(values["sev"], "5")

    def test_syslog_masks_rfc3164_hostname_and_pairs(self):
        source = '<134>Jul 12 10:00:00 fw01 app: src=192.168.1.2 user="mrossi" action=login'
        result = anonymize_structured("syslog", source, self.anon, self.vault, safe=True, source="syslog-test")
        self.assertNotIn(" fw01 ", result.output)
        prefix, pairs = parse_syslog_kv(result.output)
        self.assertIn("host-", prefix)
        values = dict((key, value) for key, value, _quoted in pairs)
        self.assertTrue(values["src"].startswith("198.18."))
        self.assertTrue(values["user"].startswith("usr-"))
        self.assertEqual(values["action"], "login")

    def test_text_field_residual_elision_is_reported(self):
        source = '{"message":"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"}'
        result = anonymize_structured(
            "json", source, self.anon, self.vault, safe=True, source="secret-json",
        )
        parsed = json.loads(result.output)
        self.assertIn("[ELIDED]", parsed["message"])
        self.assertGreaterEqual(result.elided, 1)
        self.assertTrue(result.elided_samples)
        self.assertFalse(result.blocked)

    def test_unknown_field_blocks_without_safe_mode(self):
        result = anonymize_structured(
            "json", '{"unclassified":"customer-7788"}', self.anon, self.vault,
            safe=False, source="unsafe-json",
        )
        self.assertGreater(result.failed, 0)
        self.assertTrue(result.blocked)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            anonymize_structured(
                "json", '{"source_ip":"10.0.0.1","source_ip":"10.0.0.2"}',
                self.anon, self.vault, safe=True, source="duplicate-json",
            )

    def test_syslog_rejects_unparsed_text_instead_of_dropping_it(self):
        with self.assertRaisesRegex(ValueError, "unparsed text"):
            anonymize_structured(
                "syslog", "<1>Jul 12 10:00:00 fw app: src=10.0.0.1 free text action=allow",
                self.anon, self.vault, safe=True, source="bad-syslog",
            )

    def test_auto_detection(self):
        cases = {
            "json": '{"source_ip":"10.0.0.1"}',
            "ndjson": '{"a":1}\n{"a":2}\n',
            "cef": "CEF:0|V|P|1|1|Name|5|src=10.0.0.1",
            "leef": "LEEF:1.0|V|P|1|1|src=10.0.0.1\tsev=5",
            "syslog": "<1>Jul 12 10:00:00 h app: src=10.0.0.1 action=allow\n<1>Jul 12 10:00:01 h2 app: src=10.0.0.2 action=deny\n",
        }
        for expected, text in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(detect_structured_format(text), expected)


class StructuredApiTests(unittest.TestCase):
    ADMIN_PASSWORD = "Bootstrap-Structured-Root-2026!"

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
            json={"current_password": self.ADMIN_PASSWORD, "new_password": "Structured-Personal-Password-2026!"},
        )
        self.assertEqual(changed.status_code, 200, changed.text)

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, path: str, payload: dict):
        return self.client.post(
            path,
            headers={"X-CSRF-Token": self.client.cookies.get(webapp.CSRF_COOKIE)},
            json=payload,
        )

    def test_space_collapsed_tsv_falls_back_to_text_masking(self):
        # v0.10.17: a TSV that lost its tabs collapses to a single column in CSV
        # mode; instead of failing, the app processes it as free text (sensitive
        # tokens masked) and returns a warning. No silent keep-classified row.
        collapsed = ("Issue Id Name Severity Host IP Host FQDN User name CGO SHA256 Tags\n"
                     "3324095 utm High 10.0.0.5 srv01.corp.local CORP\\jdoe abc x\n")
        r = self.post("/api/anonymize",
                      {"tenant": "c-collapse", "text": collapsed,
                       "format": "csv", "safe_mode": True})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["format"], "text")
        self.assertIn("warning", body)
        self.assertIn("Colonne non separabili", body["warning"])
        self.assertNotIn("10.0.0.5", body["output"])           # internal IP masked
        self.assertNotIn("jdoe", body["output"])               # user masked
        self.assertNotIn("srv01.corp.local", body["output"])   # host masked
        # the same data as a real (tab-separated) TSV is split into columns
        real = ("Issue Id\tName\tSeverity\tHost IP\tHost FQDN\tUser name\n"
                "3324095\tutm\tHigh\t10.0.0.5\tsrv01.corp.local\tCORP\\jdoe\n")
        ok = self.post("/api/anonymize",
                       {"tenant": "c-collapse", "text": real,
                        "format": "csv", "safe_mode": True})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertNotIn("jdoe", ok.json()["output"])          # user masked
        self.assertGreater(len(ok.json()["fields"]), 1)        # split into columns

    def test_api_auto_detects_json_and_reverses_structurally(self):
        source = '{"source":{"ip":"192.168.1.5"},"user":{"name":"mrossi"},"event":{"action":"login"}}'
        anon = self.post(
            "/api/anonymize",
            {"tenant": "cliente-json", "text": source, "format": "auto", "safe_mode": True},
        )
        self.assertEqual(anon.status_code, 200, anon.text)
        body = anon.json()
        self.assertEqual(body["format"], "json")
        self.assertFalse(body["blocked"])
        restored = self.post(
            "/api/deanonymize",
            {"tenant": "cliente-json", "text": body["output"], "format": "auto"},
        )
        self.assertEqual(restored.status_code, 200, restored.text)
        self.assertEqual(json.loads(restored.json()["output"]), json.loads(source))

    def test_invalid_ndjson_returns_400(self):
        response = self.post(
            "/api/anonymize",
            {"tenant": "cliente-json", "text": '{"a":1}\nnot-json', "format": "ndjson", "safe_mode": True},
        )
        self.assertEqual(response.status_code, 400, response.text)


if __name__ == "__main__":
    unittest.main()
