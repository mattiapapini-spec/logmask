"""v0.27.0 - override per campo: gestione diretta dei campi non tracciati.

I campi che nessun kit classifica venivano elisi in Safe mode e per cambiarne
il trattamento serviva scrivere un kit YAML a mano. Ora esiste un override
globale per nome campo con tre scelte - mantieni (keep), pseudonimizza (mask)
ed elidi (redact) - indipendente dal vendor rilevato, perche' i campi non
tracciati compaiono proprio quando nessun kit ha fatto match.
"""
import csv
import io
import tempfile
import unittest
from pathlib import Path

import logmask
from logmask import (Anonymizer, Deanonymizer, CsvAnonymizer, NO_ELISION_DLP_POLICY,
                     ORDER, Options, Vault, apply_safe_policy, default_policy,
                     detect_family, read_samples, resolve_field)

COLUMNS = ["ticket_ref", "weird_custom_field", "mystery_col", "note"]
ROW = ["INC-2026-0042", "valore-strano-123", "abc", "testo qualsiasi"]


def run(overrides, safe=True):
    logmask.FIELD_OVERRIDES = dict(overrides)
    try:
        tmp = tempfile.TemporaryDirectory()
        src = Path(tmp.name) / "in.csv"
        buf = io.StringIO()
        w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        w.writerow(COLUMNS)
        for _ in range(2):
            w.writerow(ROW)
        with open(src, "w", encoding="utf-8", newline="") as fh:
            fh.write(buf.getvalue())
        cols, samples, dialect = read_samples(src, 200)
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        anon = Anonymizer(vault, set(ORDER),
                          Options(ip_mode="all", dlp_policy=dict(NO_ELISION_DLP_POLICY)))
        policy = default_policy(cols, samples, detect_family(cols))
        if safe:
            policy = apply_safe_policy(policy, samples)
        proc = CsvAnonymizer(anon, policy, "upload:t", safe=safe)
        out = io.StringIO()
        proc.process(src, out, dialect, cols)
        row = list(csv.DictReader(io.StringIO(out.getvalue())))[0]
        return row, vault, anon.opt
    finally:
        logmask.FIELD_OVERRIDES = {}


class OverrideActionsTests(unittest.TestCase):
    def test_keep_leaves_value_readable(self):
        row, _v, _o = run({"weird_custom_field": {"action": "keep"}})
        self.assertEqual(row["weird_custom_field"], "valore-strano-123")

    def test_mask_pseudonymizes(self):
        row, _v, _o = run({"mystery_col": {"action": "mask", "kind": "opaque"}})
        self.assertTrue(row["mystery_col"].startswith("id-"))
        self.assertNotIn("abc", row["mystery_col"])

    def test_redact_elides(self):
        row, _v, _o = run({"note": {"action": "redact"}})
        self.assertEqual(row["note"], "[ELIDED]")

    def test_mask_override_is_reversible(self):
        row, vault, opt = run({"mystery_col": {"action": "mask", "kind": "opaque"}})
        restored = Deanonymizer(vault, opt).process(row["mystery_col"])
        self.assertEqual(restored, "abc")

    def test_unoverridden_fields_still_elided_in_safe_mode(self):
        row, _v, _o = run({"weird_custom_field": {"action": "keep"}})
        self.assertEqual(row["ticket_ref"], "[ELIDED]")
        self.assertEqual(row["mystery_col"], "[ELIDED]")


class ResolveFieldTests(unittest.TestCase):
    def tearDown(self):
        logmask.FIELD_OVERRIDES = {}

    def test_override_beats_vendor_and_heuristic(self):
        logmask.FIELD_OVERRIDES = {"user_name": {"action": "keep"}}
        decision = resolve_field("user_name", ["mrossi"], "exabeam")
        self.assertEqual(decision.action, "keep")
        self.assertEqual(decision.inferred_by, "config:override")

    def test_override_normalizes_field_name(self):
        logmask.FIELD_OVERRIDES = {"my_field": {"action": "redact"}}
        self.assertEqual(resolve_field("My Field", ["x"]).action, "redact")

    def test_safe_mode_respects_override_keep(self):
        logmask.FIELD_OVERRIDES = {"weird": {"action": "keep"}}
        policy = default_policy(["weird"], {"weird": ["data here"]}, None)
        policy = apply_safe_policy(policy, {"weird": ["data here"]})
        self.assertEqual(policy["columns"]["weird"]["action"], "keep")


class PersistenceTests(unittest.TestCase):
    def _app(self):
        import importlib, os, tempfile
        os.environ["LOGMASK_DATA"] = tempfile.mkdtemp()
        import app
        importlib.reload(app)
        return app

    def test_save_and_load_round_trip(self):
        app = self._app()
        saved = app.save_field_overrides({
            "Custom Field": {"action": "mask", "kind": "opaque"},
            "drop_me": {"action": "redact"},
            "keep_me": {"action": "keep"}})
        self.assertIn("custom_field", saved)
        loaded = app.load_field_overrides()
        self.assertEqual(loaded["custom_field"]["action"], "mask")
        self.assertEqual(loaded["custom_field"]["kind"], "opaque")
        self.assertEqual(loaded["drop_me"]["action"], "redact")

    def test_empty_action_removes_override(self):
        app = self._app()
        app.save_field_overrides({"temp": {"action": "keep"}})
        self.assertIn("temp", app.load_field_overrides())
        app.save_field_overrides({"temp": {"action": ""}})
        self.assertNotIn("temp", app.load_field_overrides())

    def test_invalid_action_rejected(self):
        app = self._app()
        with self.assertRaises(ValueError):
            app.save_field_overrides({"x": {"action": "explode"}})

    def test_mask_without_kind_defaults_to_opaque(self):
        app = self._app()
        saved = app.save_field_overrides({"x": {"action": "mask"}})
        self.assertEqual(saved["x"]["kind"], "opaque")


class ApiAuthzTests(unittest.TestCase):
    def _client(self):
        import importlib, os, tempfile
        os.environ["LOGMASK_DATA"] = tempfile.mkdtemp()
        os.environ["LOGMASK_ADMIN_PASSWORD"] = "Str0ng-Pass-9921xZ"
        import app
        importlib.reload(app)
        from fastapi.testclient import TestClient
        return app, TestClient(app.app, raise_server_exceptions=False)

    def test_save_requires_auth(self):
        app, c = self._client()
        r = c.post("/api/field-overrides", json={"overrides": {"x": {"action": "keep"}}})
        self.assertEqual(r.status_code, 401)

    def test_get_reflects_actions(self):
        app, c = self._client()
        c.post("/api/login", json={"username": "admin", "password": "Str0ng-Pass-9921xZ"})
        r = c.get("/api/field-overrides")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.json()["actions"]), {"keep", "mask", "redact"})


if __name__ == "__main__":
    unittest.main()


class MaskOverrideNeverLeaksTests(unittest.TestCase):
    """v0.27.1 - un override 'mask' con un kind tipizzato (ipv4, iban...)
    restituirebbe il valore INVARIATO quando il contenuto non e' conforme:
    una fuga. Gli override mask usano quindi SEMPRE opaque, che maschera
    qualsiasi valore senza condizioni."""

    def tearDown(self):
        logmask.FIELD_OVERRIDES = {}

    def test_typed_kind_is_forced_to_opaque(self):
        for bad_kind in ("ipv4", "ipv6", "mac", "iban", "taxid", "vat", "phone"):
            with self.subTest(kind=bad_kind):
                logmask.FIELD_OVERRIDES = {"col": {"action": "mask", "kind": bad_kind}}
                decision = resolve_field("col", ["testo-non-conforme"], None)
                self.assertEqual(decision.kind, "opaque")

    def test_arbitrary_text_is_actually_masked(self):
        logmask.FIELD_OVERRIDES = {"col": {"action": "mask", "kind": "ipv4"}}
        row, _v, _o = run({"col": {"action": "mask", "kind": "ipv4"}})
        # 'col' non esiste nel CSV di run(); verifica diretta sul builder:
        from logmask import BUILDERS
        out = BUILDERS["opaque"](b"\x00" * 16, "valore-testuale", logmask.Options())
        self.assertNotIn("valore-testuale", out)
        self.assertTrue(out.startswith("id-"))

    def test_save_strips_typed_kind(self):
        import importlib, os, tempfile
        os.environ["LOGMASK_DATA"] = tempfile.mkdtemp()
        import app
        importlib.reload(app)
        saved = app.save_field_overrides({"c": {"action": "mask", "kind": "ipv4"}})
        self.assertEqual(saved["c"]["kind"], "opaque")


class OverrideAppliesToStructuredTests(unittest.TestCase):
    def test_json_honors_overrides(self):
        import tempfile
        from pathlib import Path
        from structured import anonymize_structured
        logmask.FIELD_OVERRIDES = {"mystery": {"action": "redact"},
                                   "keepme": {"action": "keep"},
                                   "maskme": {"action": "mask", "kind": "opaque"}}
        try:
            tmp = tempfile.TemporaryDirectory()
            vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
            anon = Anonymizer(vault, set(ORDER),
                              Options(ip_mode="all", dlp_policy=dict(NO_ELISION_DLP_POLICY)))
            src = '{"mystery":"x","keepme":"visible","maskme":"weird","host":"SRV-DC01.corp.local"}'
            res = anonymize_structured("json", src, anon, vault, safe=True, source="upload:t")
            import json as J
            d = J.loads(res.output)
            self.assertEqual(d["mystery"], "[ELIDED]")
            self.assertEqual(d["keepme"], "visible")
            self.assertTrue(str(d["maskme"]).startswith("id-"))
            self.assertNotIn("SRV-DC01", res.output)
        finally:
            logmask.FIELD_OVERRIDES = {}


if __name__ == "__main__":
    unittest.main()
