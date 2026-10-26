import json
import tempfile
import unittest
from pathlib import Path

from dlp import (
    DLP_CATEGORIES,
    apply,
    apply_field,
    category_for_field,
    detect,
    normalize_dlp_policy,
    valid_codice_fiscale,
    valid_iban,
)
from logmask import Anonymizer, Deanonymizer, Options, ORDER, Vault
from structured import anonymize_structured, deanonymize_structured


class DlpDetectionTests(unittest.TestCase):
    def test_validators(self):
        self.assertTrue(valid_codice_fiscale("RSSMRA80A01H501U"))
        self.assertFalse(valid_codice_fiscale("RSSMRA80A01H501X"))
        self.assertTrue(valid_iban("IT60X0542811101000000123456"))
        self.assertFalse(valid_iban("IT00X0542811101000000123456"))

    def test_high_confidence_detection(self):
        text = (
            "nome: Mario Rossi\n"
            "telefono: +39 333 123 4567\n"
            "CF RSSMRA80A01H501U\n"
            "IBAN IT60X0542811101000000123456\n"
            "indirizzo: Via Roma 10, Grosseto\n"
            "password=SuperSecret123!\n"
            "tenant=550e8400-e29b-41d4-a716-446655440000\n"
            "arn:aws:iam::123456789012:role/Admin\n"
            "https://example.invalid/cb?access_token=abcdef1234567890"
        )
        categories = {finding.category for finding in detect(text)}
        self.assertTrue({"person_name", "phone", "tax_id", "iban", "address", "credentials", "cloud_id", "sensitive_url"} <= categories)

    def test_name_does_not_cross_lines(self):
        findings = detect("nome: Mario Rossi\ntelefono: +39 333 123 4567")
        person = next(item for item in findings if item.category == "person_name")
        self.assertEqual(person.value, "Mario Rossi")

    def test_field_context(self):
        self.assertEqual(category_for_field("user.full_name", "Mario Rossi"), "person_name")
        self.assertEqual(category_for_field("customer_phone", "+39 333 123 4567"), "phone")
        self.assertEqual(category_for_field("billing.iban", "IT60X0542811101000000123456"), "iban")
        self.assertIsNone(category_for_field("event.code", "4625"))

    def test_policy_validation(self):
        policy = normalize_dlp_policy({"iban": "block"})
        self.assertEqual(policy["iban"], "block")
        self.assertEqual(set(policy), set(DLP_CATEGORIES))
        with self.assertRaises(ValueError):
            normalize_dlp_policy({"unknown": "redact"})
        with self.assertRaises(ValueError):
            normalize_dlp_policy({"iban": "delete"})


class DlpEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.vault = Vault(Path(self.temp.name) / "vault.db", b"x" * 32)

    def tearDown(self):
        self.vault.db.close()
        self.temp.cleanup()

    def anon(self, policy=None):
        return Anonymizer(self.vault, set(ORDER), Options(dlp_policy=policy))

    def test_defaults_redact_secrets_and_pseudonymize_pii(self):
        anon = self.anon()
        source = (
            "nome: Mario Rossi; telefono: +39 333 123 4567; "
            "iban: IT60X0542811101000000123456; "
            "codice fiscale RSSMRA80A01H501U; password=SuperSecret123!"
        )
        output = anon.process(source)
        self.assertIn("[ELIDED]", output)
        self.assertIn("person-", output)
        self.assertIn("tel-", output)
        self.assertIn("iban-", output)
        self.assertIn("cf-", output)
        self.assertNotIn("SuperSecret123!", output)
        self.assertFalse(anon.dlp_blocked)

    def test_pii_round_trip(self):
        anon = self.anon()
        output = anon.process("nome: Mario Rossi telefono: +39 333 123 4567")
        restored = Deanonymizer(self.vault, Options()).process(output)
        self.assertIn("Mario Rossi", restored)
        self.assertIn("+39 333 123 4567", restored)

    def test_block_action_keeps_value_but_blocks(self):
        anon = self.anon({"private_key": "block"})
        key = "-----BEGIN PRIVATE KEY-----\nQUJDREVGRw==\n-----END PRIVATE KEY-----"
        output = anon.process(key)
        self.assertEqual(output, key)
        self.assertEqual(len(anon.dlp_blocked), 1)
        self.assertEqual(anon.dlp_blocked[0]["kind"], "private_key")

    def test_keep_action_is_respected(self):
        anon = self.anon({"iban": "keep"})
        value = "IT60X0542811101000000123456"
        output = anon.process("iban: " + value)
        self.assertIn(value, output)
        self.assertEqual(anon.dlp_actions["keep"], 1)

    def test_field_policy_pseudonymizes_unknown_structured_field(self):
        anon = self.anon()
        result = apply_field(
            "customer_phone",
            "+39 333 123 4567",
            anon.opt.dlp_policy,
            lambda kind, raw: anon._map(kind, raw),
        )
        self.assertTrue(result.output.startswith("tel-"))

    def test_structured_field_context_and_reverse(self):
        anon = self.anon()
        source = json.dumps({
            "customer_phone": "+39 333 123 4567",
            "billing": {"iban": "IT60X0542811101000000123456"},
            "message": "password=SuperSecret123!",
        })
        result = anonymize_structured("json", source, anon, self.vault, safe=True, source="dlp-json")
        parsed = json.loads(result.output)
        self.assertTrue(parsed["customer_phone"].startswith("tel-"))
        self.assertTrue(parsed["billing"]["iban"].startswith("iban-"))
        self.assertIn("[ELIDED]", parsed["message"])
        restored = json.loads(deanonymize_structured("json", result.output, Deanonymizer(self.vault, Options())))
        self.assertEqual(restored["customer_phone"], "+39 333 123 4567")
        self.assertEqual(restored["billing"]["iban"], "IT60X0542811101000000123456")
        self.assertEqual(restored["message"], "password=[ELIDED]")


if __name__ == "__main__":
    unittest.main()
