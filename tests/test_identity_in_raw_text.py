"""v0.18.1 — un'identita' mascherata in un campo dedicato non deve restare in
chiaro nel testo grezzo dello stesso export.

Prima: su message/description/reason lo sweep del vault era spento del tutto
(per non far corrompere il testo naturale da una parola comune finita nel
vault), quindi 'mrossi' mascherato in user.name restava leggibile in message.

Ora: sweep attivo anche li', ma limitato ai kind identita' (user/email);
fqdn/opaque restano esclusi. In piu' uno sweep finale sull'output completo
rende il risultato indipendente dall'ORDINE dei campi e dal NOME del campo
grezzo, che cambia per ogni piattaforma (_raw, full_log, raw_message, ...).
"""
import json
import tempfile
import unittest
from pathlib import Path

from logmask import Anonymizer, ORDER, Options, Vault
from structured import anonymize_structured


def make_engine():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "vault.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options())


def run(anon, vault, payload, family="elastic_ecs", fmt="json"):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return anonymize_structured(fmt, text, anon, vault, safe=True,
                                source="t", family=family).output


class IdentityNeverInClearTests(unittest.TestCase):
    def test_masked_identity_not_left_in_message(self):
        tmp, vault, anon = make_engine()
        out = run(anon, vault, {"user.name": "mrossi",
                                "message": "login riuscito per mrossi"})
        self.assertNotIn("mrossi", out)
        tmp.cleanup()

    def test_field_order_does_not_matter(self):
        """Il campo grezzo puo' precedere quello identita': l'ordine delle
        chiavi non e' garantito e non deve cambiare il risultato."""
        tmp, vault, anon = make_engine()
        out = run(anon, vault, {"message": "login riuscito per mrossi",
                                "user.name": "mrossi"})
        self.assertNotIn("mrossi", out)
        tmp.cleanup()

    def test_identity_on_later_ndjson_record(self):
        tmp, vault, anon = make_engine()
        rows = "\n".join([json.dumps({"message": "login per mrossi"}),
                          json.dumps({"user.name": "mrossi"})])
        out = run(anon, vault, rows, fmt="ndjson")
        self.assertNotIn("mrossi", out)
        tmp.cleanup()

    def test_identity_reused_in_later_document(self):
        tmp, vault, anon = make_engine()
        run(anon, vault, {"user.name": "mrossi"})
        out = run(anon, vault, {"message": "errore per mrossi alle 10:00"})
        self.assertNotIn("mrossi", out)
        tmp.cleanup()

    def test_email_too(self):
        tmp, vault, anon = make_engine()
        out = run(anon, vault, {"user.email": "m.rossi@azienda.it",
                                "message": "invio a m.rossi@azienda.it fallito"})
        self.assertNotIn("m.rossi@azienda.it", out)
        tmp.cleanup()


class RawTextFieldsAcrossPlatformsTests(unittest.TestCase):
    """Il nome del campo grezzo cambia per ogni piattaforma: la protezione non
    deve dipendere da un elenco di nomi."""

    CASES = [
        ("splunk_cim", "user", "_raw"),
        ("wazuh", "data.srcuser", "full_log"),
        ("wazuh", "data.srcuser", "previous_log"),
        ("cortex", "actor_effective_username", "raw_message"),
        ("elastic_ecs", "user.name", "event.original"),
        ("elastic_ecs", "user.name", "message"),
        ("okta", "actor.displayName", "displayMessage"),
    ]

    def test_identity_not_in_clear_in_any_raw_field(self):
        for family, id_field, raw_field in self.CASES:
            with self.subTest(kit=family, raw=raw_field):
                tmp, vault, anon = make_engine()
                out = run(anon, vault,
                          {id_field: "mrossi",
                           raw_field: "login per mrossi da 10.0.0.5"},
                          family=family)
                parsed = json.loads(out)
                self.assertNotEqual(parsed.get(id_field), "mrossi")
                self.assertNotIn("mrossi", str(parsed.get(raw_field, "")))
                tmp.cleanup()


class DescriptiveTextNotCorruptedTests(unittest.TestCase):
    """Il motivo per cui lo sweep era stato spento: una parola comune finita
    nel vault (falso positivo storico) non deve corrompere il testo naturale."""

    def test_common_word_mapped_as_host_is_left_alone(self):
        tmp, vault, anon = make_engine()
        anon._map("fqdn", "behavior")                  # falso positivo storico
        out = run(anon, vault, {"user.name": "mrossi",
                                "message": "Suspicious behavior detected for mrossi"})
        self.assertIn("behavior", out)                 # testo intatto
        self.assertNotIn("mrossi", out)                # identita' protetta
        tmp.cleanup()

    def test_non_descriptive_text_still_fully_swept(self):
        """Sui campi non descrittivi lo sweep resta completo (anche fqdn)."""
        tmp, vault, anon = make_engine()
        out = run(anon, vault, {"host.hostname": "web01.corp.local",
                                "event.original": "conn da web01.corp.local"})
        self.assertNotIn("web01.corp.local", out)
        tmp.cleanup()

    def test_unknown_name_stays_documented_limit(self):
        """Un nome mai presente in un campo identita' non e' riconoscibile:
        limite noto e voluto, non una regressione."""
        tmp, vault, anon = make_engine()
        out = run(anon, vault, {"message": "login per mrossi"})
        self.assertIn("mrossi", out)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
