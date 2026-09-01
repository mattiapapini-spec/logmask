"""v0.23.5 - IBAN e telefoni sfuggivano alla rilevazione in prosa. Due fughe.

IBAN: lo spazio opzionale del pattern faceva proseguire il match dentro le
parole successive. "IT60...456 poi" diventava un unico candidato, il mod-97
falliva sul blob esteso e l'IBAN vero non veniva MAI riesaminato, perche' la
scansione riparte dopo il match. In prosa italiana ("bonifico su DE89...
eseguito") l'IBAN restava in chiaro quasi sempre. Ora, se il match esteso non
valida, si riprova togliendo una parola alla volta da destra.

Telefono: l'etichetta richiedeva ":" o "=". "tel. +39 335 1234567" - la forma
delle firme italiane - e i numeri internazionali nudi non venivano mai
rilevati. Ora bastano punto o spazio dopo l'etichetta, e la forma "+CC ..."
con almeno 9 cifre e' riconosciuta anche senza etichetta; fusi orari (+0200,
+02:00) e stringhe di versione restano fuori.
"""
import unittest

from logmask import NO_ELISION_DLP_POLICY, scan_sensitive_residuals

POL = dict(NO_ELISION_DLP_POLICY)


def kinds_and_values(text):
    return [(f["kind"], str(f["value"])) for f in scan_sensitive_residuals(text, POL)]


class IbanInProseTests(unittest.TestCase):
    CASES = {
        "IBAN IT60X0542811101000000123456 poi resto": "IT60X0542811101000000123456",
        "bonifico su DE89370400440532013000 eseguito": "DE89370400440532013000",
        "IBAN IT60X0542811101000000123456, resto": "IT60X0542811101000000123456",
        "IT60X0542811101000000123456": "IT60X0542811101000000123456",
        "codice FR1420041010050500013M02606 ok": "FR1420041010050500013M02606",
    }

    def test_iban_followed_by_words_is_found(self):
        for text, iban in self.CASES.items():
            with self.subTest(text=text[:40]):
                found = kinds_and_values(text)
                self.assertIn(("iban", iban), found)

    def test_spaced_iban_is_found(self):
        found = kinds_and_values("IT60 X054 2811 1010 0000 0123 456 spaziato")
        self.assertTrue(any(k == "iban" and v.startswith("IT60 X054") for k, v in found))

    def test_invalid_checksum_is_not_flagged(self):
        self.assertEqual([k for k, _ in kinds_and_values("IT99X0542811101000000123456 x")
                          if k == "iban"], [])


class PhoneTests(unittest.TestCase):
    def test_label_with_dot(self):
        self.assertIn(("phone", "+39 335 1234567"),
                      kinds_and_values("tel. +39 335 1234567 chiama"))

    def test_label_with_space_only(self):
        found = kinds_and_values("Telefono +39 06 4952 1")
        self.assertTrue(any(k == "phone" for k, _ in found))

    def test_bare_international_number(self):
        self.assertIn(("phone", "+39 335 1234567"),
                      kinds_and_values("chiama il +39 335 1234567 subito"))

    def test_bare_compact_international(self):
        self.assertIn(("phone", "+393351234567"),
                      kinds_and_values("+393351234567 diretto"))

    def test_labeled_with_colon_still_works(self):
        found = kinds_and_values("phone: 555 123 4567")
        self.assertTrue(any(k == "phone" for k, _ in found))

    def test_no_false_positives(self):
        for text in ("timestamp 2026-07-01T10:00:00+0200", "offset +02:00 ok",
                     "versione v1.2+345", "cell 42", "+12 34 corto", "UTC +1 ora",
                     "coordinate +41 52 12"):
            with self.subTest(text=text):
                self.assertEqual([k for k, _ in kinds_and_values(text) if k == "phone"],
                                 [])


class EmbeddedDlpPassTests(unittest.TestCase):
    """Le stesse forme devono essere viste anche dal passaggio DLP del motore."""

    def test_engine_masks_iban_and_phone_in_prose(self):
        import tempfile
        from pathlib import Path
        from logmask import Anonymizer, Deanonymizer, ORDER, Options, Vault
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                      ip_mode="all", dlp_policy=POL)
        anon = Anonymizer(vault, set(ORDER), opt)
        out = anon.process("bonifico su DE89370400440532013000, tel. +39 335 1234567")
        self.assertNotIn("DE89370400440532013000", out)
        self.assertNotIn("1234567", out)
        back = Deanonymizer(vault, opt).process(out)
        self.assertIn("DE89370400440532013000", back)
        self.assertIn("+39 335 1234567", back)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
