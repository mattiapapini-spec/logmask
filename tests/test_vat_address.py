"""v0.25.0 - partita IVA / VAT e indirizzi fisici, italiani e inglesi.

Due dati che in un documento o in un'e-mail identificano il cliente in modo
diretto e che finora uscivano in chiaro: la partita IVA (nessun
riconoscimento) e gli indirizzi non etichettati o in inglese (si riconosceva
solo "indirizzo: via ..." con i due punti e i soli tipi di strada italiani).

Il rischio opposto e' altrettanto concreto: "via" in un log SOC e' quasi
sempre la preposizione - "Potential RMM Tool Installation via Uncommon
Process", "esfiltrazione via DNS", "traffic via proxy 8080" - e 11 cifre di
seguito sono un record id molto piu' spesso che una partita IVA. Per questo la
P.IVA nuda passa dal controllo di Luhn e le forme di indirizzo non etichettate
esigono un nome proprio (iniziale maiuscola, non un acronimo) piu' un numero
civico. I suffissi inglesi ambigui - Way, Drive, Place, Court - sono ammessi
solo con etichetta esplicita.
"""
import tempfile
import unittest
from pathlib import Path

import dlp
from logmask import (Anonymizer, Deanonymizer, NO_ELISION_DLP_POLICY, ORDER,
                     Options, Vault, scan_sensitive_residuals)

POL = dict(NO_ELISION_DLP_POLICY)


def found(text):
    return [(f["kind"], str(f["value"])) for f in scan_sensitive_residuals(text, POL)]


def kinds(text):
    return {k for k, _ in found(text)}


def engine():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                  ip_mode="all", dlp_policy=POL)
    return tmp, vault, Anonymizer(vault, set(ORDER), opt), opt


class VatDetectionTests(unittest.TestCase):
    VALID = ["P.IVA 00743110157", "Partita IVA: 00743110157", "PIVA IT00743110157",
             "VAT number GB123456789", "VAT: DE811569869", "vat_id=IT00743110157",
             "C.F./P.IVA 00743110157", "IT00743110157", "VAT Reg No. GB123456789"]

    def test_valid_vat_is_detected(self):
        for text in self.VALID:
            with self.subTest(text=text):
                self.assertIn("vat", kinds(text))

    def test_luhn_rejects_invalid_italian_vat(self):
        self.assertNotIn("vat", kinds("P.IVA 12345678901"))
        self.assertNotIn("vat", kinds("IT12345678901"))

    def test_log_numbers_are_not_vat(self):
        for text in ("record_id 12345678901", "epoch 1750000000000",
                     "event.code 4624 su host", "port 8080 pid 4321",
                     "hash 00000000000"):
            with self.subTest(text=text):
                self.assertNotIn("vat", kinds(text))

    def test_trailing_punctuation_is_not_masked(self):
        hits = [v for k, v in found("P.IVA 00743110157.") if k == "vat"]
        self.assertEqual(hits, ["00743110157"])

    def test_category_exists_with_pseudonymize_default(self):
        self.assertEqual(dlp.DLP_CATEGORIES["vat_id"]["default"], "pseudonymize")
        self.assertEqual(dlp.DLP_CATEGORIES["vat_id"]["kind"], "vat")

    def test_field_name_is_recognized(self):
        for field in ("vat", "vat_number", "partita_iva", "p_iva", "company.vat_id"):
            with self.subTest(field=field):
                self.assertEqual(dlp.category_for_field(field, "IT00743110157"), "vat_id")


class ItalianAddressTests(unittest.TestCase):
    VALID = ["Via Roma 12, Milano", "residente in via Giuseppe Garibaldi 145/A",
             "Piazza San Marco 1", "Viale Europa 22", "loc. Casalino 7",
             "corso Vittorio Emanuele II 33", "V.le Certosa 100"]

    def test_addresses_are_detected(self):
        for text in self.VALID:
            with self.subTest(text=text):
                self.assertIn("address", kinds(text))

    def test_via_as_preposition_is_not_an_address(self):
        """Il falso positivo che avrebbe distrutto ogni log SOC."""
        for text in ("Potential RMM Tool Installation via Uncommon Process",
                     "traffic via proxy 8080", "connessione via VPN 2 volte",
                     "downloaded via HTTP 443", "escalation via CVE 2024",
                     "log via syslog 514", "exfil via DNS 53", "via TLS 1.2"):
            with self.subTest(text=text):
                self.assertNotIn("address", kinds(text))


class EnglishAddressTests(unittest.TestCase):
    VALID = ["123 Main Street, Springfield", "10 Downing Street London",
             "1600 Pennsylvania Avenue NW", "42 Baker St.", "5 Elm Road",
             "221B Baker Street", "77 Sunset Boulevard"]

    def test_addresses_are_detected(self):
        for text in self.VALID:
            with self.subTest(text=text):
                self.assertIn("address", kinds(text))

    def test_ambiguous_suffixes_need_a_label(self):
        """Way, Drive, Place, Court sono parole comuni: senza etichetta no."""
        self.assertNotIn("address", kinds("8080 Proxy Way listening"))
        self.assertNotIn("address", kinds("10 Downing Place"))
        self.assertIn("address", kinds("Billing address = 1 Microsoft Way, Redmond"))

    def test_log_lines_are_not_addresses(self):
        for text in ("4624 Logon Type 3", "500 Internal Server Error",
                     "process 1234 Command Line", "2 Factor Authentication",
                     "C:\\Users\\x\\Drive\\f.txt", "version 1.2 Release Notes"):
            with self.subTest(text=text):
                self.assertNotIn("address", kinds(text))

    def test_po_box(self):
        for text in ("PO Box 1234", "P.O. Box 77", "casella postale 9", "C.P. 45"):
            with self.subTest(text=text):
                self.assertIn("address", kinds(text))


class EndToEndTests(unittest.TestCase):
    CASES = [
        "Cliente Alfa Srl, P.IVA 00743110157, sede legale Viale Europa 22, 20100 Milano",
        "Invoice to 123 Main Street, Springfield IL - VAT number GB123456789",
        "Fattura a IT00743110157, spedire in via Giuseppe Garibaldi 145/A",
        "PO Box 1234, London",
    ]

    def test_clear_values_do_not_survive(self):
        tmp, _v, anon, _o = engine()
        for text in self.CASES:
            with self.subTest(text=text[:40]):
                out = anon.process(text)
                for clear in ("00743110157", "GB123456789", "Viale Europa 22",
                              "123 Main Street", "Giuseppe Garibaldi",
                              "PO Box 1234"):
                    if clear in text:
                        self.assertNotIn(clear, out)
        tmp.cleanup()

    def test_round_trip(self):
        tmp, vault, anon, opt = engine()
        deanon = Deanonymizer(vault, opt)
        for text in self.CASES:
            with self.subTest(text=text[:40]):
                self.assertEqual(deanon.process(anon.process(text)), text)
        tmp.cleanup()

    def test_pseudonym_shapes(self):
        tmp, _v, anon, _o = engine()
        out = anon.process("P.IVA 00743110157 in Via Roma 12")
        self.assertIn("vat-", out)
        self.assertIn("addr-", out)
        tmp.cleanup()

    def test_soc_subject_lines_are_untouched(self):
        tmp, _v, anon, _o = engine()
        for text in ("[SOC] Potential RMM Tool Installation via Uncommon Process",
                     "Suspicious Double Extension File Creation",
                     "Windows Local Security Authority Registry Configuration Manipulation",
                     "traffic via proxy 8080, record_id 12345678901"):
            with self.subTest(text=text[:40]):
                self.assertEqual(anon.process(text), text)
        tmp.cleanup()

    def test_same_value_same_pseudonym(self):
        tmp, _v, anon, _o = engine()
        a = anon.process("P.IVA 00743110157")
        b = anon.process("fornitore con P.IVA 00743110157 attivo")
        self.assertIn(a.split()[-1], b)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
