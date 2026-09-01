"""v0.21.2 — codice fiscale incastonato in un token (path, nome file).

Un CF in un segmento di path Windows
("...\\Temp\\tmpxq_VRGSRA76B55H501Z\\") usciva IN CHIARO: il boundary \\b non
scattava, perche' "_" e' un word-char. Il CF e' un identificativo piu' forte
dell'username, quindi era un leak grave. Ora viene riconosciuto anche dentro un
token (confini "non lettera-non cifra"), validato col carattere di controllo
per escludere i falsi positivi, e resta reversibile.
"""
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ORDER, Options, Vault,
                     normalize_dlp_policy, scan_sensitive_residuals)

# CF formalmente validi (carattere di controllo corretto).
CF_A = "VRGSRA76B55H501Z"
CF_B = "DROCRN66M44H501A"


def make_engine():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options())


class CodiceFiscaleInPathTests(unittest.TestCase):
    def test_cf_in_windows_temp_path_is_masked(self):
        tmp, vault, anon = make_engine()
        for cf, path in (
            (CF_A, r"C:\Users\x\AppData\Local\Temp\tmpxq_VRGSRA76B55H501Z\modulo.pdf"),
            (CF_B, r"C:\Users\y\Temp\tmpxq_DROCRN66M44H501A\out.tmp"),
        ):
            with self.subTest(cf=cf):
                out = anon.process(f"CommandLine: {path}")
                self.assertNotIn(cf, out)
                self.assertIn("cf-", out)
        tmp.cleanup()

    def test_cf_in_filename_is_masked(self):
        tmp, vault, anon = make_engine()
        out = anon.process(r"file C:\tmp\modulo-VRGSRA76B55H501Z-2026.pdf")
        self.assertNotIn(CF_A, out)
        tmp.cleanup()

    def test_bare_cf_still_masked(self):
        tmp, vault, anon = make_engine()
        self.assertNotIn(CF_A, anon.process(f"codice fiscale {CF_A}"))
        tmp.cleanup()

    def test_reversible_from_inside_path(self):
        tmp, vault, anon = make_engine()
        original = r"Temp\tmpxq_VRGSRA76B55H501Z\modulo.pdf"
        masked = anon.process(original)
        self.assertNotIn(CF_A, masked)
        self.assertEqual(Deanonymizer(vault, anon.opt).process(masked), original)
        tmp.cleanup()

    def test_no_false_positive_on_hash_guid_path(self):
        policy = normalize_dlp_policy(None)
        for text in (
            "1d5491e3c468ee4b4ef6edff4bbc7d06ee83180f6f0b1576763ea2efe049493a",  # sha256
            "{c5d2b969-0144-64ab-ab0d-000000001a01}",                            # guid
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",         # path
            "ABCDEF12G34H567I",                                                   # 16 char, checksum errato
        ):
            with self.subTest(text=text[:32]):
                findings = [f for f in scan_sensitive_residuals(text, policy)]
                self.assertEqual(findings, [])

    def test_username_pseudonym_still_reverses(self):
        """Il confine rilassato di PSEUDO_RX non deve rompere i token normali."""
        tmp, vault, anon = make_engine()
        masked = anon.process("user=mrossi da host srv01")
        self.assertEqual(Deanonymizer(vault, anon.opt).process(masked).split("da")[0],
                         "user=mrossi ")
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
