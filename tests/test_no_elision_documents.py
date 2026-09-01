"""v0.23.0 - documenti (.docx) e archivi di posta (.pst): pseudonimi, mai elisioni.

In un log l'elisione e' accettabile: il campo sparisce e l'analisi prosegue.
In un documento o in un'e-mail e' un danno netto - il file restituito perde il
testo e il ripristino non puo' ricostruirlo, perche' non c'e' niente da
invertire. Su questi due percorsi ogni valore sensibile diventa quindi uno
pseudonimo.

I segreti fanno eccezione su un punto solo: sono deterministici (stessa
password -> stesso token, le occorrenze restano correlabili) ma non vengono
mai scritti nel vault. Cosi' il documento resta leggibile e nessuno trasforma
lo strumento in un deposito di password e chiavi private dei clienti.
"""
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ELIDED, NO_ELISION_DLP_POLICY,
                     ORDER, Options, Vault, pseudonymize_residuals, sweep_known)

SECRETS = ("password=Estate2024!", "api_key=sk-live-9f3a2b7c1d4e5f60a1b2",
           "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmno")
REVERSIBLE = {
    "IBAN IT60X0542811101000000123456": "IT60X0542811101000000123456",
    "CF VRGSRA76B55H501Z": "VRGSRA76B55H501Z",
    "scrivi a mario.rossi@acmespa.it": "mario.rossi@acmespa.it",
    "server SRV-MAIL01.corp.local": "SRV-MAIL01.corp.local",
    "da 10.20.30.40": "10.20.30.40",
    "id 6f0c9a7e-4d2b-4c31-9a0e-77b1c2d3e4f5": "6f0c9a7e-4d2b-4c31-9a0e-77b1c2d3e4f5",
}


def engine():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                  ip_mode="all", client_terms=("Acme Spa",),
                  client_term_mode="pseudonymize",
                  dlp_policy=dict(NO_ELISION_DLP_POLICY))
    return tmp, vault, Anonymizer(vault, set(ORDER), opt), opt


def scrub(anon, vault, opt, text):
    """La catena usata dagli endpoint .docx e .pst."""
    out = anon.process(text)
    out, _ = sweep_known(vault, out, opt)
    out, _n, _kinds = pseudonymize_residuals(out, anon, opt.dlp_policy)
    return out


class NoElisionTests(unittest.TestCase):
    def test_secrets_are_pseudonymized_not_elided(self):
        tmp, vault, anon, opt = engine()
        for line in SECRETS:
            with self.subTest(line=line[:20]):
                out = scrub(anon, vault, opt, line)
                self.assertNotIn(ELIDED, out)
                self.assertIn("secret-", out)
        tmp.cleanup()

    def test_no_elision_anywhere_in_a_mixed_document(self):
        tmp, vault, anon, opt = engine()
        text = "\n".join(list(SECRETS) + list(REVERSIBLE) + ["Cliente Acme Spa"])
        self.assertNotIn(ELIDED, scrub(anon, vault, opt, text))
        tmp.cleanup()

    def test_clear_values_do_not_survive(self):
        tmp, vault, anon, opt = engine()
        text = "\n".join(list(SECRETS) + list(REVERSIBLE) + ["Cliente Acme Spa"])
        out = scrub(anon, vault, opt, text)
        for clear in ("Estate2024!", "sk-live-9f3a2b7c1d4e5f60a1b2", "Acme Spa",
                      *REVERSIBLE.values()):
            with self.subTest(clear=clear[:24]):
                self.assertNotIn(clear, out)
        tmp.cleanup()


class SecretsAreNeverVaultedTests(unittest.TestCase):
    def test_same_secret_same_token(self):
        tmp, vault, anon, opt = engine()
        a = scrub(anon, vault, opt, "password=Estate2024!")
        b = scrub(anon, vault, opt, "altra riga con password=Estate2024! dentro")
        self.assertIn(a.split("password=")[1].strip(), b)
        tmp.cleanup()

    def test_different_secrets_different_tokens(self):
        tmp, vault, anon, opt = engine()
        a = scrub(anon, vault, opt, "password=Estate2024!")
        b = scrub(anon, vault, opt, "password=Inverno2025!")
        self.assertNotEqual(a, b)
        tmp.cleanup()

    def test_secret_is_not_recoverable(self):
        tmp, vault, anon, opt = engine()
        out = scrub(anon, vault, opt, "password=Estate2024!")
        self.assertNotIn("Estate2024!", Deanonymizer(vault, opt).process(out))
        tmp.cleanup()

    def test_secret_never_stored_in_the_vault(self):
        """Il controllo che conta: il valore in chiaro non deve stare nel DB."""
        tmp, vault, anon, opt = engine()
        scrub(anon, vault, opt, "password=Estate2024! e api_key=sk-live-9f3a2b7c1d4e")
        vault.commit()
        blob = Path(vault.db_path if hasattr(vault, "db_path") else
                    Path(tmp.name) / "v.db").read_bytes()
        self.assertNotIn(b"Estate2024!", blob)
        self.assertNotIn(b"sk-live-9f3a2b7c1d4e", blob)
        tmp.cleanup()

    def test_tenants_get_different_tokens(self):
        t1, v1, a1, o1 = engine()
        t2 = tempfile.TemporaryDirectory()
        v2 = Vault(Path(t2.name) / "v.db", b"B" * 32)
        a2 = Anonymizer(v2, set(ORDER), o1)
        self.assertNotEqual(scrub(a1, v1, o1, "password=Estate2024!"),
                            scrub(a2, v2, o1, "password=Estate2024!"))
        t1.cleanup(); t2.cleanup()


class EverythingElseStaysReversibleTests(unittest.TestCase):
    def test_round_trip(self):
        tmp, vault, anon, opt = engine()
        for line, clear in REVERSIBLE.items():
            with self.subTest(value=clear):
                out = scrub(anon, vault, opt, line)
                self.assertNotIn(clear, out)
                self.assertIn(clear, Deanonymizer(vault, opt).process(out))
        tmp.cleanup()

    def test_masked_email_is_not_masked_twice(self):
        """Regressione: "person-xxxx@yyyy.masked" non era riconosciuto come un
        NOSTRO pseudonimo, quindi il passaggio sui residui lo ri-mascherava e
        il ripristino restituiva un altro pseudonimo invece dell'originale."""
        tmp, vault, anon, opt = engine()
        once = scrub(anon, vault, opt, "scrivi a mario.rossi@acmespa.it")
        twice = scrub(anon, vault, opt, once)
        self.assertEqual(once, twice)
        self.assertIn("mario.rossi@acmespa.it",
                      Deanonymizer(vault, opt).process(twice))
        tmp.cleanup()

    def test_pseudonyms_are_stable_across_documents(self):
        """Lo stesso host in due documenti diversi deve dare lo stesso token."""
        tmp, vault, anon, opt = engine()
        a = scrub(anon, vault, opt, "primo documento: SRV-MAIL01.corp.local")
        b = scrub(anon, vault, opt, "secondo documento: SRV-MAIL01.corp.local")
        self.assertEqual(a.split(": ")[1], b.split(": ")[1])
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
