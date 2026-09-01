"""v0.23.2 - in prosa lo sweep del vault non deve sostituire parole comuni.

Il vault di un cliente accumula, job dopo job, valori classificati male: "SOC",
"Sicurezza", "Windows", "gruppo", "File" finiti sotto user o windomain perche'
in QUEL log occupavano quella posizione. Su un altro log strutturato la
sostituzione non fa danno. In un oggetto di e-mail o in un paragrafo di
documento si': un oggetto reale come

    [SOC] Segnalazione di Sicurezza - [Heuristic Attribute] Possible Masquerading Behavior

diventava

    [usr-lry4sswj] Segnalazione di DOM-4wf4ihxo - [Heuristic Attribute] id-v24z3wsg2g7m Masquerading Behavior

cioe' illeggibile, per ogni messaggio e in modo retroattivo. Nei percorsi in
linguaggio naturale si sostituiscono quindi solo gli originali che non possono
essere parole comuni.
"""
import tempfile
import unittest
from pathlib import Path

import logmask
from logmask import (Anonymizer, ORDER, Options, Vault, sweep_known,
                     sweepable_prose_original, NO_ELISION_DLP_POLICY)

# parole comuni finite nel vault con un kind sbagliato
POISON = (("user", "SOC"), ("windomain", "Sicurezza"), ("opaque", "Possible"),
          ("user", "Windows"), ("windomain", "Security"), ("windomain", "Authority"),
          ("user", "File"), ("user", "gruppo"), ("user", "Group"), ("opaque", "First"))
# identita' vere, che devono continuare a essere sostituite anche in prosa
REAL = (("user", "m.rossi"), ("fqdn", "srv-mail01.corp.local"),
        ("email", "mario.rossi@acmespa.it"), ("user", "Mario Rossi"),
        ("windomain", "corp-it"), ("user", "wks0421"))

SUBJECTS = [
    "[SOC] Segnalazione di Sicurezza - [Heuristic Attribute] Possible Masquerading Behavior",
    "[SOC] Segnalazione di Sicurezza - Windows Local Security Authority Registry Configuration Manipulation",
    "[SOC] Segnalazione di Sicurezza - Eliminazione del gruppo Linux tm_dsa",
    "[SOC] Segnalazione di Sicurezza - First Time Seen Driver Loaded",
    "[SOC] Segnalazione di Sicurezza - Suspicious Double Extension File Creation",
]


def poisoned():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                  ip_mode="all")
    anon = Anonymizer(vault, set(ORDER), opt)
    for kind, value in POISON + REAL:
        anon._map(kind, value)
    vault.commit()
    return tmp, vault, anon, opt


class SweepablePropseOriginalTests(unittest.TestCase):
    def test_common_words_are_not_sweepable(self):
        for word in ("SOC", "Sicurezza", "Possible", "Windows", "Security",
                     "Authority", "File", "gruppo", "Group", "First", "Behavior"):
            with self.subTest(word=word):
                self.assertFalse(sweepable_prose_original(word))

    def test_identifiers_are_sweepable(self):
        for value in ("m.rossi", "srv-mail01.corp.local", "mario.rossi@acmespa.it",
                      "wks0421", "corp-it", "tm_dsa", "CORP\\utente", "Mario Rossi"):
            with self.subTest(value=value):
                self.assertTrue(sweepable_prose_original(value))

    def test_very_short_values_are_never_sweepable(self):
        for value in ("", "a", "IT", "  "):
            with self.subTest(value=repr(value)):
                self.assertFalse(sweepable_prose_original(value))


class SubjectsSurviveTests(unittest.TestCase):
    def test_subjects_are_untouched(self):
        tmp, vault, _anon, opt = poisoned()
        for subject in SUBJECTS:
            with self.subTest(subject=subject[:40]):
                out, hits = sweep_known(vault, subject, opt, prose=True)
                self.assertEqual(out, subject)
                self.assertEqual(hits, 0)
        tmp.cleanup()

    def test_no_pseudonym_token_injected(self):
        tmp, vault, _anon, opt = poisoned()
        for subject in SUBJECTS:
            out, _ = sweep_known(vault, subject, opt, prose=True)
            for prefix in ("usr-", "DOM-", "id-", "host-"):
                with self.subTest(subject=subject[:30], prefix=prefix):
                    self.assertNotIn(prefix, out)
        tmp.cleanup()


class RealIdentitiesStillSweptTests(unittest.TestCase):
    def test_identifiers_are_replaced_in_prose(self):
        tmp, vault, _anon, opt = poisoned()
        text = ("accesso di m.rossi al server srv-mail01.corp.local, scrive a "
                "mario.rossi@acmespa.it dal dominio corp-it sulla postazione wks0421")
        out, hits = sweep_known(vault, text, opt, prose=True)
        for clear in ("m.rossi", "srv-mail01.corp.local", "mario.rossi@acmespa.it",
                      "corp-it", "wks0421"):
            with self.subTest(clear=clear):
                self.assertNotIn(clear, out)
        self.assertGreaterEqual(hits, 5)
        tmp.cleanup()

    def test_two_word_identities_are_replaced(self):
        tmp, vault, _anon, opt = poisoned()
        out, _ = sweep_known(vault, "ha firmato Mario Rossi in calce", opt, prose=True)
        self.assertNotIn("Mario Rossi", out)
        tmp.cleanup()


class StructuredLogsAreUnaffectedTests(unittest.TestCase):
    def test_default_behaviour_unchanged(self):
        """Senza prose=True lo sweep resta quello di prima: i log strutturati
        non cambiano comportamento."""
        tmp, vault, _anon, opt = poisoned()
        out, hits = sweep_known(vault, "user=SOC domain=Sicurezza", opt)
        self.assertNotIn("SOC", out)
        self.assertGreater(hits, 0)
        tmp.cleanup()


class BothStrategiesAgreeTests(unittest.TestCase):
    def test_from_text_and_from_vault_agree_in_prose(self):
        """Le due strategie di sweep devono dare lo stesso risultato."""
        tmp, vault, _anon, opt = poisoned()
        text = SUBJECTS[1] + " - accesso di m.rossi da wks0421"
        from_text, _ = sweep_known(vault, text, opt, prose=True)
        from_vault, _ = logmask._sweep_from_vault(
            vault, text, opt, set(logmask.SWEEP_KINDS), True)
        self.assertEqual(from_text, from_vault)
        self.assertIn("Security Authority", from_text)
        self.assertNotIn("m.rossi", from_text)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()


class ProseIdentityFalsePositiveTests(unittest.TestCase):
    """v0.26.2 - "user"/"account" seguiti da una parola comune NON sono
    un'identita'. La 0.25.2 li mascherava tutti ("user experience" ->
    "user usr-xxxx"), corrompendo log e documenti. Ora serve la forma di
    identificatore (cifra/punto/underscore) oppure un verbo di autenticazione
    vicino."""

    COMMON_PHRASES = [
        "user experience is good", "account balance was 500 EUR",
        "user story completed", "account manager meeting scheduled",
        "by user request logged in the ticket", "for user convenience only",
        "user input validation failed", "account lockout policy applied",
        "user agent Mozilla Firefox", "user interface redesign",
        "account settings page opened", "An account was successfully logged on",
        "user was created yesterday", "account has been disabled by admin",
        "user permissions updated", "account credentials rotated",
    ]

    AUTH_NARRATIVES = {
        "User mrossi logged on to WKS0421": "mrossi",
        "utente gverdi ha effettuato accesso": "gverdi",
        "account m.bianchi disabilitato": "m.bianchi",
        "user svc_backup authenticated successfully": "svc_backup",
        "User jdoe signed in from remote host": "jdoe",
        "account user01 connected to the vpn": "user01",
    }

    def _engine(self):
        import tempfile
        from pathlib import Path
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        opt = Options(ip_mode="all", dlp_policy=dict(NO_ELISION_DLP_POLICY))
        return tmp, Anonymizer(vault, set(ORDER), opt)

    def test_common_phrases_are_untouched(self):
        tmp, anon = self._engine()
        for phrase in self.COMMON_PHRASES:
            with self.subTest(phrase=phrase):
                self.assertEqual(anon.process(phrase), phrase)
        tmp.cleanup()

    def test_auth_narratives_still_mask_the_username(self):
        tmp, anon = self._engine()
        for phrase, username in self.AUTH_NARRATIVES.items():
            with self.subTest(phrase=phrase):
                self.assertNotIn(username, anon.process(phrase))
        tmp.cleanup()

    def test_no_redos(self):
        import time
        tmp, anon = self._engine()
        t0 = time.perf_counter()
        anon.process("user " + "word " * 4000)
        self.assertLess(time.perf_counter() - t0, 2.0)
        tmp.cleanup()
