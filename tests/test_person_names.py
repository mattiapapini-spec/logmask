"""v0.19.0 — nomi di persona.

Regola: dalle liste generiche si maschera SOLO la coppia "Nome Cognome"
adiacente e capitalizzata. Il token singolo non si maschera mai da lista,
perche' cognomi come Costa/Monti/Riva e nomi internazionali come Will/May/
Mark/June sono anche parole comuni dei log: mascherarli isolati distrugge
verbi, date e brand (es. "Chase Bank" in un alert di phishing).
Il token singolo si maschera solo se e' in person_terms, cioe' se e' una
persona realmente esistente in quel tenant.
"""
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ORDER, Options, Vault,
                     load_person_lists)


def make_engine(**opt_kwargs):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "vault.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt_kwargs))


class PersonListTests(unittest.TestCase):
    def test_bundled_lists_load(self):
        given, family = load_person_lists()
        self.assertGreater(len(given), 50)
        self.assertGreater(len(family), 50)
        self.assertIn("mario", given)
        self.assertIn("rossi", family)


class NoFalsePositivesOnTechnicalLogTests(unittest.TestCase):
    """Le righe tecniche non devono essere toccate dalla regola nomi."""

    LINES = [
        "Alert: this rule will block traffic",
        "Scheduled scan may run again on August 14",
        "Analyst did not mark the alert as resolved",
        "Phishing page impersonating Chase Bank detected",
        "Policy 'King of the Hill' matched; action=allow",
        "Certificate valid until June 2026",
        "La costa adriatica non e' raggiungibile",
        "Access Denied for Service Account",
    ]

    def test_technical_text_untouched(self):
        tmp, vault, anon = make_engine()
        for line in self.LINES:
            with self.subTest(line=line):
                self.assertNotIn("person-", anon.process(line))
        tmp.cleanup()


class RealNamesAreMaskedTests(unittest.TestCase):
    def test_name_surname_pairs_masked(self):
        cases = ["Ticket assegnato a Mario Rossi per verifica",
                 "Login anomalo per Wei Chen da IP esterno",
                 "Segnalato da Andrzej Kowalski alle 09:12",
                 "Export AD: Rossi Mario, reparto IT"]      # ordine invertito
        tmp, vault, anon = make_engine()
        for line in cases:
            with self.subTest(line=line):
                out = anon.process(line)
                self.assertIn("person-", out)
                for token in ("Mario", "Rossi", "Wei", "Chen",
                              "Andrzej", "Kowalski"):
                    if token in line:
                        self.assertNotIn(token, out)
        tmp.cleanup()

    def test_same_person_same_token(self):
        tmp, vault, anon = make_engine()
        first = anon.process("a Mario Rossi")
        second = anon.process("per Mario Rossi")
        self.assertEqual(first.split("a ", 1)[1], second.split("per ", 1)[1])
        tmp.cleanup()

    def test_reversible(self):
        tmp, vault, anon = make_engine()
        masked = anon.process("Ticket per Mario Rossi")
        deanon = Deanonymizer(vault, anon.opt)
        self.assertEqual(deanon.process(masked), "Ticket per Mario Rossi")
        tmp.cleanup()

    def test_counter_reported(self):
        tmp, vault, anon = make_engine()
        anon.process("Mario Rossi e Wei Chen")
        self.assertGreaterEqual(anon.counts.get("person_name", 0), 2)
        tmp.cleanup()


class PersonTermsSingleTokenTests(unittest.TestCase):
    """Il token singolo si maschera solo dalla lista aziendale."""

    def test_single_token_not_masked_from_generic_lists(self):
        tmp, vault, anon = make_engine()
        self.assertNotIn("person-", anon.process("Ticket per Verdi"))
        self.assertNotIn("person-", anon.process("Ticket per Costa"))
        tmp.cleanup()

    def test_single_token_masked_from_person_terms(self):
        tmp, vault, anon = make_engine(person_terms=("Verdi", "Kowalski"))
        self.assertIn("person-", anon.process("Ticket per Verdi"))
        self.assertIn("person-", anon.process("Segnalato da Kowalski"))
        tmp.cleanup()

    def test_person_terms_do_not_break_technical_text(self):
        tmp, vault, anon = make_engine(person_terms=("Verdi",))
        out = anon.process("this rule will block traffic")
        self.assertNotIn("person-", out)
        tmp.cleanup()


class CapitalizedWordBeforeNameTests(unittest.TestCase):
    """Regressione: una parola capitalizzata che precede il nome (inizio frase)
    non deve "bruciare" la coppia vera. Con la sub diretta, "Contattare Giulia
    Ferrari" faceva match su (Contattare, Giulia) - scartata - e Ferrari non
    veniva piu' esaminata. Ora le coppie si valutano a finestra scorrevole."""

    CASES = ["Contattare Giulia Ferrari",
             "Alle 09:12 Paolo Conti ha aperto il caso",
             "Ieri Mario Rossi ha effettuato l'accesso",
             "Nota Marco Bianchi come owner"]

    def test_name_after_capitalized_word_is_masked(self):
        tmp, vault, anon = make_engine()
        for line in self.CASES:
            with self.subTest(line=line):
                self.assertIn("person-", anon.process(line))
        tmp.cleanup()

    def test_leading_word_preserved(self):
        tmp, vault, anon = make_engine()
        out = anon.process("Contattare Giulia Ferrari")
        self.assertTrue(out.startswith("Contattare "))
        tmp.cleanup()


class ProductNamesNotMistakenForPeopleTests(unittest.TestCase):
    """Coppie capitalizzate tecniche molto comuni nei log SOC."""

    LINES = ["Windows Defender Antivirus updated",
             "Microsoft Exchange Server 2019 patched",
             "Palo Alto Networks firewall rule",
             "Group Policy Object applied successfully",
             "Domain Controller replication failed",
             "Advanced Threat Protection enabled",
             "Data Loss Prevention policy matched",
             "Access Denied for Service Account",
             "Task Scheduler created new task",
             "Suspicious PowerShell Encoded Command detected",
             "Failed Login Attempt from External Network",
             "User Account Control prompt shown"]

    def test_product_and_technical_pairs_untouched(self):
        tmp, vault, anon = make_engine()
        for line in self.LINES:
            with self.subTest(line=line):
                self.assertNotIn("person-", anon.process(line))
        tmp.cleanup()


class NameFormatsTests(unittest.TestCase):
    """v0.20.0 — separatori e minuscole.

    I log scrivono i nomi in molti modi: "mario rossi", "mario.rossi",
    "mario_rossi", "rossi.mario", spesso senza maiuscole.
    """

    MASKED = ["Contattare Giulia Ferrari",
              "utente mario rossi ha effettuato accesso",
              "owner mario.rossi del ticket",
              "account mario_rossi creato",
              "id rossi.mario nel sistema",
              "segnalato da wei chen",
              "user andrzej-kowalski attivo",
              "Mario Rossi"]                       # coppia a bordo stringa

    def test_all_formats_masked(self):
        tmp, vault, anon = make_engine()
        for line in self.MASKED:
            with self.subTest(line=line):
                self.assertIn("person-", anon.process(line))
        tmp.cleanup()

    def test_pair_at_string_edges(self):
        """Regressione: "" e' sottostringa di qualsiasi stringa in Python, quindi
        il controllo dei confini scartava ogni coppia a inizio/fine riga."""
        tmp, vault, anon = make_engine()
        self.assertIn("person-", anon.process("Mario Rossi"))
        self.assertIn("person-", anon.process("ticket di Mario Rossi"))
        tmp.cleanup()

    def test_space_is_a_valid_separator_around_pair(self):
        """Regressione: lo spazio era finito fra i caratteri che invalidano la
        coppia, quindi non veniva mascherato piu' nulla."""
        tmp, vault, anon = make_engine()
        self.assertIn("person-", anon.process("aperto da Mario Rossi ieri"))
        tmp.cleanup()

    def test_not_masked_inside_email_fqdn_or_path(self):
        """Dentro e-mail/FQDN/percorso decidono le regole piu' specifiche."""
        tmp, vault, anon = make_engine()
        for line in ("invio a mario.rossi@azienda.it",
                     "host mario.rossi.corp.local raggiunto",
                     "file /home/mario.rossi/report.txt"):
            with self.subTest(line=line):
                self.assertNotIn("person-", anon.process(line))
        tmp.cleanup()

    def test_lowercase_technical_text_untouched(self):
        tmp, vault, anon = make_engine()
        for line in ("this rule will block traffic", "did not mark the alert",
                     "scan may run again", "access denied for service account",
                     "la costa adriatica non risponde", "connection reset by peer",
                     "il servizio non e' stato avviato", "no such file or directory"):
            with self.subTest(line=line):
                self.assertNotIn("person-", anon.process(line))
        tmp.cleanup()

    def test_reversible_with_separators(self):
        tmp, vault, anon = make_engine()
        masked = anon.process("owner mario.rossi del ticket")
        deanon = Deanonymizer(vault, anon.opt)
        self.assertEqual(deanon.process(masked), "owner mario.rossi del ticket")
        tmp.cleanup()


class InitialPlusSurnameTests(unittest.TestCase):
    """"mrossi" / "m.rossi": ammesso SOLO con person_terms. Dalle liste
    generiche spezzerebbe parole comuni ("scosta" = s+costa)."""

    def test_masked_only_with_person_terms(self):
        """Forma attaccata: serve una parola di contesto (utente/account/...).
        Forma con separatore: il separatore basta."""
        tmp, vault, anon = make_engine(person_terms=("Rossi", "Ferrari"))
        for line in ("utente mrossi loggato", "account m.rossi attivo",
                     "user g_ferrari", "login mrossi ok"):
            with self.subTest(line=line):
                self.assertIn("person-", anon.process(line))
        tmp.cleanup()

    def test_not_masked_without_person_terms(self):
        tmp, vault, anon = make_engine()
        self.assertNotIn("person-", anon.process("utente mrossi loggato"))
        tmp.cleanup()

    def test_common_words_never_split(self):
        """Anche con un cliente che ha davvero un dipendente "Costa", parole
        come "scosta"/"amare"/"discosta" non devono essere spezzate: senza una
        parola di contesto la forma attaccata non viene considerata."""
        tmp, vault, anon = make_engine(person_terms=("Costa", "Mare"))
        out = anon.process("parola scosta e amare nel testo")
        self.assertIn("scosta", out)
        self.assertIn("amare", out)
        self.assertIn("discosta", anon.process("la nave si discosta dalla riva"))
        tmp.cleanup()


class SeparatorEdgeCasesTests(unittest.TestCase):
    """v0.20.1 (bug hunt) — il separatore non e' solo il singolo spazio.

    Gli export reali usano tab (TSV), allineamenti a piu' spazi e la forma
    "Cognome, Nome" di AD/LDAP. Con il solo spazio singolo questi nomi
    restavano in chiaro.
    """

    MASKED = ["Mario  Rossi",                       # due spazi
              "Mario\tRossi",                       # tab
              "utente\tMario\tRossi\tattivo",       # TSV
              "Mario     Rossi      admin",         # tabella allineata
              "Rossi, Mario",                       # AD "Cognome, Nome"
              "displayName: Ferrari, Giulia"]

    def test_real_world_separators(self):
        tmp, vault, anon = make_engine()
        for line in self.MASKED:
            with self.subTest(line=repr(line)):
                self.assertIn("person-", anon.process(line))
        tmp.cleanup()

    def test_newline_and_repeated_separator_excluded(self):
        """Un nome non si spezza su due righe, e ".." non e' un separatore."""
        tmp, vault, anon = make_engine()
        self.assertNotIn("person-", anon.process("Mario\nRossi"))
        self.assertNotIn("person-", anon.process("mario..rossi"))
        tmp.cleanup()

    def test_comma_lists_are_not_people(self):
        """La virgola serve al formato AD ma e' anche il separatore degli
        elenchi: una coppia circondata da virgole e' una lista, non una
        persona."""
        tmp, vault, anon = make_engine()
        for line in ("Costa, Monti, Riva sono nodi",
                     "Rossi, Bianchi, Verdi in elenco",
                     "tag: alert, malware, threat",
                     "host list: web01, web02, srv01",
                     "Windows Defender, Microsoft Exchange"):
            with self.subTest(line=line):
                self.assertNotIn("person-", anon.process(line))
        tmp.cleanup()

    def test_reversible_with_real_separators(self):
        tmp, vault, anon = make_engine()
        deanon = Deanonymizer(vault, anon.opt)
        for line in ("Mario\tRossi", "Rossi, Mario", "Mario  Rossi"):
            with self.subTest(line=repr(line)):
                self.assertEqual(deanon.process(anon.process(line)), line)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
