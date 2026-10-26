"""v0.25.1 - identita' dentro i messaggi Event Log e i JSON serializzati.

Da una query XQL che proietta solo i campi dell'Event Log Windows -

    | alter Event_Data = to_json_string(action_evtlog_data_fields)
    | fields _time, agent_hostname, action_evtlog_event_id,
             action_evtlog_provider_name, action_evtlog_message, Event_Data

- non usciva mascherato quasi nulla. Tre difetti sovrapposti:

1. Nessuna regola per la famiglia action_evtlog_*: il kit Cortex non veniva
   nemmeno riconosciuto (un solo fingerprint su sei colonne) e il messaggio
   dell'evento restava in chiaro, o veniva eliso per intero in Safe mode -
   perdendo l'evidenza invece di proteggerla.
2. action_evtlog_event_id finiva sul catch-all .*_(id)$ e veniva mascherato:
   un event id e' un codice di prodotto, non un identificativo del cliente.
3. Anche riconosciuto come testo, il messaggio conservava le identita': sono
   dichiarate come "Account Name: mrossi", una forma che il motore non
   riconosceva. Stessa cosa per il JSON serializzato in cella
   ("SubjectUserName": "mrossi"). Vale per qualunque prodotto: lo stesso testo
   compare in Elastic (message), Wazuh (full_log), Splunk (_raw).
"""
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, CsvAnonymizer, Deanonymizer, NO_ELISION_DLP_POLICY,
                     ORDER, Options, Vault, apply_safe_policy, default_policy,
                     detect_vendor_kit, read_samples, resolve_field)

COLUMNS = ["_time", "agent_hostname", "action_evtlog_event_id",
           "action_evtlog_provider_name", "action_evtlog_message", "Event_Data"]
EVENT_DATA = json.dumps({
    "SubjectUserName": "mrossi", "SubjectDomainName": "CORP",
    "TargetUserName": "gverdi", "TargetDomainName": "ACMESPA",
    "WorkstationName": "WKS0421", "IpAddress": "10.20.30.40", "LogonType": "3"})
MESSAGE = ("An account was successfully logged on.\n\tAccount Name:\t\tmrossi\n"
           "\tAccount Domain:\t\tCORP\n\tWorkstation Name:\tWKS0421\n"
           "\tSource Network Address:\t10.20.30.40\n\tTarget User Name:\tgverdi\n")
SECRETS = ("mrossi", "gverdi", "WKS0421", "10.20.30.40", "SRV-DC01", "ACMESPA", "CORP")


def engine():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                  ip_mode="all", dlp_policy=dict(NO_ELISION_DLP_POLICY))
    return tmp, vault, Anonymizer(vault, set(ORDER), opt), opt


def export_csv(path: Path, rows: int = 3) -> None:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, quoting=csv.QUOTE_ALL,
                            lineterminator="\r\n")
    writer.writeheader()
    for i in range(rows):
        writer.writerow({
            "_time": f"2026-08-04T09:1{i}:33Z", "agent_hostname": "SRV-DC01",
            "action_evtlog_event_id": "4624",
            "action_evtlog_provider_name": "Microsoft-Windows-Security-Auditing",
            "action_evtlog_message": MESSAGE, "Event_Data": EVENT_DATA})
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(buf.getvalue())


class IdentityInFreeTextTests(unittest.TestCase):
    def test_windows_event_message(self):
        tmp, _v, anon, _o = engine()
        out = anon.process(MESSAGE)
        for clear in ("mrossi", "gverdi", "CORP", "WKS0421", "10.20.30.40"):
            with self.subTest(clear=clear):
                self.assertNotIn(clear, out)
        tmp.cleanup()

    def test_serialized_json_cell(self):
        tmp, _v, anon, _o = engine()
        out = anon.process(EVENT_DATA)
        for clear in ("mrossi", "gverdi", "CORP", "ACMESPA", "WKS0421", "10.20.30.40"):
            with self.subTest(clear=clear):
                self.assertNotIn(clear, out)
        tmp.cleanup()

    def test_round_trip(self):
        tmp, vault, anon, opt = engine()
        deanon = Deanonymizer(vault, opt)
        for text in (MESSAGE, EVENT_DATA):
            with self.subTest(text=text[:30]):
                self.assertEqual(deanon.process(anon.process(text)), text)
        tmp.cleanup()

    def test_json_stays_valid(self):
        tmp, _v, anon, _o = engine()
        self.assertEqual(len(json.loads(anon.process(EVENT_DATA))), 7)
        tmp.cleanup()

    def test_placeholders_are_not_masked(self):
        """I segnaposto dei log Windows non sono identita'."""
        tmp, _v, anon, _o = engine()
        for text in ("Account Name: -", "Target User Name: N/A",
                     "Account Domain: %%1833", "Logon Type: 3",
                     "Computer Name: localhost", "user name: SYSTEM"):
            with self.subTest(text=text):
                self.assertEqual(anon.process(text), text)
        tmp.cleanup()

    def test_our_own_pseudonym_is_stable(self):
        tmp, _v, anon, _o = engine()
        once = anon.process("Account Name: mrossi")
        self.assertEqual(anon.process(once), once)
        tmp.cleanup()


class CortexEvtlogKitTests(unittest.TestCase):
    def test_kit_is_detected_from_the_projection(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "in.csv"
            export_csv(path)
            columns, _s, _d = read_samples(path, 200)
            self.assertEqual(detect_vendor_kit(columns).get("id"), "cortex")

    def test_event_id_is_kept(self):
        """Regressione: finiva sul catch-all .*_(id)$ e veniva mascherato."""
        decision = resolve_field("action_evtlog_event_id", ["4624"], "cortex")
        self.assertEqual(decision.action, "keep")

    def test_message_and_data_are_masked_as_text(self):
        for column in ("action_evtlog_message", "Event_Data"):
            with self.subTest(column=column):
                self.assertEqual(resolve_field(column, [MESSAGE], "cortex").action, "text")


class EndToEndExportTests(unittest.TestCase):
    def _run(self, safe: bool) -> str:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "in.csv"
            export_csv(path)
            columns, samples, dialect = read_samples(path, 200)
            kit = detect_vendor_kit(columns).get("id")
            vault = Vault(Path(td) / "v.db", b"A" * 32)
            opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                          ip_mode="all", dlp_policy=dict(NO_ELISION_DLP_POLICY))
            anon = Anonymizer(vault, set(ORDER), opt)
            policy = default_policy(columns, samples, kit)
            if safe:
                policy = apply_safe_policy(policy, samples)
            processor = CsvAnonymizer(anon, policy, "upload:test", safe=safe)
            out = io.StringIO()
            processor.process(path, out, dialect, columns)
            return out.getvalue()

    def test_nothing_leaks(self):
        for safe in (False, True):
            output = self._run(safe)
            for clear in SECRETS:
                with self.subTest(safe=safe, clear=clear):
                    self.assertNotIn(clear, output)

    def test_operational_fields_stay_readable(self):
        output = self._run(False)
        self.assertIn("4624", output)
        self.assertIn("Microsoft-Windows-Security-Auditing", output)
        self.assertIn("2026-08-04T09:10:33Z", output)

    def test_message_is_masked_not_elided(self):
        """In Safe mode il messaggio non deve sparire: perderlo significa
        perdere l'evidenza, e mascherarlo la conserva."""
        output = self._run(True)
        self.assertIn("An account was successfully logged on", output)
        self.assertNotIn("[ELIDED]", output)


if __name__ == "__main__":
    unittest.main()
