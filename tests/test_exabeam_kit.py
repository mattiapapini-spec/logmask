"""v0.25.2 - kit Exabeam dedicato, per entrambe le generazioni.

Exabeam risultava "integrato" solo di nome: condivideva un kit con Darktrace,
i cui fingerprint sono quasi tutti Darktrace (modelname, breachscore,
deviceid). Su un export Exabeam reale il kit non scattava nemmeno, quindi
nessun campo veniva classificato - lo stesso guasto visto con la query Cortex.

I nomi dei campi New-Scale sono verificati sul repository ufficiale
ExabeamLabs/CIMLibrary (Fields_Descriptions.md). Le famiglie src_*/user*/
raw_log seguono la simmetria dei dest_* documentati.
"""
import csv
import io
import tempfile
import unittest
from pathlib import Path

import vendor_kits
from logmask import (Anonymizer, CsvAnonymizer, NO_ELISION_DLP_POLICY, ORDER,
                     Options, Vault, apply_safe_policy, default_policy,
                     detect_vendor_kit, read_samples)

CIM_COLUMNS = ["approx_log_time", "activity_type", "dest_user_entity_id",
               "dest_user_full_name", "dest_user_sid", "dest_device_entity_id",
               "dest_dns_hostname", "dest_ip", "dest_mac", "domain",
               "dest_process_command_line", "hash_sha256", "event_code",
               "outcome", "connection_uid", "m_user_email", "message"]
CIM_ROW = ["2026-08-04T09:12:33Z", "account-login", "mrossi", "Mario Rossi",
           "S-1-5-21-1111-2222-3333-1105", "WKS0421", "wks0421.acmespa.local",
           "10.20.30.40", "00:1a:2b:3c:4d:5e", "ACMESPA",
           "C:\\Windows\\System32\\cmd.exe /c whoami",
           "43c2d3293ad939241df61b3630a9d3b6", "4624", "success",
           "9f1c2e5b7a3d4f6081b2c3d4e5f60718", "mario.rossi@acmespa.it",
           "Account Name: mrossi Workstation Name: WKS0421"]

AA_COLUMNS = ["session_id", "user", "src_host", "dest_host", "src_ip", "dest_ip",
              "risk_score", "triggered_rules", "zone", "event_type", "rule_name",
              "raw_log"]
AA_ROW = ["mrossi-20260804093000", "mrossi", "WKS0421", "SRV-DC01", "10.20.30.40",
          "10.20.30.5", "142", "AA-DC-F,AA-UH-F", "corporate", "account-login",
          "Abnormal logon time",
          "User mrossi logged on to WKS0421 from 10.20.30.40 domain ACMESPA"]

IDENTIFYING = ["mrossi", "Mario Rossi", "WKS0421", "wks0421.acmespa.local",
               "10.20.30.40", "SRV-DC01", "mario.rossi@acmespa.it",
               "00:1a:2b:3c:4d:5e"]
OPERATIONAL = ["4624", "success", "account-login", "Abnormal logon time",
               "43c2d3293ad939241df61b3630a9d3b6", "142", "corporate"]


def run(columns, row, safe=False, rows=3):
    tmp = tempfile.TemporaryDirectory()
    src = Path(tmp.name) / "in.csv"
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(columns)
    for _ in range(rows):
        writer.writerow(row)
    with open(src, "w", encoding="utf-8", newline="") as fh:
        fh.write(buf.getvalue())
    cols, samples, dialect = read_samples(src, 200)
    kit = detect_vendor_kit(cols).get("id")
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    anon = Anonymizer(vault, set(ORDER),
                      Options(ip_mode="all", dlp_policy=dict(NO_ELISION_DLP_POLICY)))
    policy = default_policy(cols, samples, kit)
    if safe:
        policy = apply_safe_policy(policy, samples)
    processor = CsvAnonymizer(anon, policy, "upload:test", safe=safe)
    out = io.StringIO()
    processor.process(src, out, dialect, cols)
    text = out.getvalue()
    tmp.cleanup()
    return kit, text


class KitStructureTests(unittest.TestCase):
    def test_exabeam_has_its_own_kit(self):
        vendor_kits.force_reload()
        self.assertIn("exabeam", vendor_kits.KITS)
        self.assertIn("darktrace", vendor_kits.KITS)

    def test_old_shared_id_still_resolves(self):
        """Un catalogo forzato o una policy salvata che nominava il vecchio id
        unico deve continuare a risolvere. Non si fissa il kit di destinazione:
        se il vecchio file e' ancora presente nella cartella dei kit risolve a
        se stesso, altrimenti all'alias su darktrace - in entrambi i casi non
        si rompe nulla."""
        self.assertIsNotNone(vendor_kits.canonical_kit_id("darktrace_exabeam"))

    def test_custom_fields_have_no_rule(self):
        """I campi c_* sono definiti dal cliente: devono restare non
        classificati, cosi' in Safe mode vengono elisi invece di sembrare
        coperti dal kit."""
        from logmask import resolve_field
        self.assertNotEqual(resolve_field("c_ticket_owner", ["gverdi"], "exabeam")
                            .inferred_by, "vendor:exabeam")


class NewScaleCimTests(unittest.TestCase):
    def test_kit_is_detected(self):
        kit, _text = run(CIM_COLUMNS, CIM_ROW)
        self.assertEqual(kit, "exabeam")

    def test_no_identifying_value_survives(self):
        for safe in (False, True):
            _kit, text = run(CIM_COLUMNS, CIM_ROW, safe=safe)
            for clear in IDENTIFYING:
                with self.subTest(safe=safe, clear=clear):
                    self.assertNotIn(clear, text)

    def test_operational_fields_stay_readable(self):
        _kit, text = run(CIM_COLUMNS, CIM_ROW)
        for value in ("4624", "success", "account-login",
                      "43c2d3293ad939241df61b3630a9d3b6"):
            with self.subTest(value=value):
                self.assertIn(value, text)

    def test_connection_uid_is_masked(self):
        """Documentato come md5 di IP + nome utente: ricalcolabile, quindi
        identificativo e non un IOC."""
        _kit, text = run(CIM_COLUMNS, CIM_ROW)
        self.assertNotIn("9f1c2e5b7a3d4f6081b2c3d4e5f60718", text)

    def test_metadata_field_is_masked(self):
        _kit, text = run(CIM_COLUMNS, CIM_ROW)
        self.assertNotIn("mario.rossi@acmespa.it", text)


class AdvancedAnalyticsTests(unittest.TestCase):
    def test_kit_is_detected(self):
        kit, _text = run(AA_COLUMNS, AA_ROW)
        self.assertEqual(kit, "exabeam")

    def test_columns_are_masked(self):
        _kit, text = run(AA_COLUMNS, AA_ROW)
        for clear in ("mrossi", "SRV-DC01", "10.20.30.40"):
            with self.subTest(clear=clear):
                self.assertNotIn(clear, text)

    def test_identity_inside_raw_log_is_masked(self):
        """Il nome utente compare nel raw_log senza sintassi chiave/valore:
        va sostituito con lo pseudonimo che la riga ha gia' assegnato."""
        _kit, text = run(AA_COLUMNS, AA_ROW)
        raw = list(csv.DictReader(io.StringIO(text)))[0]["raw_log"]
        self.assertNotIn("mrossi", raw)
        self.assertNotIn("WKS0421", raw)
        self.assertIn("logged on to", raw)

    def test_operational_fields_stay_readable(self):
        _kit, text = run(AA_COLUMNS, AA_ROW)
        # "zone" NON e' fra questi: i nomi di zona sono scelti dal cliente
        # ("corporate", "ACMESPA-DMZ", "Milano-LAN") e descrivono la sua
        # topologia, quindi vengono mascherati.
        for value in ("142", "Abnormal logon time", "account-login"):
            with self.subTest(value=value):
                self.assertIn(value, text)


class NoTextCorruptionTests(unittest.TestCase):
    SUBJECT = ("[SOC] Segnalazione di Sicurezza - [Heuristic Attribute] "
               "Possible Masquerading Behavior")

    def test_soc_subject_is_untouched(self):
        """Lo sweep sulle colonne di testo non deve reintrodurre la corruzione
        della prosa corretta nella 0.23.2."""
        columns = AA_COLUMNS + ["subject"]
        row = AA_ROW + [self.SUBJECT]
        _kit, text = run(columns, row)
        self.assertIn(self.SUBJECT, text)

    def test_prose_words_are_not_swept(self):
        from logmask import sweepable_prose_original
        for word in ("Sicurezza", "Windows", "Possible", "SOC", "corporate"):
            with self.subTest(word=word):
                self.assertFalse(sweepable_prose_original(word))
        self.assertTrue(sweepable_prose_original("WKS0421"))


class CimCoverageTests(unittest.TestCase):
    """Copertura misurata sull'elenco ufficiale dei campi CIM.

    Il repository ExabeamLabs/CIMLibrary pubblica Fields_Descriptions.md con
    1165 campi. Il kit non deve lasciare "keep" nessun campo il cui NOME dice
    che porta un'identita': un campo tenuto in chiaro e' una fuga silenziosa,
    perche' nessun controllo scatta su un valore che nessuno ha classificato.
    """

    IDENTIFYING_FIELDS = [
        # utenti (verificati)
        "user", "users", "user_sid", "user_dn", "user_ou", "user_upn", "user_uid",
        "user_arn", "src_user", "dest_user", "dest_user_sid", "dest_user_dn",
        "dest_user_full_name", "domain_user_name", "local_user_name",
        "account", "account_name", "account_user_name", "employee_id",
        "manager_name", "process_owner", "file_owner", "sid_history",
        "subject_sid", "principal_name", "removed_users", "added_users",
        # macchine
        "host", "src_host", "dest_host", "src_fqdn", "dest_dns_hostname",
        "computer_name", "domain_controller", "quarantine_machine",
        "vm_host_name", "virtual_station_name", "src_translated_host",
        # rete
        "src_ip", "dest_ip", "src_ipv6", "dest_ipv6", "src_mac", "dest_mac",
        "src_translated_ip", "dest_translated_ip", "src_translated_ipnum",
        "nas_ip_address", "framed_addr", "calling_station_id", "private_ip",
        # posta e dominio
        "email_address", "src_email_address", "mailfrom", "manager_email",
        "src_domain", "dest_domain", "nt_domain", "sid_domain", "realm",
        "user_group_name", "src_group_name", "role_name",
        # segreti e credenziali fisiche
        "src_password", "new_password", "old_password", "badge_id", "card_num",
        # posizione
        "location_full", "src_location", "remote_location_city",
        # metadati m_*
        "m_winlog_user_name", "m_winlog_user_domain", "m_winlog_user_identifier",
        "m_host", "m_hostname", "m_computer_name", "m_agent_hostname",
    ]

    OPERATIONAL_FIELDS = [
        "activity_type", "outcome", "event_code", "event_name", "severity",
        "risk_score", "src_port", "dest_port", "bytes_in", "bytes_out",
        "hash_sha256", "hash_md5", "process_hash", "parent_hash_sha256",
        "os_version", "device_vendor", "device_product", "mitre_technique",
        "cve_id", "user_agent", "logon_type", "auth_method", "country_code",
        "m_timestamp", "m_event_code", "m_log_level", "m_channel",
    ]

    def test_no_identifying_field_is_kept_in_clear(self):
        from logmask import resolve_field
        for field in self.IDENTIFYING_FIELDS:
            with self.subTest(field=field):
                decision = resolve_field(field, ["value"], "exabeam")
                self.assertNotEqual(decision.action, "keep",
                                    f"{field} resterebbe in chiaro")

    def test_operational_fields_stay_readable(self):
        from logmask import resolve_field
        for field in self.OPERATIONAL_FIELDS:
            with self.subTest(field=field):
                self.assertEqual(resolve_field(field, ["value"], "exabeam").action,
                                 "keep", f"{field} verrebbe mascherato")

    def test_metadata_identity_beats_the_generic_metadata_rule(self):
        """m_winlog_user_name porta un nome utente: la regola generica sui
        metadati non deve vincere e lasciarlo leggibile."""
        from logmask import resolve_field
        self.assertEqual(resolve_field("m_winlog_user_name", ["mrossi"], "exabeam").kind,
                         "user")
        self.assertEqual(resolve_field("m_winlog_user_domain", ["CORP"], "exabeam").kind,
                         "windomain")

    def test_connection_uid_is_not_treated_as_an_ioc(self):
        from logmask import resolve_field
        self.assertEqual(resolve_field("connection_uid", ["9f1c2e5b"], "exabeam").action,
                         "mask")


if __name__ == "__main__":
    unittest.main()
