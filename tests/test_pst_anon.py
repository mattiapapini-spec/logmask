"""v0.11.0 — PST ingestion: mbox parsing + message anonymization.

The PST->mbox step (readpst) is a well-known external tool and is not exercised
here; these tests cover everything downstream on a synthetic mbox, which is
exactly the format readpst emits.
"""
import json
import mailbox
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

import pst_anon
from logmask import Anonymizer, Options, ORDER, Vault


def make_engine(**opt):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"P" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt))


def build_mbox(messages):
    d = tempfile.mkdtemp()
    path = Path(d) / "Inbox"
    box = mailbox.mbox(str(path))
    box.lock()
    for frm, to, cc, subj, body in messages:
        m = EmailMessage()
        m["From"] = frm
        m["To"] = to
        if cc:
            m["Cc"] = cc
        m["Subject"] = subj
        m["Date"] = "Tue, 14 Jul 2026 10:00:00 +0000"
        m.set_content(body)
        box.add(m)
    box.flush()
    box.unlock()
    box.close()
    return path


class PstMessageAnonTests(unittest.TestCase):

    MSGS = [
        ("Mario Rossi <mario.rossi@contoso.com>",
         "anna@contoso.com, Luca <luca@contoso.com>", "",
         "Report Q3", "Ecco il report. Scrivi a admin@contoso.com o 10.0.0.5."),
        ("svc@vendor.example", "mario.rossi@contoso.com", "",
         "Alert", "Login da SRV-DC01 (93.57.78.9) per ClienteBeta."),
    ]

    def test_addresses_only_no_display_name_leak(self):
        tmp, vault, anon = make_engine(client_terms=("ClienteBeta",))
        recs = pst_anon.anonymize_records(
            list(pst_anon.parse_mbox(build_mbox(self.MSGS), folder="Inbox")), anon)
        blob = json.dumps(recs)
        for leak in ("Mario Rossi", "Luca", "mario.rossi@contoso.com",
                     "anna@contoso.com", "luca@contoso.com"):
            self.assertNotIn(leak, blob, leak)
        tmp.cleanup()

    def test_body_scrubbed(self):
        tmp, vault, anon = make_engine(ip_mode="internal", client_terms=("ClienteBeta",),
                                       tenant_networks=("93.57.78.0/24",))
        recs = pst_anon.anonymize_records(
            list(pst_anon.parse_mbox(build_mbox(self.MSGS), folder="Inbox")), anon)
        blob = json.dumps(recs)
        for leak in ("admin@contoso.com", "10.0.0.5", "SRV-DC01", "93.57.78.9", "ClienteBeta"):
            self.assertNotIn(leak, blob, leak)
        tmp.cleanup()

    def test_same_sender_same_token_across_messages(self):
        tmp, vault, anon = make_engine()
        recs = pst_anon.anonymize_records(
            list(pst_anon.parse_mbox(build_mbox(self.MSGS), folder="Inbox")), anon)
        # mario.rossi@contoso.com is "from" in msg 0 and a recipient in msg 1
        self.assertEqual(recs[0]["from"], recs[1]["toRecipients"])
        tmp.cleanup()

    def test_same_domain_constant(self):
        tmp, vault, anon = make_engine()
        recs = pst_anon.anonymize_records(
            list(pst_anon.parse_mbox(build_mbox(self.MSGS), folder="Inbox")), anon)
        dom = lambda s: s.split("@", 1)[1]
        self.assertEqual(dom(recs[0]["from"]),
                         dom(recs[0]["toRecipients"].split(", ")[0]))
        tmp.cleanup()

    def test_metadata_kept(self):
        tmp, vault, anon = make_engine()
        recs = pst_anon.anonymize_records(
            list(pst_anon.parse_mbox(build_mbox(self.MSGS), folder="Inbox")), anon)
        self.assertEqual(recs[0]["date"], "Tue, 14 Jul 2026 10:00:00 +0000")
        self.assertEqual(recs[0]["folder"], "Inbox")
        self.assertEqual(recs[0]["hasAttachments"], "false")
        tmp.cleanup()

    def test_ndjson_and_csv_serialization(self):
        tmp, vault, anon = make_engine()
        recs = pst_anon.anonymize_records(
            list(pst_anon.parse_mbox(build_mbox(self.MSGS), folder="Inbox")), anon)
        nd = pst_anon.to_ndjson(recs)
        self.assertEqual(len(nd.splitlines()), 2)
        self.assertEqual(json.loads(nd.splitlines()[0])["subject"], "Report Q3")
        cs = pst_anon.to_csv(recs)
        self.assertIn("date,folder,from,toRecipients", cs)
        import csv as _csv, io as _io
        rows = list(_csv.reader(_io.StringIO(cs)))
        self.assertEqual(len(rows), 3)   # header + 2 (bodies may contain newlines)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()


class PstEndpointTests(unittest.TestCase):
    """v0.11.0 — /api/anonymize-pst multipart endpoint (readpst bypassed with a
    synthetic extraction so the wiring is exercised without pst-utils)."""
    ADMIN_PASSWORD = "Bootstrap-Pst-Root-2026!"

    def setUp(self):
        from fastapi.testclient import TestClient
        import app as webapp
        from auth import AuthStore
        self.webapp = webapp
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        webapp.DATA = root
        webapp.KEY_PATH = root / "master.key"
        webapp.VAULT_PATH = root / "vault.db"
        webapp.TENANTS_DIR = root / "tenants"
        webapp.AUTH_PATH = root / "auth.db"
        webapp.BOOTSTRAP_FILE = root / "bootstrap-admin.txt"
        webapp.MASTER = b"A" * 32
        webapp.AUTH = AuthStore(root / "auth.db")
        webapp.AUTH.bootstrap_admin("admin", self.ADMIN_PASSWORD, webapp.BOOTSTRAP_FILE)
        self.client = TestClient(webapp.app)
        self.client.post("/api/login", json={"username": "admin", "password": self.ADMIN_PASSWORD})
        csrf = self.client.cookies.get(webapp.CSRF_COOKIE)
        self.client.post("/api/change-password", headers={"X-CSRF-Token": csrf},
                         json={"current_password": self.ADMIN_PASSWORD,
                               "new_password": "Pst-Personal-Password-2026!"})
        self._avail, self._extract = pst_anon.readpst_available, pst_anon.extract_records
        pst_anon.readpst_available = lambda: True
        pst_anon.extract_records = lambda path: [
            {"date": "Tue, 14 Jul 2026 10:00:00 +0000", "folder": "Inbox",
             "from": "mario@contoso.com", "toRecipients": "anna@contoso.com",
             "ccRecipients": "", "bccRecipients": "", "subject": "Report",
             "hasAttachments": "false", "attachmentNames": "",
             "body": "vedi 10.0.0.5 e admin@contoso.com"}]

    def tearDown(self):
        pst_anon.readpst_available, pst_anon.extract_records = self._avail, self._extract
        self.tmp.cleanup()

    def test_pst_upload_endpoint(self):
        csrf = self.client.cookies.get(self.webapp.CSRF_COOKIE)
        r = self.client.post(
            "/api/anonymize-pst", headers={"X-CSRF-Token": csrf},
            data={"tenant": "c-pst", "format": "ndjson", "ip_mode": "all"},
            files={"file": ("mail.pst", b"fakepstbytes", "application/octet-stream")})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["messages"], 1)
        self.assertEqual(body["filename"], "mail.anon.ndjson")
        self.assertNotIn("mario@contoso.com", body["output"])   # sender masked
        self.assertNotIn("admin@contoso.com", body["output"])   # body e-mail masked
        self.assertNotIn("10.0.0.5", body["output"])            # body IP masked
        self.assertIn("Report", body["output"])                 # subject (no PII) kept
