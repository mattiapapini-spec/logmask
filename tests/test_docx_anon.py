"""v0.22.0 — anonimizzazione .docx con formato coerente.

Il documento restituito e' un .docx valido con la stessa struttura: cambia solo
il testo. Il caso critico e' che Word spezza il testo su piu' "run": un valore
sensibile puo' finire diviso ("mario" + ".rossi") e sfuggirebbe a una
sostituzione run-per-run. Qui si verifica che non sfugga MAI, e che la
formattazione venga preservata quando e' possibile farlo in sicurezza.
"""
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

import docx_anon
from logmask import Anonymizer, ORDER, Options, Vault, redact_residuals

W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def build_docx(paragraphs, core=None, extra=None):
    """paragraphs: lista di liste di run (stringhe)."""
    body = ""
    for runs in paragraphs:
        cells = "".join(
            f'<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">{r}</w:t></w:r>'
            if i == 1 else f'<w:r><w:t xml:space="preserve">{r}</w:t></w:r>'
            for i, r in enumerate(runs))
        body += f"<w:p>{cells}</w:p>"
    doc = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           f'<w:document {W_NS}><w:body>{body}</w:body></w:document>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", doc)
        if core:
            zf.writestr("docProps/core.xml", core)
        for name, payload in (extra or {}).items():
            zf.writestr(name, payload)
    return buf.getvalue()


def make_scrub(**opt):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    anon = Anonymizer(vault, set(ORDER), Options(**opt))
    return tmp, vault, anon, (lambda s: redact_residuals(anon.process(s))[0])


def texts_of(data):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return zf.read("word/document.xml").decode("utf-8")


class DocxDetectionTests(unittest.TestCase):
    def test_is_docx(self):
        self.assertTrue(docx_anon.is_docx(build_docx([["ciao"]])))

    def test_rejects_non_docx(self):
        self.assertFalse(docx_anon.is_docx(b"testo semplice"))
        self.assertFalse(docx_anon.is_docx(b"PK\x03\x04rotto"))


class DocxMaskingTests(unittest.TestCase):
    def test_ip_masked_and_document_still_valid(self):
        tmp, vault, anon, scrub = make_scrub(ip_mode="all")
        raw = build_docx([["Alert su ", "10.0.0.5"]])
        res = docx_anon.anonymize_docx(raw, scrub)
        xml = texts_of(res.data)
        self.assertNotIn("10.0.0.5", xml)
        self.assertIsNone(zipfile.ZipFile(io.BytesIO(res.data)).testzip())
        tmp.cleanup()

    def test_value_split_across_runs_is_masked(self):
        """Il caso critico: "mario.rossi" spezzato su due run."""
        tmp, vault, anon, scrub = make_scrub()
        raw = build_docx([["utente mario", ".rossi ha effettuato accesso"]])
        res = docx_anon.anonymize_docx(raw, scrub)
        xml = texts_of(res.data)
        self.assertNotIn("mario.rossi", xml)
        self.assertGreaterEqual(res.collapsed, 1)   # paragrafo ricomposto
        tmp.cleanup()

    def test_formatting_preserved_when_safe(self):
        """Se nessun valore e' spezzato, i run restano separati e la
        formattazione interna (grassetto) sopravvive."""
        tmp, vault, anon, scrub = make_scrub(ip_mode="all")
        raw = build_docx([["Alert su ", "10.0.0.5"]])
        res = docx_anon.anonymize_docx(raw, scrub)
        xml = texts_of(res.data)
        self.assertIn("b/", xml.replace("<w:b/>", "b/").replace("<ns0:b />", "b/"))
        self.assertEqual(res.collapsed, 0)
        tmp.cleanup()

    def test_technical_text_untouched(self):
        tmp, vault, anon, scrub = make_scrub()
        raw = build_docx([["Windows 10 - nessun dato sensibile"]])
        res = docx_anon.anonymize_docx(raw, scrub)
        self.assertIn("Windows 10", texts_of(res.data))
        tmp.cleanup()

    def test_document_metadata_scrubbed(self):
        """Autore e "ultimo salvataggio" sono PII classica nei documenti."""
        core = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
                'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
                '<dc:creator>Mario Rossi</dc:creator>'
                '<cp:lastModifiedBy>giulia.ferrari</cp:lastModifiedBy></cp:coreProperties>')
        tmp, vault, anon, scrub = make_scrub()
        res = docx_anon.anonymize_docx(build_docx([["testo"]], core=core), scrub)
        with zipfile.ZipFile(io.BytesIO(res.data)) as zf:
            props = zf.read("docProps/core.xml").decode("utf-8")
        self.assertNotIn("Mario Rossi", props)
        self.assertNotIn("giulia.ferrari", props)
        self.assertGreaterEqual(res.metadata_scrubbed, 2)
        tmp.cleanup()

    def test_all_package_parts_preserved(self):
        tmp, vault, anon, scrub = make_scrub()
        raw = build_docx([["testo"]], extra={"word/styles.xml": "<styles/>",
                                             "word/media/img.png": b"\x89PNG"})
        res = docx_anon.anonymize_docx(raw, scrub)
        with zipfile.ZipFile(io.BytesIO(res.data)) as zf:
            names = zf.namelist()
            self.assertIn("word/styles.xml", names)
            self.assertIn("word/media/img.png", names)
            self.assertEqual(zf.read("word/media/img.png"), b"\x89PNG")
        tmp.cleanup()

    def test_embedded_objects_are_flagged(self):
        tmp, vault, anon, scrub = make_scrub()
        raw = build_docx([["testo"]], extra={"word/media/img.png": b"\x89PNG"})
        res = docx_anon.anonymize_docx(raw, scrub)
        self.assertTrue(any("incorporati" in w for w in res.warnings))
        tmp.cleanup()

    def test_invalid_docx_raises(self):
        tmp, vault, anon, scrub = make_scrub()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("altro.txt", "niente")
        with self.assertRaises(ValueError):
            docx_anon.anonymize_docx(buf.getvalue(), scrub)
        tmp.cleanup()

    def test_empty_paragraphs_are_skipped(self):
        tmp, vault, anon, scrub = make_scrub()
        res = docx_anon.anonymize_docx(build_docx([[""], ["  "], ["testo"]]), scrub)
        self.assertEqual(res.changed, 0)
        tmp.cleanup()



class DocxEndpointTests(unittest.TestCase):
    """POST /api/anonymize-docx restituisce un .docx valido in base64."""
    ADMIN_PASSWORD = "Bootstrap-Docx-Root-2026!"

    def setUp(self):
        import base64
        from fastapi.testclient import TestClient
        import app as webapp
        from auth import AuthStore
        self.b64 = base64
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
        self.client.post("/api/login",
                         json={"username": "admin", "password": self.ADMIN_PASSWORD})
        self.client.post("/api/change-password",
                         headers={"X-CSRF-Token": self._csrf()},
                         json={"current_password": self.ADMIN_PASSWORD,
                               "new_password": "Docx-Personal-Password-2026!"})

    def tearDown(self):
        self.tmp.cleanup()

    def _csrf(self):
        return self.client.cookies.get(self.webapp.CSRF_COOKIE)

    def _post(self, payload, name="report.docx"):
        return self.client.post(
            "/api/anonymize-docx", headers={"X-CSRF-Token": self._csrf()},
            data={"tenant": "acme", "ip_mode": "all"},
            files={"file": (name, payload,
                            "application/vnd.openxmlformats-officedocument."
                            "wordprocessingml.document")})

    def test_returns_valid_docx_with_masked_text(self):
        raw = build_docx([["Alert su ", "10.0.0.5"], ["utente mario", ".rossi"]])
        response = self._post(raw)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["filename"].endswith(".anon.docx"))
        data = self.b64.b64decode(body["document_b64"])
        self.assertTrue(docx_anon.is_docx(data))
        xml = texts_of(data)
        self.assertNotIn("10.0.0.5", xml)
        self.assertNotIn("mario.rossi", xml)

    def test_rejects_non_docx_upload(self):
        response = self._post(b"non sono un documento", name="finto.docx")
        self.assertEqual(response.status_code, 400)

    def test_requires_csrf(self):
        response = self.client.post(
            "/api/anonymize-docx", data={"tenant": "acme"},
            files={"file": ("a.docx", build_docx([["x"]]), "application/octet-stream")})
        self.assertIn(response.status_code, (401, 403))

    def test_audited(self):
        self._post(build_docx([["Alert su ", "10.0.0.5"]]))
        events = self.client.get("/api/admin/audit?limit=20").json()["events"]
        self.assertIn("anonymize-docx", [e["action"] for e in events])

if __name__ == "__main__":
    unittest.main()


class DocxStructurePreservedTests(unittest.TestCase):
    """Tabelle, indici (TOC), numerazione, stili e hyperlink devono restare."""

    RICH = ('<?xml version="1.0"?><w:document ' + W_NS + '><w:body>'
            '<w:p><w:pPr><w:pStyle w:val="Heading1"/><w:numPr><w:numId w:val="2"/>'
            '</w:numPr></w:pPr><w:r><w:t>Sezione</w:t></w:r></w:p>'
            '<w:p><w:fldSimple w:instr=" TOC \\o "><w:r><w:t>Indice</w:t></w:r>'
            '</w:fldSimple></w:p>'
            '<w:tbl><w:tblPr><w:tblStyle w:val="Griglia"/></w:tblPr><w:tr>'
            '<w:tc><w:p><w:r><w:t>WKS0421</w:t></w:r></w:p></w:tc>'
            '<w:tc><w:p><w:r><w:t>10.0.0.5</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
            '</w:body></w:document>')

    def _rich_docx(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", self.RICH)
            zf.writestr("word/numbering.xml", "<num/>")
            zf.writestr("word/styles.xml", "<styles/>")
            zf.writestr("word/header1.xml",
                        '<?xml version="1.0"?><w:hdr ' + W_NS +
                        '><w:p><w:r><w:t>Report per DC01</w:t></w:r></w:p></w:hdr>')
        return buf.getvalue()

    def test_tables_toc_numbering_styles_survive(self):
        tmp, vault, anon, scrub = make_scrub(ip_mode="all", host_terms=("WKS*", "*DC*"))
        res = docx_anon.anonymize_docx(self._rich_docx(), scrub)
        xml = texts_of(res.data)
        for marker in ("tbl>", "Griglia", "TOC", "numId", "Heading1"):
            with self.subTest(marker=marker):
                self.assertIn(marker, xml)
        with zipfile.ZipFile(io.BytesIO(res.data)) as zf:
            self.assertIn("word/numbering.xml", zf.namelist())
            self.assertIn("word/styles.xml", zf.namelist())
        tmp.cleanup()

    def test_table_content_masked_and_header_too(self):
        tmp, vault, anon, scrub = make_scrub(ip_mode="all", host_terms=("WKS*", "*DC*"))
        res = docx_anon.anonymize_docx(self._rich_docx(), scrub)
        xml = texts_of(res.data)
        self.assertNotIn("WKS0421", xml)
        self.assertNotIn("10.0.0.5", xml)
        with zipfile.ZipFile(io.BytesIO(res.data)) as zf:
            self.assertNotIn("DC01", zf.read("word/header1.xml").decode("utf-8"))
        tmp.cleanup()


class DocxRoundTripTests(unittest.TestCase):
    """docx -> anonimizzato -> docx ripristinato, struttura sempre intatta."""

    def test_round_trip_restores_values_and_structure(self):
        from logmask import Deanonymizer
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        opt = Options(ip_mode="all", host_terms=("WKS*",))
        anon = Anonymizer(vault, set(ORDER), opt)
        raw = build_docx([["Host WKS0421 con IP ", "10.0.0.5"],
                          ["utente mario", ".rossi"]])
        masked = docx_anon.anonymize_docx(
            raw, lambda s: redact_residuals(anon.process(s))[0])
        xml_masked = texts_of(masked.data)
        for secret in ("WKS0421", "10.0.0.5", "mario.rossi"):
            self.assertNotIn(secret, xml_masked)

        restored = docx_anon.deanonymize_docx(
            masked.data, Deanonymizer(vault, opt).process)
        xml_restored = texts_of(restored.data)
        for secret in ("WKS0421", "10.0.0.5", "mario.rossi"):
            self.assertIn(secret, xml_restored)
        self.assertTrue(docx_anon.is_docx(restored.data))
        tmp.cleanup()


class DocxRestoreCompletenessTests(unittest.TestCase):
    """"66/791 paragrafi" non dice se il restore e' COMPLETO: la maggior parte
    dei paragrafi di un report non contiene pseudonimi. Il numero che conta e'
    quanti token sono rimasti non risolti."""

    def _doc_with_few_secrets(self):
        paras = [[f"Paragrafo narrativo {i} senza dati."] for i in range(50)]
        paras += [[f"Host WKS04{i}1 IP 10.0.0.{i} utente mario.rossi"] for i in range(5)]
        return build_docx(paras)

    def test_full_restore_reports_zero_unresolved(self):
        from logmask import Deanonymizer
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        opt = Options(ip_mode="all", host_terms=("WKS*",))
        anon = Anonymizer(vault, set(ORDER), opt)
        masked = docx_anon.anonymize_docx(
            self._doc_with_few_secrets(),
            lambda s: redact_residuals(anon.process(s))[0])
        restored = docx_anon.deanonymize_docx(masked.data,
                                              Deanonymizer(vault, opt).process)
        self.assertGreater(restored.tokens_in, 0)
        self.assertEqual(restored.tokens_left, 0)       # restore completo
        self.assertLess(restored.changed, restored.paragraphs)  # non tutti i par.
        tmp.cleanup()

    def test_wrong_vault_reports_unresolved(self):
        """Con il vault sbagliato il restore non risolve nulla e lo dice."""
        from logmask import Deanonymizer
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        opt = Options(ip_mode="all", host_terms=("WKS*",))
        anon = Anonymizer(vault, set(ORDER), opt)
        masked = docx_anon.anonymize_docx(
            self._doc_with_few_secrets(),
            lambda s: redact_residuals(anon.process(s))[0])
        other = Vault(Path(tempfile.mkdtemp()) / "v2.db", b"B" * 32)
        restored = docx_anon.deanonymize_docx(masked.data,
                                              Deanonymizer(other, opt).process)
        self.assertEqual(restored.tokens_left, restored.tokens_in)
        tmp.cleanup()

    def test_restored_real_ips_are_not_counted_as_pseudonyms(self):
        """Un IP reale ripristinato (10.0.0.1) ha la stessa forma di uno
        pseudonimo IPv4 legacy: contarlo darebbe "non risolti" fantasma."""
        raw = build_docx([["IP interno 10.0.0.1 e 10.20.30.40"]])
        self.assertEqual(docx_anon.count_pseudonyms(raw), 0)
