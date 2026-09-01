"""v0.26.0 - PDF: il testo originale deve sparire davvero dal file.

Coprire il testo con un rettangolo NON lo rimuove: resta nel content stream e
si recupera con un copia-incolla. E' la fuga piu' classica dei documenti
"redatti" - ci sono finiti tribunali e ministeri, non solo utenti distratti.
Qui il testo viene eliminato e lo pseudonimo scritto al suo posto, e il file
prodotto viene RILETTO per verificare che nessun valore originale sia ancora
estraibile: se lo fosse, l'operazione fallisce invece di consegnare un
documento che sembra anonimizzato.
"""
import tempfile
import unittest
from pathlib import Path

import pdf_anon
from logmask import (Anonymizer, Deanonymizer, NO_ELISION_DLP_POLICY, ORDER,
                     Options, Vault, pseudonymize_residuals, sweep_known)

if not pdf_anon.available():                       # pragma: no cover
    raise unittest.SkipTest("PyMuPDF non disponibile")

import pymupdf

LINES = [
    "Rapporto incidente - Cliente Acme Spa",
    "Segnalato da: Mario Rossi (mario.rossi@acmespa.it)",
    "Host coinvolto: SRV-DC01.corp.local - IP 10.20.30.40",
    "P.IVA 00743110157 - Via Roma 12, Milano",
    "Account Name: mrossi   Account Domain: CORP",
]
IDENTIFYING = ["Mario Rossi", "mario.rossi@acmespa.it", "SRV-DC01.corp.local",
               "10.20.30.40", "00743110157", "Via Roma 12", "mrossi", "CORP"]


def sample_pdf(lines=None, metadata=True, pages=1) -> bytes:
    doc = pymupdf.open()
    for _ in range(pages):
        page = doc.new_page()
        for i, line in enumerate(lines or LINES):
            page.insert_text((60, 80 + i * 22), line, fontsize=11)
    if metadata:
        doc.set_metadata({"author": "Mario Rossi", "title": "Incidente Acme",
                          "subject": "mrossi", "keywords": "acmespa, mrossi"})
        doc.set_toc([[1, "Sezione Mario Rossi", 1]])
    data = doc.tobytes()
    doc.close()
    return data


def engine():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                  ip_mode="all", client_terms=("Acme Spa",),
                  client_term_mode="pseudonymize",
                  dlp_policy=dict(NO_ELISION_DLP_POLICY))
    anon = Anonymizer(vault, set(ORDER), opt)

    def scrub(text: str) -> str:
        out = anon.process(text)
        out, _swept = sweep_known(vault, out, opt, prose=True)
        out, _n, _k = pseudonymize_residuals(out, anon, opt.dlp_policy)
        return out

    return tmp, vault, opt, scrub


class TextIsActuallyRemovedTests(unittest.TestCase):
    def test_no_identifying_value_is_extractable(self):
        """Il controllo che distingue una redazione vera da un rettangolo."""
        tmp, _v, _o, scrub = engine()
        result = pdf_anon.anonymize_pdf(sample_pdf(), scrub)
        produced = "\n".join(pdf_anon.extract_text(result.data))
        for clear in IDENTIFYING:
            with self.subTest(clear=clear):
                self.assertNotIn(clear, produced)
        tmp.cleanup()

    def test_value_is_absent_from_the_raw_bytes(self):
        """Non basta che get_text() non lo mostri: non deve proprio esserci."""
        tmp, _v, _o, scrub = engine()
        result = pdf_anon.anonymize_pdf(sample_pdf(), scrub)
        for clear in ("mario.rossi@acmespa.it", "SRV-DC01.corp.local"):
            with self.subTest(clear=clear):
                self.assertNotIn(clear.encode(), result.data)
        tmp.cleanup()

    def test_pseudonyms_are_present_in_place(self):
        tmp, _v, _o, scrub = engine()
        produced = "\n".join(pdf_anon.extract_text(
            pdf_anon.anonymize_pdf(sample_pdf(), scrub).data))
        for prefix in ("usr-", "host-", "vat-", "addr-"):
            with self.subTest(prefix=prefix):
                self.assertIn(prefix, produced)
        tmp.cleanup()

    def test_surrounding_text_survives(self):
        tmp, _v, _o, scrub = engine()
        produced = "\n".join(pdf_anon.extract_text(
            pdf_anon.anonymize_pdf(sample_pdf(), scrub).data))
        self.assertIn("Rapporto incidente", produced)
        self.assertIn("Milano", produced)
        tmp.cleanup()

    def test_leak_check_blocks_a_failed_masking(self):
        """Se per qualsiasi motivo un valore sopravvivesse, si deve fallire."""
        tmp, _v, _o, _s = engine()
        # scrub "bugiardo": dice di mascherare quando gli si passa la pagina
        # intera (come fa la verifica) ma non tocca i singoli span. E' il
        # comportamento di una redazione solo grafica.
        def lying(text: str) -> str:
            if "\n" in text:
                return text.replace("SRV-DC01.corp.local", "host-xxxx.masked.local")
            return text

        with self.assertRaises(pdf_anon.PdfLeakError):
            pdf_anon.anonymize_pdf(sample_pdf(), lying)
        tmp.cleanup()


class HiddenTextTests(unittest.TestCase):
    def test_metadata_is_scrubbed(self):
        tmp, _v, _o, scrub = engine()
        result = pdf_anon.anonymize_pdf(sample_pdf(), scrub)
        doc = pymupdf.open(stream=result.data, filetype="pdf")
        blob = " ".join(v for v in (doc.metadata or {}).values() if v)
        doc.close()
        self.assertNotIn("Mario Rossi", blob)
        self.assertNotIn("mrossi", blob)
        self.assertGreater(result.metadata_scrubbed, 0)
        tmp.cleanup()

    def test_bookmarks_are_scrubbed(self):
        tmp, _v, _o, scrub = engine()
        result = pdf_anon.anonymize_pdf(sample_pdf(), scrub)
        doc = pymupdf.open(stream=result.data, filetype="pdf")
        toc = doc.get_toc(simple=True)
        doc.close()
        self.assertNotIn("Mario Rossi", " ".join(t[1] for t in toc))

    def test_embedded_attachments_are_removed(self):
        doc = pymupdf.open()
        page = doc.new_page()
        page.insert_text((60, 80), "Host SRV-DC01.corp.local", fontsize=11)
        doc.embfile_add("segreto.txt", b"utente mrossi password Estate2024!")
        data = doc.tobytes()
        doc.close()
        tmp, _v, _o, scrub = engine()
        result = pdf_anon.anonymize_pdf(data, scrub)
        self.assertEqual(result.attachments_removed, 1)
        self.assertNotIn(b"Estate2024!", result.data)
        tmp.cleanup()


class ScannedPagesTests(unittest.TestCase):
    def test_page_without_text_is_reported(self):
        """Una scansione non ha testo: non viene analizzata, e dirlo e'
        l'unica cosa che impedisce di condividerla credendola sicura."""
        doc = pymupdf.open()
        page = doc.new_page()
        pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 40, 40))
        pix.clear_with(200)
        page.insert_image(pymupdf.Rect(50, 50, 200, 200), pixmap=pix)
        data = doc.tobytes()
        doc.close()
        tmp, _v, _o, scrub = engine()
        result = pdf_anon.anonymize_pdf(data, scrub)
        self.assertEqual(result.image_only_pages, [1])
        self.assertTrue(any("scansione" in w for w in result.warnings))
        tmp.cleanup()


class RoundTripTests(unittest.TestCase):
    def test_restore_brings_back_the_originals(self):
        tmp, vault, opt, scrub = engine()
        masked = pdf_anon.anonymize_pdf(sample_pdf(), scrub)
        restored = pdf_anon.deanonymize_pdf(masked.data,
                                            Deanonymizer(vault, opt).process)
        produced = "\n".join(pdf_anon.extract_text(restored.data))
        for clear in ("Mario Rossi", "mario.rossi@acmespa.it",
                      "SRV-DC01.corp.local", "10.20.30.40", "00743110157"):
            with self.subTest(clear=clear):
                self.assertIn(clear, produced)
        tmp.cleanup()

    def test_pseudonym_count_drops_to_zero(self):
        tmp, vault, opt, scrub = engine()
        masked = pdf_anon.anonymize_pdf(sample_pdf(), scrub)
        before = pdf_anon.count_pseudonyms(masked.data)
        restored = pdf_anon.deanonymize_pdf(masked.data,
                                            Deanonymizer(vault, opt).process)
        self.assertGreater(before, 0)
        self.assertEqual(pdf_anon.count_pseudonyms(restored.data), 0)
        tmp.cleanup()


class TextModeTests(unittest.TestCase):
    def test_extract_text_returns_one_string_per_page(self):
        self.assertEqual(len(pdf_anon.extract_text(sample_pdf(pages=3))), 3)

    def test_extracted_text_can_be_masked_and_restored(self):
        tmp, vault, opt, scrub = engine()
        pages = [scrub(page) for page in pdf_anon.extract_text(sample_pdf())]
        body = "\n".join(pages)
        for clear in IDENTIFYING:
            with self.subTest(clear=clear):
                self.assertNotIn(clear, body)
        back = Deanonymizer(vault, opt).process(body)
        self.assertIn("Mario Rossi", back)
        self.assertIn("SRV-DC01.corp.local", back)
        tmp.cleanup()


class GuardTests(unittest.TestCase):
    def test_is_pdf(self):
        self.assertTrue(pdf_anon.is_pdf(sample_pdf()))
        self.assertFalse(pdf_anon.is_pdf(b"PK\x03\x04 non un pdf"))
        self.assertFalse(pdf_anon.is_pdf(b""))

    def test_page_limit(self):
        saved = pdf_anon.MAX_PAGES
        pdf_anon.MAX_PAGES = 2
        try:
            with self.assertRaises(pdf_anon.PdfTooLargeError):
                pdf_anon.extract_text(sample_pdf(pages=5))
        finally:
            pdf_anon.MAX_PAGES = saved


if __name__ == "__main__":
    unittest.main()
