"""v0.24.1 - audit di sicurezza: limiti sul contenuto DECOMPRESSO.

Il limite di upload agisce sui byte compressi. Un .docx da 200 KB puo'
espandersi a centinaia di MB in memoria (misurato: picco RSS 613 MB prima del
fix) e un .pst confezionato ad arte puo' far scrivere a readpst molti piu'
byte di quelli caricati, fino a esaurire disco o memoria del container: un
denial of service alla portata di chiunque possa caricare un file.

Due controlli, perche' l'indice zip puo' mentire: prima la somma delle
dimensioni dichiarate, poi un budget sui byte realmente letti (zipfile limita
comunque la lettura alla dimensione dichiarata e verifica il CRC, quindi
mentire al ribasso produce un errore, non un'espansione).
"""
import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

import docx_anon
import pst_anon

DOC_XML = ('<?xml version="1.0"?><w:document xmlns:w='
           '"http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:body><w:p><w:r><w:t>contatto m.rossi@acme.it</w:t></w:r></w:p>'
           '</w:body></w:document>')


def make_docx(extra_member: bytes | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", DOC_XML)
        if extra_member is not None:
            z.writestr("word/media/huge.bin", extra_member)
    return buf.getvalue()


class DocxBombTests(unittest.TestCase):
    def setUp(self):
        self._save = docx_anon.MAX_UNCOMPRESSED
        docx_anon.MAX_UNCOMPRESSED = 4 * 1024 * 1024      # 4 MiB per i test

    def tearDown(self):
        docx_anon.MAX_UNCOMPRESSED = self._save

    def test_declared_bomb_is_rejected_immediately(self):
        bomb = make_docx(b"\0" * (8 * 1024 * 1024))
        self.assertLess(len(bomb), 64 * 1024)              # supera l'upload check
        with self.assertRaises(docx_anon.DocxTooLargeError) as ctx:
            docx_anon.anonymize_docx(bomb, lambda s: s)
        self.assertIn("MiB", str(ctx.exception))

    def test_count_pseudonyms_is_protected_too(self):
        bomb = make_docx(b"\0" * (8 * 1024 * 1024))
        with self.assertRaises(docx_anon.DocxTooLargeError):
            docx_anon.count_pseudonyms(bomb)

    def test_legitimate_document_still_works(self):
        doc = make_docx(b"immagine finta" * 100)
        result = docx_anon.anonymize_docx(
            doc, lambda s: s.replace("m.rossi@acme.it", "usr-x@y.masked"))
        self.assertEqual(result.changed, 1)

    def test_error_is_a_value_error(self):
        """L'endpoint la mappa su HTTP 413: deve restare ValueError."""
        self.assertTrue(issubclass(docx_anon.DocxTooLargeError, ValueError))


class PstExtractionCapTests(unittest.TestCase):
    def test_oversized_extraction_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fake = td / "readpst"
            fake.write_text('#!/bin/sh\nfor a in "$@"; do :; done\n'
                            'dd if=/dev/zero of="$2/big.mbox" bs=1M count=8 2>/dev/null\n'
                            'exit 0\n')
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            save_bin, save_cap = pst_anon.READPST, pst_anon.MAX_EXTRACTED
            pst_anon.READPST = str(fake)
            pst_anon.MAX_EXTRACTED = 4 * 1024 * 1024
            try:
                with self.assertRaises(pst_anon.PstExtractionError) as ctx:
                    pst_anon.extract_records(td / "x.pst")
                self.assertIn("limite", str(ctx.exception))
            finally:
                pst_anon.READPST, pst_anon.MAX_EXTRACTED = save_bin, save_cap

    def test_small_extraction_passes(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fake = td / "readpst"
            fake.write_text('#!/bin/sh\nexit 0\n')
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            save = pst_anon.READPST
            pst_anon.READPST = str(fake)
            try:
                self.assertEqual(pst_anon.extract_records(td / "x.pst"), [])
            finally:
                pst_anon.READPST = save


class EntityExpansionTests(unittest.TestCase):
    def test_billion_laughs_is_blocked(self):
        """expat respinge l'amplificazione da entita': il docx fallisce con un
        errore, non con l'esplosione della memoria."""
        bomb_xml = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "AAAAAAAAAA">'
                    + "".join(f'<!ENTITY {chr(98+i)} "'
                              + f'&{chr(97+i)};' * 8 + '">' for i in range(8))
                    + ']><w:document xmlns:w="http://schemas.openxmlformats.org/'
                      'wordprocessingml/2006/main"><w:body><w:p><w:r>'
                      '<w:t>&i;</w:t></w:r></w:p></w:body></w:document>')
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", bomb_xml)
        with self.assertRaises(Exception):
            docx_anon.anonymize_docx(buf.getvalue(), lambda s: s)


if __name__ == "__main__":
    unittest.main()
