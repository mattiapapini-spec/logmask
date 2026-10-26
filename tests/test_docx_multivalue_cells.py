"""v0.27.7 - celle di tabella con piu' valori in elenco.

Un elenco dentro una cella Word usa <w:br/> (Shift+Invio) fra i valori, non
paragrafi separati. Il processore concatenava TUTTI i <w:t> del paragrafo
senza separatore: "10.0.0.1<br/>10.0.0.2" diventava "10.0.0.110.0.0.2", il
matcher agganciava solo il primo valore plausibile e gli altri restavano IN
CHIARO. Ora <w:br/>, <w:cr/> e <w:tab/> delimitano segmenti indipendenti,
ognuno mascherato per conto suo; i break restano al loro posto.
"""
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

import docx_anon
from logmask import (Anonymizer, Deanonymizer, NO_ELISION_DLP_POLICY, ORDER,
                     Options, Vault)

CT = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
      '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
      '<Default Extension="xml" ContentType="application/xml"/>'
      '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
      '</Types>')
RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '</Relationships>')
WNS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def para(*runs):
    return "<w:p>" + "".join(runs) + "</w:p>"


def run(text):
    return f"<w:r><w:t>{text}</w:t></w:r>"


def br():
    return "<w:r><w:br/></w:r>"


def make_docx(body: str) -> bytes:
    doc = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           f'<w:document {WNS}><w:body>{body}</w:body></w:document>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CT)
        z.writestr("_rels/.rels", RELS)
        z.writestr("word/document.xml", doc)
    return buf.getvalue()


def engine():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    anon = Anonymizer(vault, set(ORDER),
                      Options(ip_mode="all", dlp_policy=dict(NO_ELISION_DLP_POLICY)))
    return tmp, vault, anon


def doc_xml(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return z.read("word/document.xml").decode()


class MultiValueCellTests(unittest.TestCase):
    def test_every_ip_in_a_br_list_is_masked(self):
        body = ("<w:tbl><w:tr><w:tc>"
                + para(run("10.20.30.41"), br(), run("10.20.30.42"), br(), run("10.20.30.43"))
                + "</w:tc></w:tr></w:tbl>")
        tmp, vault, anon = engine()
        out = doc_xml(docx_anon.anonymize_docx(make_docx(body), anon.process).data)
        for ip in ("10.20.30.41", "10.20.30.42", "10.20.30.43"):
            self.assertNotIn(ip, out)

    def test_every_labeled_account_is_masked(self):
        """Il sintomo riportato: solo il primo 'Account Name:' veniva mascherato."""
        body = ("<w:tbl><w:tr><w:tc>"
                + para(run("Account Name: mrossi"), br(), run("Account Name: lbianchi"))
                + "</w:tc></w:tr></w:tbl>")
        tmp, vault, anon = engine()
        out = doc_xml(docx_anon.anonymize_docx(make_docx(body), anon.process).data)
        self.assertNotIn("mrossi", out)
        self.assertNotIn("lbianchi", out)

    def test_hosts_in_br_list_are_masked_individually(self):
        body = ("<w:tbl><w:tr><w:tc>"
                + para(run("SRV-DC01.corp.local"), br(), run("SRV-DC02.corp.local"))
                + "</w:tc></w:tr></w:tbl>")
        tmp, vault, anon = engine()
        out = doc_xml(docx_anon.anonymize_docx(make_docx(body), anon.process).data)
        self.assertNotIn("SRV-DC01", out)
        self.assertNotIn("SRV-DC02", out)
        # due host diversi -> due pseudonimi diversi (non fusi in uno)
        import re
        hosts = set(re.findall(r"host-[a-z2-7]{4,10}", out))
        self.assertEqual(len(hosts), 2, out)

    def test_breaks_survive_masking(self):
        body = ("<w:tbl><w:tr><w:tc>"
                + para(run("10.20.30.41"), br(), run("10.20.30.42"))
                + "</w:tc></w:tr></w:tbl>")
        tmp, vault, anon = engine()
        out = doc_xml(docx_anon.anonymize_docx(make_docx(body), anon.process).data)
        self.assertIn("br", out)   # l'interruzione di riga non viene rimossa

    def test_round_trip_restores_every_value(self):
        body = ("<w:tbl><w:tr><w:tc>"
                + para(run("10.20.30.41"), br(), run("10.20.30.42"), br(), run("10.20.30.43"))
                + "</w:tc><w:tc>"
                + para(run("Account Name: mrossi"), br(), run("Account Name: lbianchi"))
                + "</w:tc></w:tr></w:tbl>")
        tmp, vault, anon = engine()
        masked = docx_anon.anonymize_docx(make_docx(body), anon.process)
        deo = Deanonymizer(vault, anon.opt)
        back = docx_anon.deanonymize_docx(masked.data, deo.process)
        rest = doc_xml(back.data)
        for value in ("10.20.30.41", "10.20.30.42", "10.20.30.43", "mrossi", "lbianchi"):
            self.assertIn(value, rest)
        self.assertEqual(back.tokens_left, 0)

    def test_value_split_across_runs_within_a_segment_still_collapses(self):
        """La logica di collasso per-segmento resta: un valore spezzato fra
        run DENTRO la stessa riga viene ricomposto e mascherato."""
        body = ("<w:tbl><w:tr><w:tc>"
                + para(run("10.20."), run("30.41"), br(), run("10.20.30.42"))
                + "</w:tc></w:tr></w:tbl>")
        tmp, vault, anon = engine()
        out = doc_xml(docx_anon.anonymize_docx(make_docx(body), anon.process).data)
        self.assertNotIn("30.41", out)
        self.assertNotIn("10.20.30.42", out)

    def test_multi_paragraph_cells_still_work(self):
        body = ("<w:tbl><w:tr><w:tc>"
                + para(run("192.168.7.1")) + para(run("192.168.7.2"))
                + "</w:tc></w:tr></w:tbl>")
        tmp, vault, anon = engine()
        out = doc_xml(docx_anon.anonymize_docx(make_docx(body), anon.process).data)
        self.assertNotIn("192.168.7.1", out)
        self.assertNotIn("192.168.7.2", out)

    def test_count_pseudonyms_does_not_fuse_adjacent_tokens(self):
        body = para(run("usr-abcd2345"), br(), run("usr-efgh6777"))
        n = docx_anon.count_pseudonyms(make_docx(body))
        self.assertEqual(n, 2)


if __name__ == "__main__":
    unittest.main()
