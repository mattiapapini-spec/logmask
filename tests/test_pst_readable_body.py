"""v0.23.1 - due colonne per il contenuto del messaggio.

`completeHeader` conserva il messaggio come esce dall'archivio (MIME, HTML,
header dei messaggi inoltrati e citati): niente viene perso. `body` contiene lo
stesso contenuto ridotto a testo leggibile - senza tag, entita' o spaziatura
casuale - perche' e' la colonna che un analista legge davvero.

Copre anche un difetto trovato mentre si scriveva: un messaggio non multipart in
SOLO HTML - cioe' la maggior parte della posta reale - produceva un corpo vuoto,
perche' si accettava esclusivamente text/plain. Il contenuto spariva
dall'export senza nessun errore.
"""
import email
import unittest

import pst_anon

HTML = """<html><head><style>p{color:red}</style></head><body>
<p>Gentile&nbsp;cliente,</p><div>fattura <b>n.&nbsp;2025/1234</b>.</div>
<table><tr><td>Importo</td><td>1.250,00&nbsp;&euro;</td></tr></table>
<p>Saluti<br>Amministrazione</p>
<blockquote>Da: mario.rossi@example.com<br>Oggetto: sollecito</blockquote>
<script>track()</script></body></html>"""


def record(payload: str, ctype: str = "text/html; charset=utf-8") -> dict:
    msg = email.message_from_string(
        f"From: Mario Rossi <mario.rossi@example.com>\nTo: a@b.it\n"
        f"Subject: Fattura\nContent-Type: {ctype}\n\n{payload}")
    return pst_anon.message_to_record(msg, folder="Posta in arrivo")


class ColumnsTests(unittest.TestCase):
    def test_both_columns_exist_and_are_ordered(self):
        self.assertIn("completeHeader", pst_anon.RECORD_FIELDS)
        self.assertIn("body", pst_anon.RECORD_FIELDS)
        fields = list(pst_anon.RECORD_FIELDS)
        self.assertLess(fields.index("completeHeader"), fields.index("body"))

    def test_both_columns_are_anonymized(self):
        for field in ("completeHeader", "body"):
            with self.subTest(field=field):
                self.assertIn(field, pst_anon.TEXT_FIELDS)

    def test_complete_header_keeps_the_markup(self):
        rec = record(HTML)
        self.assertIn("<table>", rec["completeHeader"])
        self.assertIn("&nbsp;", rec["completeHeader"])

    def test_body_is_readable(self):
        body = record(HTML)["body"]
        for markup in ("<p>", "<table>", "&nbsp;", "&euro;", "track()", "color:red"):
            with self.subTest(markup=markup):
                self.assertNotIn(markup, body)
        self.assertIn("Gentile cliente,", body)
        self.assertIn("1.250,00 €", body)

    def test_quoted_chain_is_kept(self):
        """Nelle analisi la catena citata e' spesso la prova: non si butta."""
        body = record(HTML)["body"]
        self.assertIn("mario.rossi@example.com", body)
        self.assertIn("sollecito", body)


class HtmlOnlyMessageTests(unittest.TestCase):
    def test_html_only_message_is_not_empty(self):
        """Regressione: il corpo spariva del tutto sui messaggi solo-HTML."""
        rec = record(HTML)
        self.assertTrue(rec["completeHeader"].strip())
        self.assertTrue(rec["body"].strip())

    def test_plain_text_message_still_works(self):
        rec = record("Ciao,\r\n\r\n\r\n\r\nrichiesta   ricevuta.\r\n  ",
                     ctype="text/plain; charset=utf-8")
        self.assertEqual(rec["body"], "Ciao,\n\nrichiesta ricevuta.")

    def test_non_text_message_stays_empty(self):
        rec = record("\x00\x01binario", ctype="application/octet-stream")
        self.assertEqual(rec["completeHeader"], "")
        self.assertEqual(rec["body"], "")


class ReadableTextTests(unittest.TestCase):
    def test_broken_html_does_not_raise(self):
        self.assertEqual(pst_anon.readable_text("<div>testo <b>non chiuso <p>secondo"),
                         "testo non chiuso\nsecondo")

    def test_table_cells_are_separated(self):
        out = pst_anon.readable_text("<table><tr><td>Importo</td><td>1.250</td></tr></table>")
        self.assertIn("Importo\t1.250", out)

    def test_blank_runs_are_collapsed(self):
        self.assertEqual(pst_anon.readable_text("a<br><br><br><br><br>b"), "a\n\nb")

    def test_invisible_characters_removed(self):
        self.assertEqual(pst_anon.readable_text("te​sto﻿"), "testo")

    def test_empty_input(self):
        self.assertEqual(pst_anon.readable_text(""), "")

    def test_plain_text_is_not_html_unescaped(self):
        """In un testo non-HTML "&amp;" e' letterale: non va tradotto."""
        self.assertEqual(pst_anon.readable_text("Rossi &amp; Figli"), "Rossi &amp; Figli")


class SerializationTests(unittest.TestCase):
    def test_csv_header_contains_both_columns(self):
        header = pst_anon.to_csv([record(HTML)]).splitlines()[0]
        self.assertIn("completeHeader", header)
        self.assertIn("body", header)

    def test_ndjson_contains_both_columns(self):
        import json
        row = json.loads(pst_anon.to_ndjson([record(HTML)]))
        self.assertTrue(row["completeHeader"])
        self.assertTrue(row["body"])
        self.assertNotEqual(row["completeHeader"], row["body"])


if __name__ == "__main__":
    unittest.main()
