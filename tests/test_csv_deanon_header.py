"""v0.21.4 — la de-anonimizzazione CSV/TSV saltava la prima riga.

csv_deanonymize copiava la prima riga invariata, assumendola un header di nomi
colonna. Ma un export senza header - una singola cella, o una lista di
pseudonimi - non veniva mai ripristinato: l'unica riga era trattata come
header e restituita tale e quale ("risolti 0"). Ora tutte le righe vengono
reversate; il reverse e' mirato (tocca solo i valori presenti nel vault del
tenant), quindi i veri nomi colonna, che non sono pseudonimi, restano intatti.
"""
import csv
import io
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ORDER, Options, Vault,
                     csv_deanonymize)


def _engine(**opt):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt))


def _deanon(tmpdir, vault, opt, content):
    src = Path(tmpdir) / "in.tsv"
    src.write_text(content, encoding="utf-8")
    out = io.StringIO()
    csv_deanonymize(src, out, Deanonymizer(vault, opt))
    return out.getvalue()


class CsvDeanonHeaderTests(unittest.TestCase):
    def test_single_cell_is_reversed(self):
        tmp, vault, anon = _engine(ip_mode="all")
        masked = anon.process("93.57.78.9")
        out = _deanon(tmp.name, vault, anon.opt, masked + "\n")
        self.assertIn("93.57.78.9", out)
        tmp.cleanup()

    def test_list_without_header_all_reversed(self):
        tmp, vault, anon = _engine(ip_mode="all")
        a = anon.process("93.57.78.9")
        b = anon.process("8.8.4.4")
        out = _deanon(tmp.name, vault, anon.opt, f"{a}\n{b}\n")
        self.assertIn("93.57.78.9", out)
        self.assertIn("8.8.4.4", out)
        tmp.cleanup()

    def test_first_data_row_no_longer_skipped(self):
        """Anche con piu' righe, la PRIMA non deve piu' sfuggire."""
        tmp, vault, anon = _engine(ip_mode="all")
        a = anon.process("93.57.78.9")   # finiva sulla prima riga -> saltata
        b = anon.process("1.1.1.1")
        out = _deanon(tmp.name, vault, anon.opt, f"{a}\n{b}\n")
        self.assertIn("93.57.78.9", out)
        tmp.cleanup()

    def test_real_column_header_preserved(self):
        """Un vero header di nomi colonna non e' fatto di pseudonimi: resta
        intatto, e le righe dati vengono reversate."""
        tmp, vault, anon = _engine(ip_mode="all")
        ip1 = anon.process("93.57.78.9")
        ip2 = anon.process("10.20.30.40")
        out = _deanon(tmp.name, vault, anon.opt, f"src_ip,dst_ip\n{ip1},{ip2}\n")
        self.assertIn("src_ip", out)
        self.assertIn("dst_ip", out)
        self.assertIn("93.57.78.9", out)
        self.assertIn("10.20.30.40", out)
        tmp.cleanup()

    def test_non_pseudonym_header_words_untouched(self):
        tmp, vault, anon = _engine(ip_mode="all")
        out = _deanon(tmp.name, vault, anon.opt, "action_local_ip\nsome_value\n")
        self.assertIn("action_local_ip", out)
        self.assertIn("some_value", out)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
