"""v0.21.5 — le convenzioni host non devono corrompere gli ID opachi (base64).

I host_terms fanno match su SOTTOSTRINGHE: un glob come *DC* o WKS* combacia
con pezzi casuali dentro un _id base64 ("6bI/+VVDCxxxx==") e lo sostituisce con
un pseudonimo host, corrompendo l'identificatore univoco dell'evento. Il guasto
e' silenzioso: nessun errore, solo dedup, correlazione evento-alert e join
rotti. Un hostname puo' contenere solo lettere, cifre, punto e trattino: se il
carattere adiacente al match e' "+", "/" o "=" siamo dentro un blob opaco.
"""
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ORDER, Options, Vault,
                     inside_opaque_blob)

# convenzioni di naming inventate: glob "contains" e "prefix" molto larghi
REAL_HOST_TERMS = ("KWX*", "JVX*", "KDA*", "*QNS", "*.WORKGROUP", "XL-*",
                   "*DC*", "WKS*", "YBW*", "Fzr*", "fzr*", "FZR*")

EVENT_IDS = [
    "XIlU+FbPWXlloJYNbRoP+g==:190:119:255",   # riferimento corretto
    "6bI/+VVDCsomethingzz==:124:119:255",     # *DC* dentro il base64
    "WKSabcdefghijklmnop==:408:119:255",      # WKS* a inizio blob
    "deeb2prb/2avb6g==:146:119:255",
    "3rumk6w2DCab==:408:119:255",
]


def make_engine(**opt):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt))


class OpaqueBlobGuardTests(unittest.TestCase):
    def test_helper_detects_base64_context(self):
        text = "6bI/+VVDCxxx=="
        self.assertTrue(inside_opaque_blob(text, 5, 12))     # fra "+" e "="

    def test_helper_allows_plain_boundaries(self):
        text = "host WKS0421 online"
        self.assertFalse(inside_opaque_blob(text, 5, 12))    # fra spazi

    def test_helper_handles_string_edges(self):
        """Regressione: "" in "+/=" e' True in Python, quindi un hostname che
        occupa tutto il valore rischiava di non essere mai mascherato."""
        self.assertFalse(inside_opaque_blob("WKS0421", 0, 7))


class EventIdNotCorruptedTests(unittest.TestCase):
    def test_base64_event_ids_survive_host_terms(self):
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS)
        for event_id in EVENT_IDS:
            with self.subTest(event_id=event_id[:24]):
                self.assertEqual(anon.process(event_id), event_id)
        tmp.cleanup()

    def test_no_host_pseudonym_injected(self):
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS)
        for event_id in EVENT_IDS:
            self.assertNotIn("host-", anon.process(event_id))
        tmp.cleanup()

    def test_ids_untouched_without_host_terms_too(self):
        tmp, vault, anon = make_engine()
        for event_id in EVENT_IDS:
            self.assertEqual(anon.process(event_id), event_id)
        tmp.cleanup()


class RealHostsStillMaskedTests(unittest.TestCase):
    """La protezione non deve impedire il mascheramento dei nomi macchina."""

    HOSTS = ["WKS0421", "KWX03", "SRVDC01", "JVXSRV", "XL-nord", "YBW12", "FZR99"]

    def test_bare_hosts_masked(self):
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS)
        for host in self.HOSTS:
            with self.subTest(host=host):
                out = anon.process(host)
                self.assertTrue(out.startswith("host-"), out)
                self.assertNotIn(host, out)
        tmp.cleanup()

    def test_hosts_inside_sentence_masked(self):
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS)
        out = anon.process("connessione da WKS0421 verso KWX03")
        self.assertNotIn("WKS0421", out)
        self.assertNotIn("KWX03", out)
        tmp.cleanup()

    def test_host_masking_still_reversible(self):
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS)
        masked = anon.process("WKS0421")
        self.assertEqual(Deanonymizer(vault, anon.opt).process(masked), "WKS0421")
        tmp.cleanup()

    def test_ioc_hash_guard_still_active(self):
        """Il guard v0.21.3 sugli hash non deve essere stato indebolito."""
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS)
        sha = "43c2d3293ad939241df61b3630a9d3b6dcaa11223344556677889900aabbccdd"
        self.assertEqual(anon.process(sha), sha)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
