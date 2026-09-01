"""v0.21.3 — le convenzioni host (host_terms) non devono distruggere gli IOC.

Un glob "contains" come *DC* combacia con qualsiasi hash SHA256 che contenga
"dc" (entrambe cifre esadecimali), trasformandolo in un pseudonimo host-* e
distruggendo proprio il valore su cui si fa pivot in un'indagine. E poiche' i
host_terms si applicano anche alle colonne mantenute in chiaro, veniva mangiato
anche il campo sha256 gia' classificato keep. L'MD5 che non conteneva "dc"
sopravviveva: da qui la firma del bug ("only its MD5 survived").
"""
import json
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ORDER, Options, Vault,
                     looks_like_ioc_hex)
from structured import anonymize_structured

# convenzioni di naming realistiche (inventate): notare *DC* (contains) e *QNS (suffix)
REAL_HOST_TERMS = ("KWX*", "JVX*", "KDA*", "*QNS", "*.WORKGROUP", "XL-*",
                   "*DC*", "WKS*", "YBW*", "Fzr*", "FZR*")

SHA256_WITH_DC = "43c2d3293ad939241df61b3630a9d3b6dcaa11223344556677889900aabbccdd"
SHA256_PLAIN = "1d5491e3c468ee4b4ef6edff4bbc7d06ee83180f6f0b1576763ea2efe049493a"
MD5 = "68f9b52895f4d34e74112f3129b3b00d"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def make_engine(**opt):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt))


class IocHexGuardTests(unittest.TestCase):
    def test_helper_recognises_hashes(self):
        for h in (SHA256_WITH_DC, SHA256_PLAIN, MD5, SHA1):
            self.assertTrue(looks_like_ioc_hex(h))

    def test_helper_rejects_hostnames(self):
        for name in ("SRVDC01", "web01", "DC01", "port-a", "srv-sso", "KWX01"):
            self.assertFalse(looks_like_ioc_hex(name))

    def test_hashes_survive_host_terms(self):
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS)
        for h in (SHA256_WITH_DC, SHA256_PLAIN, MD5, SHA1):
            with self.subTest(hash=h[:16]):
                self.assertEqual(anon.process(h), h)
        tmp.cleanup()

    def test_sha256_keep_field_and_title_preserved(self):
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS, ip_mode="internal")
        doc = {
            "action_file_sha256": SHA256_WITH_DC,
            "actor_process_image_sha256": SHA256_PLAIN,
            "action_file_md5": MD5,
            "name": f"IOC ({SHA256_WITH_DC})",
            "action_process_image_name": "ProcessHacker.exe",
        }
        out = json.loads(anonymize_structured("json", json.dumps(doc), anon, vault,
                                              safe=True, source="t", family="cortex").output)
        self.assertEqual(out["action_file_sha256"], SHA256_WITH_DC)
        self.assertEqual(out["actor_process_image_sha256"], SHA256_PLAIN)
        self.assertEqual(out["action_file_md5"], MD5)
        self.assertIn(SHA256_WITH_DC, out["name"])
        self.assertNotIn("host-", out["name"])
        tmp.cleanup()

    def test_real_hostnames_still_masked(self):
        """La protezione IOC non deve impedire il mascheramento degli host veri,
        anche quando contengono "DC"."""
        tmp, vault, anon = make_engine(host_terms=REAL_HOST_TERMS)
        for host in ("SRVDC01", "WKS0421", "KWX03", "JVXSRV"):
            with self.subTest(host=host):
                out = anon.process(host)
                self.assertTrue(out.startswith("host-"))
                self.assertNotIn(host, out)
        tmp.cleanup()

    def test_bare_hostname_heuristic_also_guarded(self):
        """Anche senza host_terms configurati, l'euristica non deve toccare un hash."""
        tmp, vault, anon = make_engine()
        self.assertEqual(anon.process(SHA256_WITH_DC), SHA256_WITH_DC)
        tmp.cleanup()

    def test_short_hex_hostname_still_masked(self):
        """Un nome host breve tipo 'dc01' non e' un IOC: la guardia scatta solo
        su stringhe esadecimali lunghe (>=16)."""
        self.assertFalse(looks_like_ioc_hex("dc01"))
        self.assertFalse(looks_like_ioc_hex("abcdef"))       # 6 char: non e' un hash


if __name__ == "__main__":
    unittest.main()
