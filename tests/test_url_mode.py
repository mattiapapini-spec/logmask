"""v0.24.0 - policy URL a tre livelli, speculare alla policy IP.

    none     -> l'URL resta com'e'
    internal -> maschera solo gli host riconducibili al cliente (IP interni o
                delle reti tenant, FQDN gia' nel vault, nomi cliente); il resto
                resta leggibile
    all      -> mascheratura completa (default, comportamento storico)

Con un'eccezione NON negoziabile: credenziali userinfo e valori di query
dichiaratamente sensibili (token=, password=, ...) vengono trattati in OGNI
modo, anche in "none". Sono segreti, non indirizzi: la policy URL decide
quanto dell'indirizzo resta leggibile, non se far uscire un segreto.
"""
import tempfile
import unittest
from pathlib import Path

from logmask import Anonymizer, Deanonymizer, ORDER, Options, Vault

EXTERNAL = "https://evil-c2.badsite.ru/payload.bin?id=abc123"
CLIENT = "https://portal.acmespa.it/login?user=mrossi&token=sEcReT123456"
INTERNAL_IP = "http://10.20.30.40:8080/admin"
TENANT_IP = "http://93.57.78.9/panel"
CREDS = "https://user:Password1@ftp.example.com/dir/file.txt"


def engine(url_mode):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                  ip_mode="all", url_mode=url_mode,
                  tenant_networks=("93.57.78.0/24",))
    anon = Anonymizer(vault, set(ORDER), opt)
    anon._map("fqdn", "portal.acmespa.it")      # host noto del cliente
    return tmp, vault, anon, opt


class AllModeTests(unittest.TestCase):
    def test_every_host_is_masked(self):
        tmp, _v, anon, _o = engine("all")
        for url in (EXTERNAL, CLIENT, INTERNAL_IP, TENANT_IP):
            with self.subTest(url=url[:40]):
                out = anon.process(url)
                self.assertNotIn("badsite", out) if "badsite" in url else None
                self.assertTrue("host-" in out or "198.1" in out, out)
        tmp.cleanup()

    def test_round_trip(self):
        tmp, vault, anon, opt = engine("all")
        masked = anon.process("https://evil-c2.badsite.ru/payload.bin")
        self.assertEqual(Deanonymizer(vault, opt).process(masked),
                         "https://evil-c2.badsite.ru/payload.bin")
        tmp.cleanup()


class InternalModeTests(unittest.TestCase):
    def test_external_url_stays_readable(self):
        tmp, _v, anon, _o = engine("internal")
        out = anon.process(EXTERNAL)
        self.assertIn("evil-c2.badsite.ru", out)
        self.assertIn("payload.bin", out)
        tmp.cleanup()

    def test_client_host_is_masked(self):
        tmp, _v, anon, _o = engine("internal")
        out = anon.process(CLIENT)
        self.assertNotIn("portal.acmespa.it", out)
        self.assertIn("host-", out)
        tmp.cleanup()

    def test_internal_and_tenant_ip_hosts_are_masked(self):
        tmp, _v, anon, _o = engine("internal")
        for url, ip in ((INTERNAL_IP, "10.20.30.40"), (TENANT_IP, "93.57.78.9")):
            with self.subTest(url=url):
                self.assertNotIn(ip, anon.process(url))
        tmp.cleanup()

    def test_token_still_elided(self):
        tmp, _v, anon, _o = engine("internal")
        self.assertNotIn("sEcReT123456", anon.process(CLIENT))
        tmp.cleanup()


class NoneModeTests(unittest.TestCase):
    def test_urls_are_kept(self):
        tmp, _v, anon, _o = engine("none")
        for url in (EXTERNAL, INTERNAL_IP, TENANT_IP):
            with self.subTest(url=url[:40]):
                self.assertEqual(anon.process(url), url)
        tmp.cleanup()

    def test_client_hostname_is_kept_too(self):
        tmp, _v, anon, _o = engine("none")
        self.assertIn("portal.acmespa.it", anon.process(CLIENT))
        tmp.cleanup()

    def test_secrets_never_come_out_even_in_none(self):
        """La parte non negoziabile."""
        tmp, _v, anon, _o = engine("none")
        out_creds = anon.process(CREDS)
        self.assertNotIn("Password1", out_creds)
        out_token = anon.process(CLIENT)
        self.assertNotIn("sEcReT123456", out_token)
        tmp.cleanup()

    def test_rest_of_the_line_is_still_processed(self):
        """La policy URL riguarda gli URL: un IP nudo fuori dall'URL segue
        la policy IP."""
        tmp, _v, anon, _o = engine("none")
        out = anon.process(f"contatto {EXTERNAL} da 10.99.88.77")
        self.assertIn(EXTERNAL, out)
        self.assertNotIn("10.99.88.77", out)
        tmp.cleanup()


class FieldLevelIocStillWinsTests(unittest.TestCase):
    def test_ioc_field_readable_even_with_mode_all(self):
        tmp, _v, anon, _o = engine("all")
        out = anon.process(EXTERNAL, url_ioc=True)
        self.assertIn("evil-c2.badsite.ru", out)
        tmp.cleanup()


class OptionsValidationTests(unittest.TestCase):
    def test_invalid_mode_falls_back_to_all(self):
        self.assertEqual(Options(url_mode="banana").url_mode, "all")
        self.assertEqual(Options(url_mode=None).url_mode, "all")
        self.assertEqual(Options().url_mode, "all")


if __name__ == "__main__":
    unittest.main()
