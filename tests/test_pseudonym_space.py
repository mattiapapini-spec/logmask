"""v0.23.4 - lo spazio di pseudonimi IPv4 non deve finire dopo 253 indirizzi.

Con «preserva subnet» l'ottetto host veniva costruito con ``s[0] or 1``: 255
valori possibili per 256 ottetti reali. Un export che toccava tutti gli host di
una subnet - cioe' un qualunque export Elastic di una rete vera - esauriva lo
spazio e l'anonimizzazione moriva a meta' con "pseudonym space exhausted".
Concorreva un secondo difetto: 64 tentativi di salt sono un sondaggio casuale,
e con 255 posti su 256 occupati falliscono nel 78% dei casi PUR ESSENDOCI un
posto libero.

Riusare uno pseudonimo gia' assegnato non e' un'alternativa: fonderebbe due
macchine diverse nello stesso indirizzo sintetico, corrompendo l'analisi in
silenzio. Quando lo spazio finisce davvero si dice cosa fare.
"""
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ORDER, Options,
                     PseudonymSpaceExhausted, Vault)


def engine(preserve_subnet: bool):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    opt = Options(preserve_subnet=preserve_subnet, keep_domain=False,
                  keep_scope=True, ip_mode="all")
    return tmp, vault, Anonymizer(vault, set(ORDER), opt), opt


class FullSubnetTests(unittest.TestCase):
    def test_every_host_of_a_subnet_is_mapped(self):
        """Il caso che falliva: 256 host della stessa /24."""
        tmp, _vault, anon, _opt = engine(True)
        seen = {}
        for last in range(256):
            ip = f"10.20.30.{last}"
            out = anon.process(ip)
            self.assertNotEqual(out, ip)
            self.assertNotIn(out, seen, f"{ip} e {seen.get(out)} -> stesso pseudonimo")
            seen[out] = ip
        self.assertEqual(len(seen), 256)
        tmp.cleanup()

    def test_many_subnets_and_hosts(self):
        tmp, _vault, anon, _opt = engine(True)
        seen = set()
        for third in range(64):
            for last in range(256):
                seen.add(anon.process(f"10.20.{third}.{last}"))
        self.assertEqual(len(seen), 64 * 256)
        tmp.cleanup()

    def test_subnet_grouping_is_preserved(self):
        tmp, _vault, anon, _opt = engine(True)
        a = anon.process("10.20.30.5").rsplit(".", 1)[0]
        b = anon.process("10.20.30.200").rsplit(".", 1)[0]
        c = anon.process("10.20.31.5").rsplit(".", 1)[0]
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        tmp.cleanup()

    def test_round_trip_over_a_full_subnet(self):
        tmp, vault, anon, opt = engine(True)
        deanon = Deanonymizer(vault, opt)
        for last in (0, 1, 127, 254, 255):
            ip = f"10.20.30.{last}"
            with self.subTest(ip=ip):
                self.assertEqual(deanon.process(anon.process(ip)), ip)
        tmp.cleanup()


class FlatModeTests(unittest.TestCase):
    def test_large_volume_without_subnet_preservation(self):
        tmp, _vault, anon, _opt = engine(False)
        seen = set()
        for third in range(40):
            for last in range(256):
                seen.add(anon.process(f"10.20.{third}.{last}"))
        self.assertEqual(len(seen), 40 * 256)
        tmp.cleanup()

    def test_round_trip(self):
        tmp, vault, anon, opt = engine(False)
        self.assertEqual(Deanonymizer(vault, opt).process(anon.process("93.57.78.9")),
                         "93.57.78.9")
        tmp.cleanup()


class ExhaustionIsExplainedTests(unittest.TestCase):
    def test_too_many_subnets_gives_an_actionable_message(self):
        tmp, _vault, anon, _opt = engine(True)
        with self.assertRaises(PseudonymSpaceExhausted) as ctx:
            for a in range(2):
                for b in range(256):
                    anon.process(f"10.{a}.{b}.1")
        message = str(ctx.exception)
        self.assertIn("256", message)
        self.assertIn("subnet", message.lower())
        tmp.cleanup()

    def test_exhaustion_is_a_runtime_error_subclass(self):
        """Il codice esistente che cattura RuntimeError continua a funzionare."""
        self.assertTrue(issubclass(PseudonymSpaceExhausted, RuntimeError))

    def test_api_returns_422_with_the_message(self):
        import app as app_module
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        probe = FastAPI()
        probe.add_exception_handler(PseudonymSpaceExhausted,
                                    app_module.pseudonym_space_json)

        @probe.get("/boom")
        def boom():
            raise PseudonymSpaceExhausted("«Preserva subnet» ... disattivala")

        res = TestClient(probe, raise_server_exceptions=False).get("/boom")
        self.assertEqual(res.status_code, 422)
        self.assertIn("Preserva subnet", res.json()["detail"])


if __name__ == "__main__":
    unittest.main()
