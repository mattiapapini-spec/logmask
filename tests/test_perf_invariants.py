"""v0.17.0 — le ottimizzazioni non devono cambiare il comportamento.

Due interventi:
  1. fast-path O(1) in normalize_dlp_policy per una policy gia' validata;
  2. cache sul parsing degli IP (is_internal_ip / is_tenant_ip).

Qui si verifica che NESSUNO dei due indebolisca la validazione o alteri le
decisioni: la validazione degli input esterni (API/CLI) resta piena e il
mascheramento resta identico e reversibile.
"""
import json
import tempfile
import unittest
from pathlib import Path

from dlp import default_dlp_policy, normalize_dlp_policy
from logmask import (Anonymizer, Deanonymizer, ORDER, Options, Vault,
                     is_internal_ip)
from structured import anonymize_structured


class DlpPolicyFastPathTests(unittest.TestCase):
    def test_external_input_still_validated(self):
        """Il fast-path vale solo per policy gia' normalizzate: un dict
        qualsiasi (es. dal body API) deve essere validato come prima."""
        with self.assertRaises(ValueError):
            normalize_dlp_policy({"categoria_inesistente": "redact"})
        with self.assertRaises(ValueError):
            normalize_dlp_policy({"credentials": "azione_inesistente"})

    def test_fast_path_returns_equivalent_policy(self):
        once = normalize_dlp_policy({"credentials": "redact"})
        twice = normalize_dlp_policy(once)
        self.assertEqual(dict(once), dict(twice))
        self.assertEqual(twice["credentials"], "redact")

    def test_plain_dict_is_not_fast_pathed(self):
        """Un dict normale con le stesse chiavi deve comunque passare dalla
        validazione (non deve essere scambiato per gia'-normalizzato)."""
        plain = dict(default_dlp_policy())
        plain["credentials"] = "AZIONE_SBAGLIATA"
        with self.assertRaises(ValueError):
            normalize_dlp_policy(plain)

    def test_defaults_unchanged(self):
        self.assertEqual(dict(normalize_dlp_policy(None)), dict(default_dlp_policy()))


class IpCacheTests(unittest.TestCase):
    CASES = [("10.0.0.5", True), ("192.168.1.1", True), ("172.16.0.1", True),
             ("127.0.0.1", True), ("fd00::1", True), ("100.64.0.1", True),
             ("8.8.8.8", False), ("167.71.198.43", False), ("2001:4860::1", False),
             ("non-un-ip", False), ("", False)]

    def test_repeated_calls_stable(self):
        for value, expected in self.CASES:
            with self.subTest(ip=value):
                first = is_internal_ip(value)
                self.assertEqual(first, expected)
                for _ in range(3):                      # cache non deve deviare
                    self.assertEqual(is_internal_ip(value), expected)

    def test_tenant_ip_cache_is_per_options(self):
        """La cache tenant e' per-istanza: opzioni diverse -> risposte diverse."""
        with_net = Options(ip_mode="internal", tenant_networks=("203.0.113.0/24",))
        without = Options(ip_mode="internal")
        for _ in range(3):
            self.assertTrue(with_net.is_tenant_ip("203.0.113.9"))
            self.assertFalse(without.is_tenant_ip("203.0.113.9"))
            self.assertFalse(with_net.is_tenant_ip("8.8.8.8"))


class EndToEndUnchangedTests(unittest.TestCase):
    def test_masking_still_reversible_and_ip_policy_intact(self):
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        opt = Options(ip_mode="internal", tenant_networks=("203.0.113.0/24",))
        anon = Anonymizer(vault, set(ORDER), opt)
        doc = {"host.name": "web01", "user.name": "mrossi",
               "source.ip": "10.0.0.5",          # interno -> mascherato
               "destination.ip": "8.8.8.8",      # pubblico -> mantenuto
               "client.ip": "203.0.113.9"}       # rete tenant -> mascherato
        out = json.loads(anonymize_structured("json", json.dumps(doc), anon, vault,
                                              safe=True, source="t",
                                              family="elastic_ecs").output)
        self.assertNotIn("web01", json.dumps(out))
        self.assertNotIn("mrossi", json.dumps(out))
        self.assertNotEqual(out["source.ip"], "10.0.0.5")
        self.assertNotEqual(out["client.ip"], "203.0.113.9")
        self.assertEqual(out["destination.ip"], "8.8.8.8")
        deanon = Deanonymizer(vault, opt)
        self.assertEqual(deanon.process(out["host.name"]), "web01")
        self.assertEqual(deanon.process(out["source.ip"]), "10.0.0.5")
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
