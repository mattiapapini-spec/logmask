"""v0.18.0 — due allineamenti fra percorso testo libero e percorso strutturato.

1) Passthrough SOLO di cio' che riconosciamo come nostro: una stringa con la
   FORMA di uno pseudonimo non e' di per se' sicura (un host del cliente
   potrebbe chiamarsi davvero 'host-abcd1234'). Prima passava in chiaro nel
   testo libero (fail-open) e veniva ri-mascherata nelle colonne (output non
   idempotente). Ora: se e' nel vault del tenant passa, altrimenti si maschera.

2) Un host che compare sia come nome corto sia come FQDN riceve UN SOLO token.
   Se la stessa label esiste in piu' domini l'informazione per decidere non e'
   nel dato: non si indovina, il nome corto prende un token proprio e il caso
   viene contato come ambiguo.
"""
import json
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ORDER, Options, Vault,
                     build_host_label_index)
from structured import anonymize_structured


def make_engine(key=b"A" * 32, **opt_kwargs):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "vault.db", key)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt_kwargs))


def run_json(anon, vault, doc):
    return json.loads(anonymize_structured("json", json.dumps(doc), anon, vault,
                                           safe=True, source="t",
                                           family="elastic_ecs").output)


class VaultOwnedPassthroughTests(unittest.TestCase):
    def test_lookalike_token_masked_in_columns(self):
        """Fail-open chiuso: forma di pseudonimo ma non nostro -> mascherato.

        Vale ovunque LogMask decida di mascherare: colonne classificate dal kit
        e testo libero con contesto esplicito.
        """
        tmp, vault, anon = make_engine()
        doc = {"user.name": "usr-bbbb3456", "host.name": "host-aaaa2345",
               "host.id": "id-cccc45677890"}
        out = run_json(anon, vault, doc)
        for column, fake in doc.items():
            with self.subTest(column=column):
                self.assertNotEqual(out[column], fake)
        tmp.cleanup()

    def test_lookalike_token_masked_in_free_text_with_context(self):
        tmp, vault, anon = make_engine()
        self.assertNotIn("usr-bbbb3456", anon.process("user=usr-bbbb3456"))
        self.assertNotIn("host-aaaa2345", anon.process("da host-aaaa2345"))
        tmp.cleanup()

    def test_bare_word_without_context_is_a_general_limit(self):
        """Un token nudo senza contesto resta: NON e' specifico dei lookalike,
        vale per qualsiasi parola (limite noto, vedi README/SECURITY)."""
        tmp, vault, anon = make_engine()
        self.assertIn("mrossi", anon.process("connessione da mrossi"))
        self.assertIn("usr-bbbb3456", anon.process("connessione da usr-bbbb3456"))
        tmp.cleanup()

    def test_our_own_token_passes_unchanged(self):
        tmp, vault, anon = make_engine()
        first = run_json(anon, vault, {"host.hostname": "web01.corp.local"})
        token = first["host.hostname"]
        self.assertTrue(vault.owns(token))
        self.assertIn(token, anon.process(f"alert su {token}"))
        tmp.cleanup()

    def test_reanonymizing_output_is_stable(self):
        """Ri-processare un export gia' anonimizzato non deve cambiare i token."""
        tmp, vault, anon = make_engine()
        doc = {"host.hostname": "web01.corp.local", "user.name": "mrossi",
               "source.ip": "10.0.0.5", "user.email": "m.rossi@azienda.it"}
        first = run_json(anon, vault, doc)
        second = run_json(anon, vault, first)
        third = run_json(anon, vault, second)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_foreign_tenant_token_is_not_trusted(self):
        """Un token emesso da un ALTRO vault non e' 'gia' sicuro': si maschera."""
        tmp_a, vault_a, anon_a = make_engine(key=b"A" * 32)
        foreign = run_json(anon_a, vault_a, {"host.hostname": "web01.corp.local"})["host.hostname"]
        tmp_b, vault_b, anon_b = make_engine(key=b"B" * 32)
        self.assertFalse(vault_b.owns(foreign))
        self.assertNotIn(foreign, anon_b.process(f"visto {foreign}"))
        tmp_a.cleanup()
        tmp_b.cleanup()


class HostLabelLinkingTests(unittest.TestCase):
    def test_index_builder(self):
        idx = build_host_label_index(["web01.corp.local", "WEB01.corp.local",
                                      "web01.roma.local", "nodots", "a b.c"])
        self.assertEqual(idx["web01"], {"web01.corp.local", "web01.roma.local"})

    def test_short_name_and_fqdn_share_one_token(self):
        tmp, vault, anon = make_engine()
        out = run_json(anon, vault, {"host.name": "web01",
                                     "host.hostname": "web01.corp.local",
                                     "agent.name": "web01"})
        root = out["host.hostname"].split(".", 1)[0]
        self.assertEqual(out["host.name"], root)
        self.assertEqual(out["agent.name"], root)
        tmp.cleanup()

    def test_ambiguous_label_is_not_guessed(self):
        """Stessa label in due domini: nessuna attribuzione arbitraria."""
        tmp, vault, anon = make_engine()
        out = run_json(anon, vault, {"host.name": "web01",
                                     "a.hostname": "web01.milano.local",
                                     "b.hostname": "web01.roma.local"})
        root_a = out["a.hostname"].split(".", 1)[0]
        root_b = out["b.hostname"].split(".", 1)[0]
        self.assertNotEqual(root_a, root_b)                 # host distinti
        self.assertNotIn(out["host.name"], (root_a, root_b))  # non indovina
        self.assertGreaterEqual(anon.counts.get("host_label_ambiguous", 0), 1)
        tmp.cleanup()

    def test_short_name_without_fqdn_unchanged_behaviour(self):
        tmp, vault, anon = make_engine()
        out = run_json(anon, vault, {"host.name": "srv99"})
        self.assertTrue(out["host.name"].startswith("host-"))
        self.assertNotIn("srv99", json.dumps(out))
        tmp.cleanup()

    def test_linked_tokens_reverse_to_their_own_value(self):
        """v0.20.3: nome corto e FQDN condividono la radice (correlazione), ma
        ognuno reversa al PROPRIO valore originale. Prima il token breve non
        aveva una riga di vault e ricadeva sull'FQDN completo."""
        tmp, vault, anon = make_engine()
        out = run_json(anon, vault, {"host.name": "web01",
                                     "host.hostname": "web01.corp.local"})
        deanon = Deanonymizer(vault, anon.opt)
        self.assertEqual(deanon.process(out["host.hostname"]), "web01.corp.local")
        self.assertEqual(deanon.process(out["host.name"]), "web01")
        self.assertEqual(out["host.name"], out["host.hostname"].split(".", 1)[0])
        tmp.cleanup()

    def test_no_client_name_survives(self):
        tmp, vault, anon = make_engine()
        blob = json.dumps(run_json(anon, vault, {
            "host.name": "web01", "host.hostname": "web01.corp.local",
            "agent.name": "web01", "url.domain": "web01.corp.local"}))
        for leak in ("web01", "corp.local"):
            self.assertNotIn(leak, blob, leak)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
