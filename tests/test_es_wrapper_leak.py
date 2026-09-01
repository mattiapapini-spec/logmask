"""v0.16.1 — i wrapper di trasporto Elasticsearch (_source. / fields.) non devono
far cadere un campo sulla regola catch-all `keep` del kit.

Regressione del leak reale: in un hit ES, host.name/agent.name/observer.name
restavano IN CHIARO perche' la forma con prefisso (`fields.host.name`) veniva
provata per prima e catturata dal catch-all `^[\\w@]+\\..*$ -> keep` del kit ECS,
prima che venisse tentata la forma logica `host.name` (regola ^-ancorata -> mask).
I campi coperti da regole NON ancorate (.*\\.hostname$, .*\\.id$) mascheravano
comunque: da qui l'incoerenza _source <-> fields.
"""
import json
import tempfile
import unittest
from pathlib import Path

from logmask import Anonymizer, ORDER, Options, Vault, col_candidates, resolve_field
from structured import anonymize_structured


def make_engine(**opt_kwargs):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "vault.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt_kwargs))


class EsWrapperClassificationTests(unittest.TestCase):
    """La classificazione deve essere identica con e senza wrapper."""

    ANCHORED_IDENTITY = ["host.name", "agent.name", "observer.name",
                         "winlog.computer_name", "dns.question.name"]

    def test_transport_wrapper_never_changes_decision(self):
        for col in self.ANCHORED_IDENTITY:
            base = resolve_field(col, ["web01"], "elastic_ecs")
            for pre in ("_source.", "fields.", "fields._source.", "_source.fields."):
                with self.subTest(column=pre + col):
                    got = resolve_field(pre + col, ["web01"], "elastic_ecs")
                    self.assertEqual((got.action, got.kind), (base.action, base.kind))
                    self.assertEqual(got.action, "mask")      # mai keep: era il leak

    def test_wrapper_stripped_from_candidates(self):
        self.assertEqual(col_candidates("fields.host.name")[0], "host.name")
        self.assertEqual(col_candidates("_source.host.name")[0], "host.name")

    def test_semantic_prefixes_still_offered(self):
        """winlog.* NON e' trasporto: resta tra i candidati (kit vi si appoggiano)."""
        cands = col_candidates("winlog.event_data.SubjectUserName")
        self.assertIn("winlog.event_data.subjectusername", cands)
        self.assertIn("subjectusername", cands)


class EsHitEndToEndTests(unittest.TestCase):
    """Forma reale di un hit ES: _source annidato + blocco fields appiattito."""

    HIT = {
        "_index": "packetbeat-7.17.6", "_id": "ab12",
        "_source": {
            "host": {"name": "web01", "hostname": "WEB01.corp.local", "id": "i-0abc"},
            "agent": {"name": "web01", "hostname": "WEB01.corp.local", "type": "packetbeat"},
            "observer": {"name": "sensor-mi01"},
            "url": {"domain": "web01.corp.local", "path": "/gila/composer.json"},
            "source": {"ip": "167.71.198.43"},
        },
        "fields": {
            "host.name": ["web01"], "agent.name": ["web01"],
            "host.hostname": ["WEB01.corp.local"], "observer.name": ["sensor-mi01"],
            "url.domain": ["web01.corp.local"], "source.ip": ["167.71.198.43"],
        },
    }

    def _run(self):
        tmp, vault, anon = make_engine(ip_mode="internal")
        out = anonymize_structured("json", json.dumps(self.HIT), anon, vault,
                                   safe=True, source="t", family="elastic_ecs")
        parsed = json.loads(out.output)
        tmp.cleanup()
        return parsed, out.output

    def test_no_asset_name_in_clear(self):
        _, blob = self._run()
        for leak in ("web01", "WEB01", "sensor-mi01", "corp.local"):
            self.assertNotIn(leak, blob, leak)

    def test_source_and_fields_agree(self):
        p, _ = self._run()
        self.assertEqual(p["_source"]["host"]["name"], p["fields"]["host.name"][0])
        self.assertEqual(p["_source"]["agent"]["name"], p["fields"]["agent.name"][0])
        self.assertEqual(p["_source"]["observer"]["name"], p["fields"]["observer.name"][0])
        self.assertEqual(p["_source"]["host"]["hostname"], p["fields"]["host.hostname"][0])

    def test_same_value_same_token_across_both_copies(self):
        p, _ = self._run()
        self.assertEqual(p["_source"]["host"]["name"], p["_source"]["agent"]["name"])
        self.assertTrue(p["_source"]["host"]["name"].startswith("host-"))

    def test_operational_fields_still_readable(self):
        p, _ = self._run()
        self.assertEqual(p["_source"]["url"]["path"], "/gila/composer.json")
        self.assertEqual(p["_source"]["agent"]["type"], "packetbeat")


if __name__ == "__main__":
    unittest.main()
