import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from logmask import (
    ORDER,
    Anonymizer,
    CsvAnonymizer,
    Deanonymizer,
    Options,
    Vault,
    default_policy,
    read_samples,
    sweep_known,
)
from structured import anonymize_structured


class IpPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.key = b"I" * 32

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, mode: str, preserve_subnet: bool = False):
        vault = Vault(self.root / f"{mode}.db", self.key)
        anon = Anonymizer(
            vault,
            set(ORDER),
            Options(ip_mode=mode, preserve_subnet=preserve_subnet),
        )
        self.addCleanup(vault.db.close)
        return vault, anon

    def test_internal_mode_classifies_private_and_public_addresses(self):
        opt = Options(ip_mode="internal")
        internal = [
            "10.1.2.3",
            "172.16.4.5",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.10.20",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::1",
        ]
        public = [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.10",
            "2001:4860:4860::8888",
        ]
        self.assertTrue(all(opt.should_anonymize_ip(ip) for ip in internal))
        self.assertTrue(all(not opt.should_anonymize_ip(ip) for ip in public))

    def test_text_modes_all_internal_and_none(self):
        text = "internal=192.168.1.10 public=8.8.8.8"

        _vault, anon = self.make("internal")
        out = anon.process(text)
        self.assertNotIn("192.168.1.10", out)
        self.assertIn("8.8.8.8", out)
        self.assertEqual(anon.policy_kept["ipv4"], 1)
        self.assertEqual(anon.counts["ipv4"], 1)

        _vault, anon = self.make("all")
        out = anon.process(text)
        self.assertNotIn("192.168.1.10", out)
        self.assertNotIn("8.8.8.8", out)
        self.assertEqual(anon.counts["ipv4"], 2)

        _vault, anon = self.make("none")
        out = anon.process(text)
        self.assertEqual(out, text)
        self.assertEqual(anon.policy_kept["ipv4"], 2)
        self.assertEqual(anon.counts["ipv4"], 0)

    def test_internal_mode_handles_mixed_csv_column(self):
        path = self.root / "mixed.csv"
        path.write_text("source_ip,severity\n192.168.1.20,low\n8.8.4.4,high\n", encoding="utf-8")
        columns, samples, dialect = read_samples(path)
        policy = default_policy(columns, samples)
        vault, anon = self.make("internal")
        processor = CsvAnonymizer(anon, policy, "test.csv", safe=True)
        out = io.StringIO(newline="")
        processor.process(path, out, dialect, columns)
        rows = list(csv.DictReader(io.StringIO(out.getvalue())))

        self.assertNotEqual(rows[0]["source_ip"], "192.168.1.20")
        self.assertEqual(rows[1]["source_ip"], "8.8.4.4")
        self.assertEqual(processor.per_col["source_ip"][4], 1)
        self.assertEqual(anon.counts["ipv4"], 1)
        self.assertEqual(processor.failed, 0)

    def test_internal_mode_applies_to_nested_json(self):
        vault, anon = self.make("internal")
        source = json.dumps(
            {
                "source": {"ip": "10.0.0.15"},
                "destination": {"ip": "1.1.1.1"},
                "event": {"action": "allow"},
            }
        )
        result = anonymize_structured(
            "json", source, anon, vault, safe=True, source="test.json"
        )
        parsed = json.loads(result.output)
        self.assertNotEqual(parsed["source"]["ip"], "10.0.0.15")
        self.assertEqual(parsed["destination"]["ip"], "1.1.1.1")
        self.assertEqual(result.policy_kept, 1)
        self.assertFalse(result.blocked)

    def test_known_entity_sweep_obeys_internal_policy(self):
        vault = Vault(self.root / "sweep.db", self.key)
        self.addCleanup(vault.db.close)
        creator = Anonymizer(vault, set(ORDER), Options(ip_mode="all"))
        private_pseudo = creator.process("192.168.50.5")
        public_pseudo = creator.process("9.9.9.9")
        vault.commit()

        text, count = sweep_known(
            vault,
            "seen 192.168.50.5 and 9.9.9.9",
            Options(ip_mode="internal"),
        )
        self.assertNotIn("192.168.50.5", text)
        self.assertIn("9.9.9.9", text)
        self.assertIn(private_pseudo, text)
        self.assertNotIn(public_pseudo, text)
        self.assertEqual(count, 1)


    def test_ipv4_pseudonyms_use_benchmark_range_not_customer_ranges(self):
        vault, anon = self.make("all")
        out = anon.process("internal=192.168.1.10 public=8.8.8.8")
        self.assertNotIn("192.168.1.10", out)
        self.assertNotIn("8.8.8.8", out)
        self.assertNotRegex(out, r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        self.assertNotRegex(out, r"\b100\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        self.assertRegex(out, r"\b198\.18\.\d{1,3}\.\d{1,3}\b")
        self.assertRegex(out, r"\b198\.19\.\d{1,3}\.\d{1,3}\b")
        vault.commit()
        restored = Deanonymizer(vault, Options()).process(out)
        self.assertIn("192.168.1.10", restored)
        self.assertIn("8.8.8.8", restored)

    def test_preserve_subnet_uses_benchmark_range_and_reverses(self):
        vault, anon = self.make("all", preserve_subnet=True)
        out = anon.process("a=192.168.44.7 b=192.168.44.8 c=1.1.1.1")
        self.assertRegex(out, r"\b198\.18\.\d{1,3}\.\d{1,3}\b")
        self.assertRegex(out, r"\b198\.19\.\d{1,3}\.\d{1,3}\b")
        self.assertNotRegex(out, r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        self.assertNotRegex(out, r"\b100\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        vault.commit()
        restored = Deanonymizer(vault, Options()).process(out)
        self.assertIn("192.168.44.7", restored)
        self.assertIn("192.168.44.8", restored)
        self.assertIn("1.1.1.1", restored)

    def test_frontend_exposes_exact_three_modes(self):
        html = (Path(__file__).parents[1] / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn('value="all" selected>anonimizza tutti gli IP', html)
        self.assertIn('value="internal">anonimizza solo IP interni', html)
        self.assertIn('value="none">non anonimizzare IP', html)
        self.assertNotIn('value="external"', html)


if __name__ == "__main__":
    unittest.main()
