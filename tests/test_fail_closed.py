import csv
import io
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from logmask import (
    ORDER,
    Anonymizer,
    CsvAnonymizer,
    ELIDED,
    Options,
    Vault,
    apply_safe_policy,
    default_policy,
    read_samples,
    redact_residuals,
    scan_sensitive_residuals,
)


class FailClosedTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.key = b"K" * 32

    def tearDown(self):
        self.tmpdir.cleanup()

    def make_engine(self):
        vault = Vault(self.root / "vault.db", self.key)
        anon = Anonymizer(vault, set(ORDER), Options(preserve_subnet=True))
        return vault, anon

    def run_csv(self, content: str, safe: bool):
        path = self.root / "input.csv"
        path.write_text(content)
        columns, samples, dialect = read_samples(path)
        policy = default_policy(columns, samples)
        if safe:
            policy = apply_safe_policy(policy, samples)
        vault, anon = self.make_engine()
        processor = CsvAnonymizer(anon, policy, "test", safe=safe)
        out = io.StringIO()
        processor.process(path, out, dialect, columns)
        vault.commit()
        return out.getvalue(), processor, policy, vault

    def test_invalid_ip_is_elided_in_safe_mode(self):
        output, processor, policy, vault = self.run_csv(
            "source_ip,severity\nnot-an-ip,high\n", safe=True
        )
        self.addCleanup(vault.db.close)
        self.assertEqual(policy["columns"]["source_ip"]["action"], "mask")
        self.assertIn(f"{ELIDED},high", output)
        self.assertEqual(processor.failed, 0)
        self.assertEqual(processor.elided, 1)

    def test_invalid_ip_blocks_when_safe_mode_is_off(self):
        output, processor, _policy, vault = self.run_csv(
            "source_ip,severity\nnot-an-ip,high\n", safe=False
        )
        self.addCleanup(vault.db.close)
        self.assertIn("not-an-ip", output)
        self.assertEqual(processor.failed, 1)
        self.assertIn("not-an-ip", processor.failed_samples)

    def test_unknown_numeric_column_is_not_assumed_safe(self):
        output, processor, policy, vault = self.run_csv(
            "customer_reference,severity\n3331234567,medium\n", safe=True
        )
        self.addCleanup(vault.db.close)
        self.assertEqual(policy["columns"]["customer_reference"]["action"], "redact")
        self.assertIn(f"{ELIDED},medium", output)
        self.assertEqual(processor.elided, 1)

    def test_valid_ip_is_masked_without_failure(self):
        output, processor, _policy, vault = self.run_csv(
            "source_ip,severity\n192.168.1.50,high\n", safe=True
        )
        self.addCleanup(vault.db.close)
        self.assertNotIn("192.168.1.50", output)
        self.assertEqual(processor.failed, 0)
        self.assertGreaterEqual(sum(processor.anon.counts.values()), 1)

    def test_secret_uuid_phone_and_iban_are_final_gate_findings(self):
        text = (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 "
            "correlation=123e4567-e89b-42d3-a456-426614174000 "
            "telefono: +39 333 123 4567 "
            "iban IT60X0542811101000000123456"
        )
        kinds = {finding["kind"] for finding in scan_sensitive_residuals(text)}
        self.assertTrue({"secret", "uuid", "phone", "iban"}.issubset(kinds))
        redacted, count, samples = redact_residuals(text)
        self.assertGreaterEqual(count, 4)
        self.assertNotIn("abcdefghijklmnop", redacted)
        self.assertNotIn("123e4567-e89b-42d3-a456-426614174000", redacted)
        self.assertTrue(samples)
        self.assertFalse(scan_sensitive_residuals(redacted))



    def test_ip_mode_all_masks_internal_and_external(self):
        vault = Vault(self.root / "all.db", self.key)
        self.addCleanup(vault.db.close)
        anon = Anonymizer(vault, set(ORDER), Options(ip_mode="all"))
        output = anon.process("src=192.168.1.10 dst=8.8.8.8")
        self.assertNotIn("192.168.1.10", output)
        self.assertNotIn("8.8.8.8", output)
        self.assertEqual(anon.counts["ipv4"], 2)

    def test_ip_mode_internal_masks_internal_and_keeps_external(self):
        vault = Vault(self.root / "internal.db", self.key)
        self.addCleanup(vault.db.close)
        anon = Anonymizer(vault, set(ORDER), Options(ip_mode="internal"))
        output = anon.process("src=192.168.1.10 dst=8.8.8.8 loop=127.0.0.1")
        self.assertNotIn("192.168.1.10", output)
        self.assertNotIn("127.0.0.1", output)
        self.assertIn("8.8.8.8", output)
        self.assertEqual(anon.counts["ipv4"], 2)
        self.assertEqual(anon.policy_kept["ipv4"], 1)

    def test_ip_mode_none_keeps_all_ips(self):
        vault = Vault(self.root / "none.db", self.key)
        self.addCleanup(vault.db.close)
        anon = Anonymizer(vault, set(ORDER), Options(ip_mode="none"))
        output = anon.process("src=192.168.1.10 dst=8.8.8.8")
        self.assertIn("192.168.1.10", output)
        self.assertIn("8.8.8.8", output)
        self.assertEqual(anon.counts["ipv4"], 0)
        self.assertEqual(anon.policy_kept["ipv4"], 2)

    def test_generated_pseudonyms_do_not_trigger_final_gate(self):
        vault, anon = self.make_engine()
        self.addCleanup(vault.db.close)
        output = anon.process(
            "user=mrossi email mrossi@example.com host srv-01.example.com"
        )
        self.assertFalse(scan_sensitive_residuals(output), output)

    def test_old_vault_schema_is_migrated_with_failed_column(self):
        db_path = self.root / "old.db"
        db = sqlite3.connect(db_path)
        db.execute(
            """CREATE TABLE fields (
                source TEXT NOT NULL, column TEXT NOT NULL, kind TEXT,
                action TEXT NOT NULL, rows_seen INTEGER NOT NULL DEFAULT 0,
                nonempty INTEGER NOT NULL DEFAULT 0,
                masked INTEGER NOT NULL DEFAULT 0,
                elided INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (source, column)
            )"""
        )
        db.commit()
        db.close()
        vault = Vault(db_path, self.key)
        self.addCleanup(vault.db.close)
        vault.register_field("s", "source_ip", "ip", "mask", 1, 1, 0, 0, 1)
        columns = {row[1] for row in vault.db.execute("PRAGMA table_info(fields)")}
        self.assertIn("failed", columns)
        self.assertEqual(vault.fields_report()[0][8], 1)


if __name__ == "__main__":
    unittest.main()
