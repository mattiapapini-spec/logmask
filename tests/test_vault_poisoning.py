"""v0.21.6 — un vault "avvelenato" non deve corrompere il testo tecnico.

Se per un mascheramento passato il vault contiene valori che NON sono nomi
macchina - parole di prodotto ("Windows", "Management"), nomi di processo
("WmiPrvSE.exe") - lo sweep li sostituiva in OGNI job successivo del tenant:
"Windows 10" -> "host-xxxx 10", "Windows Management Instrumentation" ->
"host-xxxx host-yyyy Instrumentation". Danno persistente, retroattivo e
silenzioso, che degrada la tracciabilita' forense.

Ora si spazzano solo gli originali che hanno la FORMA di un nome macchina.
"""
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, ORDER, Options, Vault, sweep_known,
                     sweepable_host_original)

POISON = ["Windows", "Management", "Instrumentation", "WmiPrvSE.exe",
          "powershell.exe", "Microsoft"]
REAL_HOSTS = ["WKS0421", "srv-sso", "DC01", "web01.corp.local"]


def poisoned_vault():
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    anon = Anonymizer(vault, set(ORDER), Options())
    for word in POISON + REAL_HOSTS:
        anon._map("fqdn", word)
    vault.commit()
    return tmp, vault, anon


class SweepableHostOriginalTests(unittest.TestCase):
    def test_common_words_not_sweepable(self):
        for word in ("Windows", "Management", "Instrumentation", "Microsoft",
                     "behavior", "Service"):
            with self.subTest(word=word):
                self.assertFalse(sweepable_host_original(word))

    def test_process_names_not_sweepable(self):
        for name in ("WmiPrvSE.exe", "powershell.exe", "svchost.dll",
                     "script.ps1", "report.pdf"):
            with self.subTest(name=name):
                self.assertFalse(sweepable_host_original(name))

    def test_machine_names_sweepable(self):
        for host in ("WKS0421", "srv-sso", "DC01", "web01.corp.local",
                     "KWX03", "dc01.corp.local"):
            with self.subTest(host=host):
                self.assertTrue(sweepable_host_original(host))


class PoisonedVaultDoesNotCorruptTextTests(unittest.TestCase):
    def test_product_names_survive(self):
        tmp, vault, anon = poisoned_vault()
        out, _ = sweep_known(vault, "Windows Management Instrumentation su Windows 10",
                             anon.opt)
        self.assertEqual(out, "Windows Management Instrumentation su Windows 10")
        tmp.cleanup()

    def test_child_process_names_survive(self):
        tmp, vault, anon = poisoned_vault()
        out, _ = sweep_known(vault, "child process WmiPrvSE.exe spawned by powershell.exe",
                             anon.opt)
        self.assertIn("WmiPrvSE.exe", out)
        self.assertIn("powershell.exe", out)
        tmp.cleanup()

    def test_no_host_token_injected_into_technical_text(self):
        tmp, vault, anon = poisoned_vault()
        for text in ("Windows 10 build 19045",
                     "Microsoft Windows Server 2019",
                     "Windows Management Instrumentation started"):
            with self.subTest(text=text):
                out, _ = sweep_known(vault, text, anon.opt)
                self.assertNotIn("host-", out)
        tmp.cleanup()

    def test_real_hosts_still_swept(self):
        """La protezione non deve impedire la sostituzione dei nomi macchina."""
        tmp, vault, anon = poisoned_vault()
        out, hits = sweep_known(vault, "connessione da WKS0421 a web01.corp.local",
                                anon.opt)
        self.assertNotIn("WKS0421", out)
        self.assertNotIn("web01.corp.local", out)
        self.assertGreaterEqual(hits, 2)
        tmp.cleanup()

    def test_both_sweep_strategies_agree(self):
        """Le due strategie (dal testo / dal vault) devono comportarsi uguale."""
        import logmask
        tmp, vault, anon = poisoned_vault()
        text = "Windows Management su WKS0421"
        from_text, _ = sweep_known(vault, text, anon.opt)
        from_vault, _ = logmask._sweep_from_vault(vault, text, anon.opt,
                                                  set(logmask.SWEEP_KINDS))
        self.assertEqual(from_text, from_vault)
        self.assertIn("Windows Management", from_text)
        self.assertNotIn("WKS0421", from_text)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
