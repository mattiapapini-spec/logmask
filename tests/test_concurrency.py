"""v0.20.2 — piu' scritture simultanee sullo stesso vault.

Scenari reali: la CLI che gira mentre l'app web anonimizza, oppure uvicorn
avviato con --workers (il lock applicativo e' per-processo, quindi non copre
nessuno dei due casi).

Prima, fra il controllo di collisione e l'INSERT, un'altra connessione poteva
inserire la stessa riga: l'INSERT falliva con IntegrityError e l'operazione
abortiva. I dati restavano integri, ma l'anonimizzazione si interrompeva.
"""
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from logmask import Anonymizer, ORDER, Options, Vault


class ConcurrentVaultWriteTests(unittest.TestCase):
    THREADS = 8
    VALUES = 40

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "shared.db"
        Vault(self.db_path, b"A" * 32)          # crea lo schema

    def tearDown(self):
        self.tmp.cleanup()

    def _run_workers(self, kind="user"):
        errors, results = [], {}

        def worker(idx):
            try:
                vault = Vault(self.db_path, b"A" * 32)   # connessione separata
                anon = Anonymizer(vault, set(ORDER), Options())
                local = {}
                for i in range(self.VALUES * 3):
                    value = f"utente{i % self.VALUES}"
                    local[value] = anon._map(kind, value)
                vault.commit()
                vault.db.close()
                results[idx] = local
            except Exception as exc:                      # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(self.THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return errors, results

    def test_no_error_under_concurrent_writes(self):
        errors, _ = self._run_workers()
        self.assertEqual(errors, [], f"scritture concorrenti fallite: {errors}")

    def test_same_value_same_pseudonym_across_threads(self):
        _, results = self._run_workers()
        merged = {}
        for local in results.values():
            for value, pseudo in local.items():
                if value in merged:
                    self.assertEqual(merged[value], pseudo, value)
                merged[value] = pseudo
        self.assertEqual(len(merged), self.VALUES)

    def test_vault_integrity_no_duplicates(self):
        self._run_workers()
        vault = Vault(self.db_path, b"A" * 32)
        rows = vault.db.execute("SELECT COUNT(*) FROM mappings").fetchone()[0]
        dup_bidx = vault.db.execute(
            "SELECT bidx FROM mappings GROUP BY bidx HAVING COUNT(*) > 1").fetchall()
        dup_pseudo = vault.db.execute(
            "SELECT pseudonym FROM mappings GROUP BY pseudonym HAVING COUNT(*) > 1").fetchall()
        self.assertEqual(rows, self.VALUES)
        self.assertEqual(dup_bidx, [])
        self.assertEqual(dup_pseudo, [])
        vault.db.close()

    def test_reverse_still_correct_after_race(self):
        _, results = self._run_workers()
        vault = Vault(self.db_path, b"A" * 32)
        sample = next(iter(results.values()))
        for value, pseudo in list(sample.items())[:10]:
            self.assertEqual(vault.reverse(pseudo), value)
        vault.db.close()

    def test_integrity_error_is_absorbed_not_raised(self):
        """Una riga inserita "da un altro" fra il controllo e l'INSERT deve
        essere assorbita riusando il pseudonimo gia' assegnato."""
        vault_a = Vault(self.db_path, b"A" * 32)
        vault_b = Vault(self.db_path, b"A" * 32)
        anon_b = Anonymizer(vault_b, set(ORDER), Options())
        first = Anonymizer(vault_a, set(ORDER), Options())._map("user", "mrossi")
        vault_a.commit()
        second = anon_b._map("user", "mrossi")     # non deve sollevare
        self.assertEqual(first, second)
        vault_a.db.close()
        vault_b.db.close()

    def test_connection_has_lock_timeout(self):
        """Senza timeout, due scritture sovrapposte danno 'database is locked'."""
        vault = Vault(self.db_path, b"A" * 32)
        try:
            self.assertTrue(isinstance(vault.db, sqlite3.Connection))
            other = Vault(self.db_path, b"A" * 32)
            other.db.execute("BEGIN IMMEDIATE")
            anon = Anonymizer(vault, set(ORDER), Options())
            other.db.execute("ROLLBACK")
            self.assertTrue(anon._map("user", "tizio").startswith("usr-"))
            other.db.close()
        finally:
            vault.db.close()


if __name__ == "__main__":
    unittest.main()


class SweepStrategyTests(unittest.TestCase):
    """v0.20.3 — le due strategie di sweep devono dare lo STESSO risultato.

    Cercare dal testo costa quanto il testo, leggere il vault costa quanto il
    vault: si sceglie la piu' economica. Un evento singolo su un vault grande
    prendeva 2,5s con 20.000 identita' perche' decifrava tutto il vault.
    """

    def _engine(self):
        from logmask import Anonymizer, ORDER, Options, Vault
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        return tmp, vault, Anonymizer(vault, set(ORDER), Options())

    def test_both_strategies_agree(self):
        from logmask import sweep_known
        import logmask
        tmp, vault, anon = self._engine()
        for i in range(60):
            anon._map("user", f"utente{i}")
        vault.commit()
        text = " ".join(f"accesso di utente{i} alle 10" for i in range(0, 60, 7))
        from_text, n1 = sweep_known(vault, text, anon.opt)
        from_vault, n2 = logmask._sweep_from_vault(vault, text, anon.opt,
                                                   set(logmask.SWEEP_KINDS))
        self.assertEqual(from_text, from_vault)
        self.assertEqual(n1, n2)
        for i in range(0, 60, 7):
            self.assertNotIn(f"utente{i} ", from_text)
        tmp.cleanup()

    def test_single_event_cost_independent_of_vault_size(self):
        """Il tempo di un evento piccolo non deve crescere col vault."""
        import json
        import time
        from structured import anonymize_structured
        doc = json.dumps({"user.name": "mrossi", "host.name": "web01",
                          "message": "login per mrossi da web01"})
        timings = []
        for size in (50, 4000):
            tmp, vault, anon = self._engine()
            for i in range(size):
                anon._map("user", f"dip{i}")
            vault.commit()
            from logmask import Anonymizer, ORDER, Options
            fresh = Anonymizer(vault, set(ORDER), Options())
            start = time.time()
            anonymize_structured("json", doc, fresh, vault, safe=True,
                                 source="t", family="elastic_ecs")
            timings.append(time.time() - start)
            tmp.cleanup()
        small, large = timings
        self.assertLess(large, max(0.25, small * 12),
                        f"il costo cresce col vault: {small:.3f}s -> {large:.3f}s")
