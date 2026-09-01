"""v0.22.6/0.22.7 - l'estrazione PST deve fallire PARLANDO, e non perdere posta.

Tre difetti reali coperti qui:

1. readpst girava senza timeout: con un archivio protetto da password o
   danneggiato poteva restare in attesa all'infinito, la richiesta non tornava
   mai e il browser mostrava solo "Failed to fetch" - nessuna diagnosi.
2. Qualsiasi problema diventava un generico "file .pst non valido?": il motivo
   riportato dallo strumento (cifrato, corrotto, formato OST) andava perso.
3. Con i job paralleli libpst estrae una quantita' di posta diversa a ogni
   esecuzione e, se un figlio muore, il padre esce comunque con status 0
   (Ubuntu #1130751): messaggi persi in SILENZIO. Per un'anonimizzazione la
   perdita silenziosa e' il guasto peggiore, perche' nessuno se ne accorge.
   Si passa quindi -j 0, con ripiego se la build di readpst non la conosce.
"""
import os
import stat
import tempfile
import unittest
from pathlib import Path

import pst_anon


def fake_readpst(tmpdir: Path, script: str) -> str:
    """Installa un finto readpst eseguibile e restituisce il suo percorso."""
    path = tmpdir / "readpst"
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


class ReadpstFailureIsExplainedTests(unittest.TestCase):
    def test_tool_error_reaches_the_user(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pst_anon.READPST = fake_readpst(
                td, 'echo "readpst: Error: unable to open PST file: '
                    'encrypted or corrupt" >&2\nexit 1\n')
            with self.assertRaises(pst_anon.PstExtractionError) as ctx:
                pst_anon._run_readpst(td / "x.pst", td / "out")
        self.assertIn("unable to open PST file", str(ctx.exception))

    def test_hanging_tool_fails_within_the_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pst_anon.READPST = fake_readpst(td, "sleep 30\n")
            pst_anon.READPST_TIMEOUT = 2
            with self.assertRaises(pst_anon.PstExtractionError) as ctx:
                pst_anon._run_readpst(td / "x.pst", td / "out")
        self.assertIn("2s", str(ctx.exception))
        pst_anon.READPST_TIMEOUT = 300

    def test_failure_without_stderr_still_reports_something(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pst_anon.READPST = fake_readpst(td, "exit 3\n")
            with self.assertRaises(pst_anon.PstExtractionError) as ctx:
                pst_anon._run_readpst(td / "x.pst", td / "out")
        self.assertIn("3", str(ctx.exception))


class NoParallelJobsTests(unittest.TestCase):
    def test_jobs_are_disabled(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            log = td / "args.txt"
            pst_anon.READPST = fake_readpst(td, 'echo "$@" > ' + str(log) + '\nexit 0\n')
            pst_anon._run_readpst(td / "x.pst", td / "out")
            self.assertIn("-j 0", log.read_text())

    def test_falls_back_when_option_unknown(self):
        """Una build di readpst senza -j non deve rompere l'estrazione."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            log = td / "calls.txt"
            pst_anon.READPST = fake_readpst(td, 'echo "$@" >> ' + str(log) + '''
case "$*" in
  *-j*) echo "usage: readpst [OPTIONS] pstfile" >&2; exit 2 ;;
  *) exit 0 ;;
esac
''')
            pst_anon._run_readpst(td / "x.pst", td / "out")   # non solleva
            calls = log.read_text().strip().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn("-j 0", calls[0])
        self.assertNotIn("-j", calls[1])

    def test_real_failure_is_not_mistaken_for_a_missing_option(self):
        """Un errore vero non deve innescare il ripiego e sparire."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pst_anon.READPST = fake_readpst(
                td, 'echo "readpst: Error: unknown .pst format" >&2\nexit 1\n')
            with self.assertRaises(pst_anon.PstExtractionError) as ctx:
                pst_anon._run_readpst(td / "x.pst", td / "out")
        self.assertIn("unknown .pst format", str(ctx.exception))


class ExtractionErrorSurfacesTests(unittest.TestCase):
    def test_extract_records_propagates_the_reason(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pst_anon.READPST = fake_readpst(
                td, 'echo "readpst: Error: unknown .pst format, possibly newer '
                    'than Outlook 2003" >&2\nexit 1\n')
            with self.assertRaises(pst_anon.PstExtractionError) as ctx:
                pst_anon.extract_records(td / "x.pst")
        self.assertIn("unknown .pst format", str(ctx.exception))


def tearDownModule():
    pst_anon.READPST = "readpst"
    pst_anon.READPST_TIMEOUT = 300


if __name__ == "__main__":
    unittest.main()
