"""v0.23.3 - un export Elastic Discover con byte NUL non deve far cadere il server.

Il modulo csv di Python solleva "line contains NUL" e si ferma. Gli export
Discover di eventi Windows contengono spesso NUL - residui di stringhe UTF-16
dentro winlog.event_data - quindi un export perfettamente normale faceva
fallire l'intera anonimizzazione. E l'errore non arrivava nemmeno all'utente:
l'eccezione non gestita usciva come TESTO ("Internal Server Error"), il browser
non riusciva a interpretarlo e la pagina mostrava "risposta non valida dal
backend". Due difetti sovrapposti: la caduta, e l'impossibilita' di capirne il
motivo.
"""
import io
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, CsvAnonymizer, ORDER, Options, Vault,
                     apply_safe_policy, default_policy, detect_family,
                     read_samples)

HEADER = '"@timestamp","host.name","user.name","message"\r\n'
ROW_NUL = ('"2026-07-01T10:00:00Z","WKS0421","m.rossi",'
           '"Process started\x00 by CORP\\m.rossi from 10.20.30.40"\r\n')
ROW_OK = '"2026-07-01T11:00:00Z","WKS0422","g.verdi","accesso riuscito"\r\n'


def run_csv(text: str):
    tmp = tempfile.TemporaryDirectory()
    src = Path(tmp.name) / "in.csv"
    with open(src, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    opt = Options(preserve_subnet=False, keep_domain=False, keep_scope=True,
                  ip_mode="all")
    anon = Anonymizer(vault, set(ORDER), opt)
    columns, samples, dialect = read_samples(src, 200)
    policy = apply_safe_policy(default_policy(columns, samples, detect_family(columns)),
                               samples)
    cp = CsvAnonymizer(anon, policy, "upload:test", safe=True)
    out = io.StringIO()
    cp.process(src, out, dialect, columns)
    tmp.cleanup()
    return columns, out.getvalue(), cp.stats_rows


class NulBytesTests(unittest.TestCase):
    def test_export_with_nul_is_processed(self):
        columns, out, rows = run_csv(HEADER + ROW_NUL + ROW_OK)
        self.assertEqual(rows, 2)
        self.assertEqual(len(columns), 4)

    def test_nul_is_not_in_the_output(self):
        _cols, out, _rows = run_csv(HEADER + ROW_NUL)
        self.assertNotIn("\x00", out)

    def test_content_around_the_nul_survives(self):
        _cols, out, _rows = run_csv(HEADER + ROW_NUL)
        self.assertIn("Process started", out)

    def test_masking_still_works_on_the_affected_row(self):
        _cols, out, _rows = run_csv(HEADER + ROW_NUL)
        for clear in ("WKS0421", "m.rossi", "10.20.30.40"):
            with self.subTest(clear=clear):
                self.assertNotIn(clear, out)

    def test_nul_in_the_header_does_not_break_columns(self):
        columns, _out, _rows = run_csv(
            '"@timestamp","host\x00.name","user.name","message"\r\n' + ROW_OK)
        self.assertIn("host.name", columns)

    def test_file_without_nul_is_unchanged(self):
        _cols, out, rows = run_csv(HEADER + ROW_OK)
        self.assertEqual(rows, 1)
        self.assertIn("accesso riuscito", out)


class UnhandledErrorsAreJsonTests(unittest.TestCase):
    """Qualunque errore imprevisto deve restare leggibile dal browser."""

    def test_handler_returns_json_with_the_exception_type(self):
        import app as app_module
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        probe = FastAPI()
        probe.add_exception_handler(Exception, app_module.unhandled_error_json)

        @probe.get("/boom")
        def boom():
            raise ValueError("qualcosa e' andato storto")

        client = TestClient(probe, raise_server_exceptions=False)
        res = client.get("/boom")
        self.assertEqual(res.status_code, 500)
        body = res.json()                      # deve essere JSON valido
        self.assertEqual(body["error_type"], "ValueError")
        self.assertIn("docker compose logs", body["detail"])

    def test_no_internal_detail_is_leaked(self):
        import app as app_module
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        probe = FastAPI()
        probe.add_exception_handler(Exception, app_module.unhandled_error_json)

        @probe.get("/boom")
        def boom():
            raise ValueError("password segreta del cliente ACME")

        client = TestClient(probe, raise_server_exceptions=False)
        body = client.get("/boom").json()
        self.assertNotIn("ACME", str(body))
        self.assertNotIn("password segreta", str(body))


if __name__ == "__main__":
    unittest.main()
