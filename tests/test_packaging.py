"""v0.27.7 — logmask installabile come libreria.

Da pacchetto installato i dati bundled (kits/, persons/) non stanno piu'
accanto al modulo ma nei package dati logmask_kits e logmask_persons. Il rischio
da coprire e' il fallimento silenzioso: senza kit il riconoscimento vendor
ricade su Generic, senza liste persone i nomi non vengono mascherati, e nessuno
se ne accorge. Quindi: o i dati si trovano, o si fallisce in modo esplicito.
"""
import os
import subprocess
import sys
import tempfile
import unittest
import venv
from pathlib import Path

import vendor_kits

REPO = Path(__file__).resolve().parent.parent


def _modern_setuptools() -> bool:
    try:
        import setuptools
    except ImportError:
        return False
    major = int(setuptools.__version__.split(".")[0])
    return major >= 77


class BundledDataDirTests(unittest.TestCase):
    def test_repo_dirs_preferred(self):
        self.assertEqual(vendor_kits.bundled_data_dir("kits"), REPO / "kits")
        self.assertEqual(vendor_kits.bundled_data_dir("persons"), REPO / "persons")

    def test_missing_data_fails_loudly(self):
        with self.assertRaises(FileNotFoundError):
            vendor_kits.bundled_data_dir("non_esiste")


@unittest.skipUnless(_modern_setuptools(), "serve setuptools>=77 per costruire il wheel offline")
class InstalledWheelTests(unittest.TestCase):
    """Costruisce il wheel, lo installa in un venv pulito e lo usa fuori dal repo."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        wheels = base / "wheels"
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
             "-q", "-w", str(wheels), str(REPO)],
            check=True, cwd=base,
        )
        env_dir = base / "venv"
        venv.EnvBuilder(with_pip=True, system_site_packages=True).create(env_dir)
        cls.python = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        wheel = next(wheels.glob("logmask-*.whl"))
        subprocess.run(
            [str(cls.python), "-m", "pip", "install", "-q", "--no-deps", str(wheel)],
            check=True, cwd=base,
        )
        cls.run_dir = base / "altrove"
        cls.run_dir.mkdir()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        for leftover in ("build", "logmask.egg-info"):
            p = REPO / leftover
            if p.exists():
                import shutil
                shutil.rmtree(p, ignore_errors=True)

    def _py(self, code: str) -> str:
        # -I: niente cwd ne' variabili d'ambiente nel path, quindi niente repo
        out = subprocess.run(
            [str(self.python), "-I", "-c", code],
            check=True, capture_output=True, text=True, cwd=self.run_dir,
        )
        return out.stdout.strip()

    def test_imports_from_site_packages_not_repo(self):
        where = self._py("import logmask; print(logmask.__file__)")
        self.assertNotIn(str(REPO), where)

    def test_all_bundled_kits_loaded(self):
        expected = len(list((REPO / "kits").glob("*.y*ml")))
        self.assertEqual(int(self._py("import vendor_kits; print(len(vendor_kits.KITS))")), expected)

    def test_person_lists_match_repo(self):
        import logmask
        repo_counts = tuple(len(x) for x in logmask.load_person_lists())
        got = self._py(
            "import logmask; print(*[len(x) for x in logmask.load_person_lists()])")
        self.assertEqual(tuple(int(x) for x in got.split()), repo_counts)
        self.assertTrue(all(repo_counts))

    def test_round_trip_in_process(self):
        code = (
            "import os, tempfile; from pathlib import Path\n"
            "from logmask import Vault, Anonymizer, Deanonymizer, Options, ORDER\n"
            "v = Vault(Path(tempfile.mkdtemp()) / 'v.db', os.urandom(32))\n"
            "o = Options(keep_scope=True, preserve_subnet=True)\n"
            "s = 'login da 192.0.2.10 per j.doe@acme-corp.com su srv01.acme-corp.com'\n"
            "m = Anonymizer(v, set(ORDER), o).process(s)\n"
            "print(m != s and 'acme-corp' not in m, Deanonymizer(v, o).process(m) == s)\n"
        )
        self.assertEqual(self._py(code), "True True")

    def test_web_service_not_in_library(self):
        out = self._py(
            "import importlib.util as u; "
            "print([m for m in ('app', 'auth') if u.find_spec(m)])")
        self.assertEqual(out, "[]")


if __name__ == "__main__":
    unittest.main()
