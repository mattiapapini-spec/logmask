"""v0.27.7 - nel repo solo codice: nessun dato reale nei file tracciati.

Le fixture devono usare valori di documentazione: IP RFC 5737 (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) o privati, domini di esempio (example.*,
contoso, fabrikam, acme, .invalid/.test/.local), il codice fiscale d'esempio
dell'Agenzia delle Entrate. Un IP pubblico, un'e-mail su un dominio vero, un
CF valido qualsiasi o un file di dati runtime tracciato fanno fallire la suite
prima che finiscano su GitHub. I valori ammessi sono elencati qui sotto, con
il motivo: aggiungerne uno e' una scelta esplicita, non un incidente.
"""
import ipaddress
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# IP pubblici ammessi: resolver DNS pubblici, usati come "IOC remoto" che deve
# restare in chiaro. Non identificano nessuno.
PUBLIC_IP_ALLOWED = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}
PUBLIC_IPV6_ALLOWED = (ipaddress.ip_network("2001:4860::/32"),)  # Google DNS
EMAIL_PLACEHOLDER_LABELS = re.compile(r"^(example|contoso|fabrikam|acme[\w-]*|azienda)$", re.I)
EMAIL_PLACEHOLDER_TLDS = {"example", "invalid", "test", "local", "localhost", "masked"}
# CF d'esempio: RSSMRA85T10A562S e' quello della documentazione ufficiale,
# RSSMRA80A01H501U il secondo CF valido dei test, ...X la sua variante errata.
CF_ALLOWED = {"RSSMRA85T10A562S", "RSSMRA80A01H501U", "RSSMRA80A01H501X"}

# file di dati runtime che non devono mai essere tracciati (specchio di .gitignore)
FORBIDDEN_PATH = re.compile(
    r"(^|/)data/|\.(db|sqlite3?|key|pem|p12|pfx|pst|ost|eml|msg|evtx|pcapng?)$|"
    r"(^|/)\.env(\.(?!example$)[^/]*)?$|_terms\.txt$|(^|/)tenant_networks\.txt$|"
    r"(^|/)keep_fields\.txt$|bootstrap-admin\.txt$|field_overrides\.json$")
FORBIDDEN_PATH_ALLOWED = re.compile(r"^examples/data/[^/]+\.example$")

ESCAPES = re.compile(r"\\[tnr]|\\\\")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]*[0-9A-Fa-f](?![0-9A-Fa-f:])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
CF = re.compile(r"(?<![A-Z0-9])[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z](?![A-Z0-9])")


def tracked_files():
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return [f for f in out.stdout.splitlines() if f]


def text_lines(files):
    for rel in files:
        if rel.startswith("persons/"):
            continue  # dizionari di nomi comuni: sono dati del motore, non fixture
        path = ROOT / rel
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if b"\0" in raw[:4096]:
            continue
        for number, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
            yield f"{rel}:{number}", ESCAPES.sub(" ", line)


def email_domain_ok(domain: str) -> bool:
    labels = domain.lower().split(".")
    return labels[-1] in EMAIL_PLACEHOLDER_TLDS or any(
        EMAIL_PLACEHOLDER_LABELS.match(label) for label in labels[:-1])


class NoRealDataTests(unittest.TestCase):
    def setUp(self):
        self.files = tracked_files()
        if self.files is None:
            self.skipTest("non e' un checkout git: niente da verificare")

    def test_no_runtime_data_files_tracked(self):
        bad = [f for f in self.files
               if FORBIDDEN_PATH.search(f) and not FORBIDDEN_PATH_ALLOWED.match(f)]
        self.assertEqual(bad, [])

    def test_no_public_ip_outside_documentation_ranges(self):
        bad = []
        for where, line in text_lines(self.files):
            for match in IPV4.finditer(line):
                try:
                    net = ipaddress.ip_network(match.group(0), strict=False)
                except ValueError:
                    continue
                if net.is_global and str(net.network_address) not in PUBLIC_IP_ALLOWED:
                    bad.append(f"{where} {match.group(0)}")
            for match in IPV6.finditer(line):
                try:
                    ip = ipaddress.ip_address(match.group(0))
                except ValueError:
                    continue
                if ip.is_global and not any(ip in n for n in PUBLIC_IPV6_ALLOWED):
                    bad.append(f"{where} {match.group(0)}")
        self.assertEqual(bad, [])

    def test_no_email_on_real_domains(self):
        bad = [f"{where} {m.group(0)}" for where, line in text_lines(self.files)
               for m in EMAIL.finditer(line) if not email_domain_ok(m.group(1))]
        self.assertEqual(bad, [])

    def test_only_example_tax_codes(self):
        bad = [f"{where} {m.group(0)}" for where, line in text_lines(self.files)
               for m in CF.finditer(line) if m.group(0) not in CF_ALLOWED]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
