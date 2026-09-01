"""v0.22.2 — tre punti dove l'identita' sfuggiva.

  * AccountName: mascherato nei kit Microsoft ma NON dal catalogo generico,
    quindi restava in chiaro con Cortex/ECS o senza kit;
  * URL SharePoint/OneDrive: "/personal/sara_virgili_azienda_it/" e' l'e-mail
    con "_" al posto di "@" e ".", e non veniva toccata perche' parte di un URL;
  * cartelle profilo: "\\\\srv\\profili\\virgili_sara\\" non veniva riconosciuta
    perche' "/" e "\\" erano trattati come confini che invalidano una coppia
    nome-cognome, mentre delimitano un segmento di percorso.
"""
import tempfile
import unittest
from pathlib import Path

from logmask import (Anonymizer, Deanonymizer, ORDER, Options, Vault,
                     resolve_field)


def make_engine(**opt):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt))


class AccountNameCoverageTests(unittest.TestCase):
    FIELDS = ["AccountName", "SamAccountName", "TargetAccountName",
              "SubjectAccountName", "UserAccount", "AccountUpn"]

    def test_masked_with_every_kit(self):
        for family in ("cortex", "elastic_ecs", "microsoft_defender", None):
            for field in self.FIELDS:
                with self.subTest(kit=family, field=field):
                    decision = resolve_field(field, ["mrossi"], family)
                    self.assertEqual(decision.action, "mask", f"{family}/{field}")


class SharePointIdentityTests(unittest.TestCase):
    URLS = [
        "https://azienda-my.sharepoint.com/personal/sara_virgili_azienda_it/Documents/f.docx",
        "https://azienda-my.sharepoint.com/personal/mario_rossi_azienda_it/x?y=1",
    ]

    def test_identity_segment_masked(self):
        tmp, vault, anon = make_engine()
        for url in self.URLS:
            with self.subTest(url=url):
                out = anon.process(url)
                self.assertNotIn("sara_virgili_azienda_it", out)
                self.assertNotIn("mario_rossi_azienda_it", out)
                self.assertIn("/personal/", out)      # struttura leggibile
        tmp.cleanup()

    def test_reversible(self):
        tmp, vault, anon = make_engine()
        url = "https://x-my.sharepoint.com/personal/sara_virgili_azienda_it/f"
        masked = anon.process(url)
        self.assertEqual(Deanonymizer(vault, anon.opt).process(masked), url)
        tmp.cleanup()

    def test_same_identity_same_token(self):
        tmp, vault, anon = make_engine()
        a = anon.process("https://x-my.sharepoint.com/personal/sara_virgili_x_it/a")
        b = anon.process("https://y-my.sharepoint.com/personal/sara_virgili_x_it/b")
        self.assertEqual(a.split("/personal/")[1].split("/")[0],
                         b.split("/personal/")[1].split("/")[0])
        tmp.cleanup()


class ProfileFolderTests(unittest.TestCase):
    def test_person_name_in_path_segment_masked(self):
        """La coppia nome-cognome fra separatori di percorso e' una persona."""
        tmp, vault, anon = make_engine()
        for path in (r"\\srv\profili\rossi_mario\dati",
                     r"\\srv\home\mario_rossi\x",
                     r"/home/mario_rossi/report"):
            with self.subTest(path=path):
                out = anon.process(path)
                self.assertNotIn("mario_rossi", out)
                self.assertNotIn("rossi_mario", out)
        tmp.cleanup()

    def test_same_person_same_token_across_paths(self):
        tmp, vault, anon = make_engine()
        a = anon.process(r"\\srv\profili\rossi_mario\dati")
        b = anon.process(r"D:\Profili\rossi_mario\Desktop")
        self.assertEqual(a.split("\\")[-2], b.split("\\")[-2])
        tmp.cleanup()

    def test_emails_and_fqdn_still_handled_by_their_rules(self):
        """Il confine rilassato non deve rompere e-mail, FQDN e percorsi di
        sistema, che hanno regole piu' specifiche."""
        tmp, vault, anon = make_engine()
        self.assertNotIn("mario.rossi@azienda.it", anon.process("mario.rossi@azienda.it"))
        self.assertNotIn("web01.corp.local", anon.process("web01.corp.local"))
        self.assertIn("whoami.exe", anon.process(r"C:\Windows\System32\whoami.exe"))
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
