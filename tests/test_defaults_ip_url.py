"""v0.26.1 - il default e' "maschera tutto", ovunque.

Un default permissivo e' pericoloso proprio perche' non si nota: chi non tocca
le impostazioni non sa che sta condividendo IP e URL in chiaro. Qui si fissa
che ogni percorso - pannello principale, .docx, .pst, .pdf, API - parta da
"anonimizza tutti gli IP" e "maschera tutti gli URL", e che i profili di
lavoro non abbassino la protezione senza dirlo.

L'unica eccezione e' "Threat hunting interno", il cui scopo dichiarato e'
tenere leggibili gli indicatori tecnici per la correlazione interna:
mascherarli renderebbe il profilo inutile.
"""
import re
import unittest
from pathlib import Path

import workflows
from logmask import Options

INDEX = Path(__file__).resolve().parent.parent / "static" / "index.html"
SELECTS = ["ip-mode", "url-mode", "docx-ipmode", "docx-urlmode",
           "pst-ipmode", "pst-urlmode", "pdf-ipmode", "pdf-urlmode"]
PERMISSIVE_PROFILES = {"threat-hunting"}


class EngineDefaultsTests(unittest.TestCase):
    def test_options_default_to_all(self):
        opt = Options()
        self.assertEqual(opt.ip_mode, "all")
        self.assertEqual(opt.url_mode, "all")

    def test_invalid_values_fall_back_to_all(self):
        self.assertEqual(Options(url_mode="banana").url_mode, "all")


class ApiDefaultsTests(unittest.TestCase):
    def test_json_endpoint_defaults(self):
        from app import AnonReq
        req = AnonReq(tenant="acme", text="x")
        self.assertEqual(req.ip_mode, "all")
        self.assertEqual(req.url_mode, "all")

    def test_upload_endpoints_default_to_all(self):
        source = (Path(__file__).resolve().parent.parent / "app.py").read_text(
            encoding="utf-8")
        for field in ("ip_mode", "url_mode"):
            with self.subTest(field=field):
                found = re.findall(field + r': str = Form\("([a-z]+)"\)', source)
                self.assertTrue(found, f"{field} non usato in nessun Form")
                self.assertEqual(set(found), {"all"},
                                 f"{field} ha un default diverso da 'all': {found}")


class UiDefaultsTests(unittest.TestCase):
    def test_every_selector_preselects_all(self):
        html = INDEX.read_text(encoding="utf-8")
        for select in SELECTS:
            with self.subTest(select=select):
                block = re.search(r'id="' + select + r'"[^>]*>(.*?)</select>',
                                  html, re.S)
                self.assertIsNotNone(block, f"selettore {select} assente")
                chosen = re.search(r'value="([a-z]+)"\s+selected', block.group(1))
                self.assertIsNotNone(chosen,
                                     f"{select} non preseleziona nulla: vince la "
                                     "prima opzione, che e' la piu' permissiva")
                self.assertEqual(chosen.group(1), "all")


class WorkflowProfileTests(unittest.TestCase):
    def test_every_profile_declares_both_policies(self):
        """Un profilo che non dichiara url_mode lascia il valore precedente:
        il risultato dipende da cosa si era selezionato prima, che e' il modo
        peggiore di decidere quanto mascherare."""
        for profile in workflows.workflow_profiles():
            with self.subTest(profile=profile["id"]):
                self.assertIn("ip_mode", profile["settings"])
                self.assertIn("url_mode", profile["settings"])

    def test_protective_profiles_mask_everything(self):
        for profile in workflows.workflow_profiles():
            if profile["id"] in PERMISSIVE_PROFILES:
                continue
            with self.subTest(profile=profile["id"]):
                self.assertEqual(profile["settings"]["ip_mode"], "all")
                self.assertEqual(profile["settings"]["url_mode"], "all")

    def test_the_exception_is_documented(self):
        """Se un profilo abbassa la protezione, la sua descrizione deve dirlo."""
        hunting = next(p for p in workflows.workflow_profiles()
                       if p["id"] == "threat-hunting")
        self.assertEqual(hunting["settings"]["ip_mode"], "none")
        self.assertIn("leggibil", hunting["description"].lower())


if __name__ == "__main__":
    unittest.main()
