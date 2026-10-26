"""v0.27.2 - completezza e sicurezza dei kit vendor.

Due garanzie di classe, non su un singolo kit:

1. NESSUN kit deve avere un catch-all che tiene in chiaro. Una regola
   '.* -> keep' e' taggata 'vendor:', quindi il Safe mode la salta: OGNI campo
   non riconosciuto (anche futuro o custom) resterebbe leggibile, annullando il
   fail-closed. E' il bug trovato in microsoft_entra. Un catch-all e' ammesso
   solo come 'text' (maschera le identita' nel valore) o 'drop'/'redact'.

2. Ogni kit deve coprire le identita' fondamentali (user, host, ip), tranne i
   vendor per cui una categoria non e' un concetto (email security, identity
   provider, audit cloud): quelli sono elencati esplicitamente qui, cosi'
   aggiungerne uno e' una scelta consapevole e non una svista.
"""
import glob
import os
import unittest

import yaml

import vendor_kits

KIT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "kits")
CATCH_ALL = {".*", "^.*$", ".*$", "^.*"}
# vendor per cui una categoria core non esiste come campo dedicato
IDENTITY_ONLY_NO_HOST = {"proofpoint", "aws_cloudtrail", "okta", "microsoft_entra"}
EMAIL_CENTRIC_NO_USER = {"proofpoint"}   # storicamente; ora proofpoint ha anche user


def load_all_kits():
    kits = {}
    for path in sorted(glob.glob(os.path.join(KIT_DIR, "*.yaml"))):
        kits[os.path.basename(path)[:-5]] = yaml.safe_load(open(path, encoding="utf-8"))
    return kits


class NoUnsafeCatchAllTests(unittest.TestCase):
    def test_no_kit_keeps_unknown_fields_in_clear(self):
        for name, kit in load_all_kits().items():
            for rule in kit.get("rules", []):
                if rule.get("pattern") in CATCH_ALL:
                    with self.subTest(kit=name):
                        self.assertNotEqual(
                            rule.get("action"), "keep",
                            f"{name}: catch-all '.*' -> keep annulla il fail-closed; "
                            "usa 'text' (maschera le identita') o rimuovi il catch-all")

    def test_catch_all_mask_uses_a_masking_kind(self):
        """Un catch-all 'mask' con un kind tipizzato (ipv4, iban...) lascerebbe
        in chiaro i valori non conformi. Se esiste, deve essere opaque/user/
        fqdn/email - kind che mascherano qualsiasi valore."""
        safe = {"opaque", "user", "email", "fqdn", "endpoint", "person"}
        for name, kit in load_all_kits().items():
            for rule in kit.get("rules", []):
                if rule.get("pattern") in CATCH_ALL and rule.get("action") == "mask":
                    with self.subTest(kit=name):
                        self.assertIn(rule.get("kind"), safe, name)


class CoreIdentityCoverageTests(unittest.TestCase):
    def _kinds(self, name):
        vendor_kits.force_reload()
        return {r.kind for r in vendor_kits.KITS[name].rules if r.kind}

    def test_every_kit_masks_users(self):
        vendor_kits.force_reload()
        for name in vendor_kits.KITS:
            if name in EMAIL_CENTRIC_NO_USER:
                continue
            with self.subTest(kit=name):
                self.assertTrue({"user", "winuser"} & self._kinds(name),
                                f"{name} non maschera alcun campo utente")

    def test_every_kit_masks_ips(self):
        vendor_kits.force_reload()
        for name in vendor_kits.KITS:
            with self.subTest(kit=name):
                self.assertTrue({"ip", "ipv4", "ipv6", "ip_strict"} & self._kinds(name),
                                f"{name} non maschera alcun IP")

    def test_host_coverage_or_documented_exception(self):
        vendor_kits.force_reload()
        for name in vendor_kits.KITS:
            if name in IDENTITY_ONLY_NO_HOST:
                continue
            with self.subTest(kit=name):
                self.assertTrue({"fqdn", "endpoint"} & self._kinds(name),
                                f"{name} non maschera host: se corretto, aggiungilo "
                                "a IDENTITY_ONLY_NO_HOST con una motivazione")


class EntraFailClosedTests(unittest.TestCase):
    def setUp(self):
        vendor_kits.force_reload()

    def test_unknown_field_is_not_kept_in_clear(self):
        from logmask import resolve_field
        d = resolve_field("some_future_custom_field", ["x"], "microsoft_entra")
        self.assertNotEqual(d.action, "keep")

    def test_device_name_is_masked_as_host(self):
        from logmask import resolve_field
        d = resolve_field("deviceDetail.displayName", ["WKS-01"], "microsoft_entra")
        self.assertEqual(d.action, "mask")
        self.assertEqual(d.kind, "fqdn")

    def test_location_city_is_masked(self):
        from logmask import resolve_field
        self.assertEqual(resolve_field("location.city", ["Milano"], "microsoft_entra").action,
                         "mask")

    def test_unknown_field_value_identities_are_masked(self):
        """Il catch-all 'text' deve mascherare un host in un campo sconosciuto."""
        import tempfile
        from pathlib import Path
        from logmask import (Anonymizer, ORDER, Options, Vault, NO_ELISION_DLP_POLICY,
                             resolve_field)
        self.assertEqual(resolve_field("weird_new_col", ["x"], "microsoft_entra").action, "text")
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        anon = Anonymizer(vault, set(ORDER), Options(ip_mode="all",
                          dlp_policy=dict(NO_ELISION_DLP_POLICY)))
        self.assertNotIn("SRV-DC01", anon.process("SRV-DC01.corp.local"))
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
