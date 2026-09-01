"""v0.21.1 — export verticale "campo -> valore" (un singolo alert, un campo
per riga). Letto come CSV normale l'header e' la prima riga e i nomi campo
finiscono fra i valori: il kit non viene rilevato e l'intera colonna dei
valori viene elisa. Se la prima colonna identifica un kit lo si ribalta in
orizzontale; altrimenti non si tocca nulla (fail-closed).
"""
import unittest

from structured import transpose_keyvalue_csv


CORTEX_VERTICAL = "\n".join([
    "action\tDETECTED",
    "action_country\tIT",
    "action_local_ip\t10.0.0.5",
    "action_remote_ip\t8.8.8.8",
    "action_file_name\twhoami.exe",
    "action_file_sha256\t1d5491e3c468ee4b4ef6edff4bbc7d06ee83180f6f0b1576763ea2efe049493a",
    "actor_process_image_name\tcmd.exe",
    "host_name\tDC01.corp.local",
    "user_name\tbackupadm",
    "os_actor_effective_username\tadministrator",
    "agent_fqdn\tDC01.corp.local",
    "severity\thigh",
    "mitre_technique_id_and_name\tT1059",
    "story_id\t{c5d2b969-0144-64ab}",
])


class TransposeDetectionTests(unittest.TestCase):
    def test_cortex_vertical_is_transposed(self):
        out = transpose_keyvalue_csv(CORTEX_VERTICAL)
        self.assertIsNotNone(out)
        header = out.splitlines()[0].split(",")
        for field in ("action_local_ip", "host_name", "user_name",
                      "action_file_sha256", "mitre_technique_id_and_name"):
            self.assertIn(field, header)

    def test_comma_delimited_vertical(self):
        out = transpose_keyvalue_csv(CORTEX_VERTICAL.replace("\t", ","))
        self.assertIsNotNone(out)
        self.assertIn("host_name", out.splitlines()[0])

    def test_array_indices_are_folded_into_previous_field(self):
        """Un campo lista appare come valore vuoto seguito da righe '0','1',...:
        gli elementi vanno raccolti nel campo precedente, non diventare campi."""
        text = "\n".join([
            "action\tDETECTED",
            "action_local_ip\t10.0.0.5",
            "action_remote_ip\t8.8.8.8",
            "action_file_name\twhoami.exe",
            "action_file_sha256\tABC123",
            "actor_process_image_name\tcmd.exe",
            "host_name\tDC01",
            "user_name\tbackupadm",
            "os_actor_effective_username\tadmin",
            "agent_fqdn\tDC01.corp.local",
            "severity\thigh",
            "story_id\t{abc}",
            "mitre_technique_id_and_name\t",
            "0\tT1059",
            "1\tT1078",
        ])
        out = transpose_keyvalue_csv(text)
        self.assertIsNotNone(out)
        header = out.splitlines()[0].split(",")
        self.assertNotIn("0", header)
        self.assertNotIn("1", header)
        self.assertIn("mitre_technique_id_and_name", header)

    def test_end_to_end_classifies_instead_of_eliding(self):
        import tempfile
        from pathlib import Path
        import logmask
        from logmask import Anonymizer, ORDER, Options, Vault
        from app import AnonReq, _anonymize_csv
        tmp = tempfile.TemporaryDirectory()
        vault = Vault(Path(tmp.name) / "v.db", b"A" * 32)
        anon = Anonymizer(vault, set(ORDER), Options(ip_mode="internal"))
        logmask.EXTRA_KEEP_FIELDS = set()
        req = AnonReq(tenant="acme", text=CORTEX_VERTICAL, format="csv",
                      ip_mode="internal", safe_mode=True)
        result = _anonymize_csv(req, "acme", vault, anon)
        self.assertEqual(result["catalog"], "cortex")
        by = {f["column"]: f["action"] for f in result["fields"]}
        self.assertEqual(by["user_name"], "mask")
        self.assertEqual(by["host_name"], "mask")
        self.assertEqual(by["action_local_ip"], "mask")
        self.assertEqual(by["action_file_sha256"], "keep")    # IOC visibile
        blob = result["output"]
        self.assertNotIn("backupadm", blob)
        self.assertNotIn("DC01.corp.local", blob)
        self.assertIn("1d5491e3c468ee4b4ef6edff4bbc7d06ee83180f6f0b1576763ea2efe049493a", blob)
        tmp.cleanup()


class NoFalseTransposeTests(unittest.TestCase):
    """Un CSV normale a due colonne non deve mai essere ribaltato: senza un kit
    rilevato la funzione lascia stare (fail-closed)."""

    NORMAL = [
        "user,count\nmrossi,5\nbianchi,3\nverdi,7\ncosta,1\nrossi,9\nneri,4\n",
        "timestamp,message\n2023-01-01,ok\n2023-01-02,fail\n2023-01-03,ok\n2023-01-04,ok\n2023-01-05,warn\n2023-01-06,ok\n",
        "key,value\na,1\nb,2\nc,3\nd,4\ne,5\nf,6\n",
        "src_ip,dst_ip\n1.2.3.4,5.6.7.8\n9.9.9.9,8.8.8.8\n",
    ]

    def test_normal_two_column_csv_untouched(self):
        for text in self.NORMAL:
            with self.subTest(text=text.splitlines()[0]):
                self.assertIsNone(transpose_keyvalue_csv(text))

    def test_short_input_untouched(self):
        self.assertIsNone(transpose_keyvalue_csv("host_name\tDC01"))
        self.assertIsNone(transpose_keyvalue_csv(""))

    def test_three_column_csv_untouched(self):
        self.assertIsNone(transpose_keyvalue_csv("a,b,c\n1,2,3\n4,5,6\n"))


if __name__ == "__main__":
    unittest.main()
