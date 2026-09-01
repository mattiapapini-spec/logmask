"""v0.10.7 — XSIAM display-name kit, URL hardening and client-term denylist."""
import json
import tempfile
import unittest
from pathlib import Path

from logmask import Anonymizer, Options, ORDER, Vault, Deanonymizer, resolve_field
from structured import anonymize_structured, detect_structured_vendor
from vendor_kits import match_rule


def make_engine(**opt_kwargs):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "vault.db", b"A" * 32)
    opt = Options(**opt_kwargs)
    return tmp, vault, Anonymizer(vault, set(ORDER), opt)


class CortexDisplayFieldTests(unittest.TestCase):
    """The XSIAM incident UI exports display names ("Host FQDN", "CGO SHA256"):
    every representative class must be classified by the cortex kit."""

    CASES = [
        # keep: IOC, MITRE, enums, numerics, timestamps
        ("File Sha256", "keep", None),
        ("CGO MD5", "keep", None),
        ("Certificate Sha1", "keep", None),
        ("Initiator signer", "keep", None),
        ("Mitre ATT&CK Tactic", "keep", None),
        ("Detection Rule ID", "keep", None),
        ("FW Rule ID", "keep", None),
        ("OS Parent PID", "keep", None),
        ("Remote Port", "keep", None),
        ("Identity Group Number Of Users", "keep", None),
        ("Is Phishing", "keep", None),
        ("Contains Featured Host", "keep", None),
        ("Last Seen", "keep", None),
        ("Vendor Product", "keep", None),
        ("Threat Name", "keep", None),
        ("Legacy Event Type", "keep", None),
        ("Host OS", "keep", None),
        ("App-ID", "keep", None),
        ("CGO name", "keep", None),
        ("Impact", "keep", None),
        # text: scrubbed free text (URLs, cmdline, paths, descriptions)
        ("Initiator CMD", "text", None),
        ("OS Parent CMD", "text", None),
        ("CGO path", "text", None),
        ("External URL", "text", None),
        ("Legacy URL", "text", None),
        ("Malicious URLs", "text", None),
        ("Extended Description", "text", None),
        ("Initial Evidence", "text", None),
        ("Misc", "text", None),
        ("Name", "text", None),
        ("Agentic AI response", "text", None),
        ("Cloud Labels", "text", None),
        ("Tags", "text", None),
        ("Indicator", "text", None),
        ("File name", "text", None),
        ("Phone Number", "text", None),
        # mask: network, hosts, identities
        ("Host IPv6", "mask", "ip"),
        ("Local IPv6", "mask", "ip"),
        ("XFF", "mask", "ip"),
        ("Cidr Range", "mask", "ip"),
        ("Host Mac Address", "mask", "mac"),
        ("Host FQDN", "mask", "fqdn"),
        ("FW Name", "mask", "endpoint"),
        ("Broker VM Name", "mask", "endpoint"),
        ("Remote Agent Hostname", "mask", "endpoint"),
        ("Assignee", "mask", "user"),
        ("Close User", "mask", "user"),
        ("Initiated By", "mask", "user"),
        ("OS Parent User Name", "mask", "user"),
        ("Email Recipient", "mask", "email"),
        ("Legacy Email Sender", "mask", "email"),
        # opaque: tenant identifiers and resources
        ("Issue Id", "mask", "opaque"),
        ("External Id", "mask", "opaque"),
        ("Broker VM ID", "mask", "opaque"),
        ("Case IDs", "mask", "opaque"),
        ("CID", "mask", "opaque"),
        ("FW Serial Number", "mask", "opaque"),
        ("FW Rule Name", "mask", "opaque"),
        ("NGFW Vsys Name", "mask", "opaque"),
        ("Cluster Name", "mask", "opaque"),
        ("Namespace", "mask", "opaque"),
        ("Container ID", "mask", "opaque"),
        ("Tenant Name", "mask", "opaque"),
        ("Source Zone Name", "mask", "opaque"),
        # v0.10.8 — residuals from the first live coverage report
        ("Playbook", "text", None),
        ("Policy Recommendation", "text", None),
        ("Policy Remediable", "keep", None),
        ("Policy Type", "keep", None),
        ("Prisma Attack Techniques", "keep", None),
        ("Source Identity User Type", "keep", None),
        ("Issue Domain", "keep", None),
        ("Source Host Ipv6 Addresses", "mask", "ip"),
        ("Target Host Ipv4 Addresses", "mask", "ip"),
        ("Target Host Ipv6 Addresses", "mask", "ip"),
        ("Source Instance", "mask", "opaque"),
    ]

    def test_display_names_resolve_through_the_cortex_kit(self):
        for display, action, kind in self.CASES:
            with self.subTest(field=display):
                decision = resolve_field(display, [], "cortex")
                self.assertEqual(decision.inferred_by, "vendor:cortex",
                                 f"{display}: inferred_by={decision.inferred_by}")
                self.assertEqual(decision.action, action, display)
                if action == "mask":
                    self.assertEqual(decision.kind, kind, display)

    def test_display_export_is_autodetected_as_cortex(self):
        payload = json.dumps({
            "Issue Id": "3324095", "Host FQDN": "srv.example.local",
            "Initiator CMD": "cmd.exe /c whoami", "CGO SHA256": "a" * 64,
            "Mitre ATT&CK Tactic": "TA0011", "Severity": "low",
        })
        detected = detect_structured_vendor("json", payload)
        self.assertEqual(detected.get("id"), "cortex")


class UrlHardeningTests(unittest.TestCase):
    """v0.10.6 spec: host always masked, opaque ids vaulted, query fail-closed."""

    URL = ("https://neteye4.example.it/neteye/kibana/kibana/app/security/alerts/"
           "redirect/ba9cc4234e7fd7c11f71ee9c4426bf0c52d43a1a5d9918248c7e284ffb102770"
           "?index=.alerts-security.alerts-default&timestamp=2026-07-06T19:16:11.440Z")

    def test_spec_reference_url(self):
        tmp, vault, anon = make_engine()
        out = anon.process("alert: " + self.URL)
        self.assertNotIn("neteye4.example.it", out)
        self.assertIn(".masked.local/neteye/kibana/", out)
        self.assertNotIn("ba9cc4234e7fd7c11f71ee9c4426bf0c52d43a1a5d9918248c7e284ffb102770", out)
        self.assertIn("/redirect/id-", out)
        self.assertIn("index=[ELIDED]", out)
        self.assertIn("timestamp=2026-07-06T19:16:11.440Z", out)
        # the alert id must be reversible
        deanon = Deanonymizer(vault, anon.opt)
        self.assertIn("ba9cc4234e7fd7c1", deanon.process(out))
        tmp.cleanup()

    def test_idempotent_on_already_masked_output(self):
        tmp, vault, anon = make_engine()
        once = anon.process(self.URL)
        twice = anon.process(once)
        self.assertEqual(once, twice)
        tmp.cleanup()

    def test_sensitive_keys_are_always_elided(self):
        tmp, vault, anon = make_engine()
        out = anon.process("https://portal.example.com/cb?ref=WB-12345-2026-01&token=abcdef012345&ts=1751830000")
        self.assertIn("ref=[ELIDED]", out)
        self.assertIn("token=[ELIDED]", out)
        self.assertIn("ts=1751830000", out)
        tmp.cleanup()

    def test_spa_fragment_keeps_route_and_vaults_the_id(self):
        tmp, vault, anon = make_engine()
        out = anon.process("https://portal.xdr.example.com/index.html#/app/workbench/alerts/WB-23990-20260706-00001?ref=cms")
        self.assertNotIn("WB-23990", out)
        self.assertIn("#/app/workbench/alerts/id-", out)
        self.assertIn("ref=[ELIDED]", out)
        tmp.cleanup()

    def test_ip_host_respects_ip_policy(self):
        tmp, vault, anon = make_engine(ip_mode="none")
        out = anon.process("https://192.168.1.10:8443/admin?index=x")
        self.assertIn("192.168.1.10:8443", out)
        self.assertIn("index=[ELIDED]", out)
        tmp.cleanup()

    def test_credentials_in_authority_are_elided(self):
        tmp, vault, anon = make_engine()
        out = anon.process("https://svc:S3cret@repo.example.com/path")
        self.assertNotIn("S3cret", out)
        self.assertIn("[ELIDED]@", out)
        tmp.cleanup()


class ClientTermsDenylistTests(unittest.TestCase):
    """Configured customer names are always elided from free text (v0.10.6 fix,
    reimplemented in v0.10.7). Names come from config, never from the sources:
    tests use synthetic names only."""

    TERMS = ("Acme Fresh Foods", "MilanoFC", "Verde Acqua")

    def test_terms_and_variants_are_elided(self):
        tmp, vault, anon = make_engine(client_terms=self.TERMS)
        text = ("Cliente ACME FRESH FOODS, segnalato da Milano FC; "
                "anche verde-acqua e MilanoFC. Ma 'milanese' resta.")
        out = anon.process(text)
        for leak in ("ACME", "Acme", "Milano", "acqua"):
            self.assertNotIn(leak, out)
        self.assertIn("milanese", out)
        self.assertGreaterEqual(anon.counts.get("client_term", 0), 4)
        tmp.cleanup()

    def test_elision_is_irreversible(self):
        tmp, vault, anon = make_engine(client_terms=self.TERMS)
        out = anon.process("Report per MilanoFC del 2026")
        deanon = Deanonymizer(vault, anon.opt)
        self.assertNotIn("MilanoFC", deanon.process(out))
        tmp.cleanup()

    def test_terms_survive_inside_structured_text_fields(self):
        tmp, vault, anon = make_engine(client_terms=self.TERMS)
        payload = json.dumps({"Issue Id": "1", "Severity": "low",
                              "Extended Description": "Escalation per Acme Fresh Foods su nodo X"})
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="cortex")
        self.assertNotIn("Acme", result.output)
        tmp.cleanup()


class XsiamDisplayReplayTests(unittest.TestCase):
    """End-to-end replay of an XSIAM display-name export (Fortigate case from
    the coverage report): zero fields outside the kit, IOC preserved."""

    INCIDENT = {
        "Issue Id": "3324095",
        "Name": "utm:ips signature",
        "Severity": "low",
        "Status": "New",
        "Vendor Product": "Fortinet - Fortigate",
        "Legacy Event Type": "Network Event",
        "Threat Name": "utm:ips signature",
        "FW Rule ID": "6705",
        "FW Rule Name": "LAN-OUT-policy-73",
        "FW Name": "fg100-fw01",
        "File Sha256": "dbba9d524a35b1136152573444d686aa07b2c53e779909d1c8be8802ad2f081b",
        "Host FQDN": "srv-dc01.corp.example.it",
        "Local IP": "10.1.2.3",
        "Remote IP": "203.0.113.44",
        "Remote Port": "443",
        "Initiator CMD": "powershell.exe -File C:\\Users\\mrossi\\run.ps1",
        "OS Parent Name": "explorer.exe",
        "OS Parent User Name": "CORP\\mrossi",
        "Assignee": "analista.uno",
        "Email Recipient": "analista.uno@soc.example.it",
        "External URL": ("https://neteye4.example.it/app/security/alerts/redirect/"
                          "ba9cc4234e7fd7c11f71ee9c4426bf0c52d43a1a5d9918248c7e284ffb102770"
                          "?index=.alerts-security.alerts-default&timestamp=2026-07-06T19:16:11.440Z"),
        "Broker VM Name": "brk-vm-01",
        "Mitre ATT&CK Tactic": "TA0011 - Command and Control",
        "Case IDs": "C-2026-0042",
        "Last Seen": "2026-07-06T19:16:11Z",
        "Host Mac Address": "00:1a:2b:3c:4d:5e",
        "XFF": "198.51.100.9",
    }

    def test_replay_has_no_fields_outside_the_kit(self):
        tmp, vault, anon = make_engine()
        result = anonymize_structured("json", json.dumps(self.INCIDENT), anon, vault,
                                      safe=True, source="xsiam-display", family="cortex")
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.exposed, 0)
        unknown = [path for path, stat in result.fields.items()
                   if stat.action == "redact"
                   or (stat.inferred_by in {"", "safe"} and not stat.safe_keep and stat.nonempty)]
        self.assertEqual(unknown, [])
        vendor = [path for path, stat in result.fields.items()
                  if str(stat.inferred_by).startswith("vendor:")]
        self.assertGreaterEqual(len(vendor), 20)

        parsed = json.loads(result.output)
        # IOC and operational metadata survive
        self.assertEqual(parsed["File Sha256"], self.INCIDENT["File Sha256"])
        self.assertEqual(parsed["Threat Name"], "utm:ips signature")
        self.assertEqual(parsed["Vendor Product"], "Fortinet - Fortigate")
        self.assertEqual(parsed["FW Rule ID"], "6705")
        self.assertEqual(parsed["Mitre ATT&CK Tactic"], "TA0011 - Command and Control")
        self.assertEqual(parsed["OS Parent Name"], "explorer.exe")
        self.assertEqual(parsed["Last Seen"], "2026-07-06T19:16:11Z")
        # identifying values are gone
        out = result.output
        for leak in ("srv-dc01", "corp.example.it", "mrossi", "analista.uno",
                     "fg100-fw01", "brk-vm-01", "neteye4", "LAN-OUT-policy-73",
                     "00:1a:2b:3c:4d:5e"):
            self.assertNotIn(leak, out)
        # command line keeps the binary, loses the user
        self.assertIn("powershell.exe", parsed["Initiator CMD"])
        # URL hardening applied inside the field value
        self.assertIn("index=[ELIDED]", parsed["External URL"])
        self.assertIn("timestamp=2026-07-06T19:16:11.440Z", parsed["External URL"])
        self.assertIn("/redirect/id-", parsed["External URL"])
        tmp.cleanup()


class XsoarPasteHardeningTests(unittest.TestCase):
    """v0.10.9 — leaks found in a live XSOAR/M365 Defender paste."""

    def test_tenant_public_networks_are_masked_in_internal_mode(self):
        tmp, vault, anon = make_engine(ip_mode="internal",
                                       tenant_networks=("93.57.78.0/24",))
        out = anon.process("lastExternalIpAddress 93.57.78.5 attacker 8.8.8.8")
        self.assertNotIn("93.57.78.5", out)
        self.assertIn("8.8.8.8", out)          # IOC remoto resta in chiaro
        tmp.cleanup()

    def test_defender_external_ip_field_is_ip_strict(self):
        rule, kit = match_rule("lastexternalipaddress", "microsoft_defender")
        self.assertEqual((kit, rule.action, rule.kind),
                         ("microsoft_defender", "mask", "ip_strict"))
        rule, kit = match_rule("device_external_ips", "cortex")
        self.assertEqual((rule.action, rule.kind), ("mask", "ip_strict"))

    def test_bare_infra_hostnames_are_masked_but_prose_is_not(self):
        tmp, vault, anon = make_engine()
        out = anon.process("hostName\tserver-sso\nnodo dc01 attivo\n"
                           "web-based detection for non-computer accounts")
        self.assertNotIn("server-sso", out)
        self.assertNotIn("dc01", out)
        self.assertIn("web-based", out)
        self.assertIn("non-computer", out)
        tmp.cleanup()

    def test_configured_host_terms_and_prefixes(self):
        tmp, vault, anon = make_engine(host_terms=("XWS*", "nodoalfa"))
        out = anon.process("login da XWS0421 e da nodoalfa ok")
        self.assertNotIn("XWS0421", out)
        self.assertNotIn("nodoalfa", out)
        tmp.cleanup()

    def test_labeled_defender_identifiers_are_vaulted(self):
        tmp, vault, anon = make_engine()
        out = anon.process("WorkspaceName\tws-snt-gr-prd-it-001\n"
                           "SystemAlertId\tfed97bd7-3ffe-291e-d675-0588836f5520\n"
                           "mdeDeviceId\td59172165d363508317484621130b3d505bf4658")
        for leak in ("ws-snt-gr-prd-it-001", "fed97bd7", "d5917216"):
            self.assertNotIn(leak, out)
        self.assertIn("WorkspaceName", out)
        tmp.cleanup()

    def test_well_known_ad_guids_stay_readable(self):
        from logmask import redact_residuals
        tmp, vault, anon = make_engine()
        kql = ("Properties has '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' or "
               "Properties has '89e95b76-444d-4c62-991a-0facbeda640c'")
        out = anon.process(kql)
        self.assertIn("89e95b76-444d-4c62-991a-0facbeda640c", out)
        self.assertIn("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", out)
        redacted, count, _ = redact_residuals(out)
        self.assertIn("89e95b76-444d-4c62-991a-0facbeda640c", redacted)
        tmp.cleanup()

    def test_kql_join_keys_are_not_residual_fqdns(self):
        from logmask import redact_residuals
        text = "on $left.SubjectLogonId == $right.TargetLogonId and $left.Computer == $right.Computer"
        out, count, _ = redact_residuals(text)
        self.assertEqual(count, 0)
        self.assertIn("$left.SubjectLogonId", out)

    def test_sweep_covers_short_labels_of_known_fqdns(self):
        from logmask import sweep_known
        tmp, vault, anon = make_engine()
        anon.process("host server-sso.corp.example.it in dominio")
        swept, count = sweep_known(vault, "colonna hostName: server-sso fine", anon.opt)
        self.assertNotIn("server-sso", swept)
        self.assertGreaterEqual(count, 1)
        tmp.cleanup()


class IocUrlModeTests(unittest.TestCase):
    """v0.10.10 (D2): URLs in indicator fields are detection content."""

    def test_ioc_kind_is_assigned_to_indicator_fields(self):
        for kit, field in (("cortex", "malicious_urls"), ("cortex", "indicator"),
                           ("microsoft_defender", "remoteurl"), ("fortinet", "url")):
            rule, _ = match_rule(field, kit)
            self.assertEqual((rule.action, rule.kind), ("text", "ioc"), (kit, field))
        rule, _ = match_rule("external_url", "cortex")
        self.assertEqual((rule.action, rule.kind), ("text", None))

    def test_ioc_url_stays_readable_with_sensitive_params_elided(self):
        tmp, vault, anon = make_engine()
        out = anon.process(
            "http://evil-panel.example.ru/gate.php?id=42&token=abc123def456",
            url_ioc=True)
        self.assertIn("evil-panel.example.ru/gate.php?id=42", out)
        self.assertIn("token=[ELIDED]", out)
        tmp.cleanup()

    def test_ioc_mode_still_masks_tenant_hosts(self):
        tmp, vault, anon = make_engine(ip_mode="internal",
                                       tenant_networks=("93.57.78.0/24",))
        out = anon.process("http://10.1.2.3/shell e http://93.57.78.5/x e "
                           "http://203.0.113.9/c2", url_ioc=True)
        self.assertNotIn("10.1.2.3", out)
        self.assertNotIn("93.57.78.5", out)
        self.assertIn("203.0.113.9/c2", out)
        tmp.cleanup()

    def test_structured_ioc_field_survives_safe_mode(self):
        tmp, vault, anon = make_engine()
        payload = json.dumps({
            "Issue Id": "9", "Severity": "high",
            "Malicious URLs": "http://bad-domain.example.com/payload.bin",
            "External URL": "https://console.internal.example.it/alerts/x?index=a",
        })
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="cortex")
        parsed = json.loads(result.output)
        self.assertIn("bad-domain.example.com/payload.bin", parsed["Malicious URLs"])
        self.assertNotIn("console.internal.example.it", parsed["External URL"])
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()


class RawXdrDataDetectionTests(unittest.TestCase):
    """v0.10.12 — small raw xdr_data exports must auto-detect + classify."""

    def test_small_raw_export_autodetects_cortex(self):
        from vendor_kits import detect_vendor_kit
        fields = ["actor_process_image_path", "agent_hostname", "dns_query_type",
                  "dns_reply_code", "numero_richieste"]
        self.assertEqual(detect_vendor_kit(fields).get("id"), "cortex")

    def test_dns_operational_enums_are_kept(self):
        for f in ("dns_reply_code", "dns_query_type", "dns_op_code", "dns_record_type"):
            rule, kit = match_rule(f, "cortex")
            self.assertEqual((kit, rule.action), ("cortex", "keep"), f)

    def test_program_files_path_is_not_mangled_as_domain_user(self):
        tmp, vault, anon = make_engine()
        out = anon.process(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        self.assertEqual(out, r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        # real DOMAIN\user is still masked
        self.assertNotIn("mrossi", anon.process(r"CORP\mrossi"))
        # user path still masks the account
        self.assertNotIn("mrossi", anon.process(r"C:\Users\mrossi\file.txt"))
        tmp.cleanup()

    def test_dns_resolutions_scrubbed_not_elided(self):
        # v0.10.13: dns_resolutions carries resolved IPs (IOC). It must be
        # classified as free text, not fail-closed to [ELIDED]. Internal /
        # tenant IPs get masked; public resolutions stay.
        rule, kit = match_rule("dns_resolutions", "cortex")
        self.assertEqual((kit, rule.action), ("cortex", "text"))
        # the _time sibling and enum fields keep falling through to their keeps
        rule_t, _ = match_rule("dns_resolutions_time", "cortex")
        self.assertEqual(rule_t.action, "keep")
        tmp, vault, anon = make_engine(ip_mode="internal")
        payload = json.dumps({"dns_query_type": "A",
                              "dns_resolutions": "10.0.0.5,8.8.8.8"})
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="cortex")
        parsed = json.loads(result.output)
        self.assertNotIn("[ELIDED]", result.output)      # no longer fail-closed
        self.assertIn("8.8.8.8", parsed["dns_resolutions"])   # public IOC kept
        self.assertNotIn("10.0.0.5", parsed["dns_resolutions"])  # internal masked
        self.assertEqual(parsed["dns_query_type"], "A")   # enum untouched
        tmp.cleanup()

    def test_auth_outcome_kept_identity_masked(self):
        # v0.10.15: authentication enums stay readable in safe mode; the
        # authenticating identity is masked as a user.
        for f in ("auth_outcome", "auth_method", "authentication_outcome",
                  "auth_result", "auth_type"):
            rule, kit = match_rule(f, "cortex")
            self.assertEqual((kit, rule.action), ("cortex", "keep"), f)
        rule, _ = match_rule("auth_identity", "cortex")
        self.assertEqual((rule.action, rule.kind), ("mask", "user"))
        tmp, vault, anon = make_engine(ip_mode="internal")
        payload = json.dumps({"auth_outcome": "SUCCESS", "auth_identity": r"CORP\\jdoe"})
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="cortex")
        parsed = json.loads(result.output)
        self.assertEqual(parsed["auth_outcome"], "SUCCESS")   # no longer [ELIDED]
        self.assertNotIn("jdoe", result.output)               # identity masked
        tmp.cleanup()


class ConfigKeepFieldsTests(unittest.TestCase):
    """v0.10.12 — operator allow-list keeps trusted custom fields in clear."""

    def setUp(self):
        import logmask
        self._saved = logmask.EXTRA_KEEP_FIELDS
        logmask.EXTRA_KEEP_FIELDS = {"numero_richieste"}

    def tearDown(self):
        import logmask
        logmask.EXTRA_KEEP_FIELDS = self._saved

    def test_allowlisted_field_survives_safe_mode(self):
        tmp, vault, anon = make_engine()
        payload = json.dumps({"agent_hostname": "PC-521", "numero_richieste": "8"})
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="cortex")
        parsed = json.loads(result.output)
        self.assertEqual(parsed["numero_richieste"], "8")
        self.assertNotIn("PC-521", result.output)

    def test_allowlist_still_runs_dlp(self):
        # a trusted field is kept, but DLP still scrubs an IBAN inside it
        tmp, vault, anon = make_engine()
        import logmask
        logmask.EXTRA_KEEP_FIELDS = {"nota_libera"}
        payload = json.dumps({"nota_libera": "IT60X0542811101000000123456"})
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="cortex")
        self.assertNotIn("IT60X0542811101000000123456", result.output)
        tmp.cleanup()


class BitdefenderKitTests(unittest.TestCase):
    """v0.10.14 — Bitdefender GravityZone dotted-schema kit."""

    FIELDS = ["alert.actions_taken", "alert.actions_to_take",
              "alert.att&ck_subtechnique", "alert.att&ck_subtechnique_id",
              "alert.att&ck_tactic", "alert.att&ck_technique",
              "alert.att&ck_technique_id", "alert.id", "alert.incident_number",
              "alert.mark", "alert.name", "alert.type", "email.receiver_address",
              "email.sender_address", "email.subject", "network.container_id",
              "network.container_name", "network.domain_name", "network.operation",
              "other.detection_class", "other.event_type", "other.sensor_name",
              "registry.key", "resource.name"]

    def test_detects_bitdefender_from_dotted_schema(self):
        from vendor_kits import detect_vendor_kit
        self.assertEqual(detect_vendor_kit(self.FIELDS)["id"], "bitdefender")

    def test_every_reported_field_is_classified(self):
        for f in self.FIELDS:
            rule, kit = match_rule(f, "bitdefender")
            self.assertIsNotNone(rule, f)
            self.assertEqual(kit, "bitdefender", f)

    def test_key_field_actions(self):
        expect = {
            "alert.att&ck_tactic": ("keep", None),
            "alert.id": ("mask", "opaque"),
            "email.sender_address": ("mask", "email"),
            "network.domain_name": ("mask", "fqdn"),
            "network.container_name": ("mask", "opaque"),
            "other.sensor_name": ("mask", "endpoint"),
            "registry.key": ("text", None),
            "resource.name": ("text", None),
            "alert.incident_number": ("keep", None),
        }
        for f, (act, kind) in expect.items():
            rule, _ = match_rule(f, "bitdefender")
            self.assertEqual((rule.action, rule.kind), (act, kind), f)

    def test_registry_key_keeps_hive_and_vaults_sid(self):
        tmp, vault, anon = make_engine()
        p = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        self.assertEqual(anon.process(p), p)          # hive path intact
        sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
        out = anon.process(r"HKU\%s\SOFTWARE" % sid)
        self.assertTrue(out.startswith(r"HKU\S-1-5-21-"))   # hive kept
        self.assertTrue(out.endswith(r"-1001\SOFTWARE"))    # RID + subkey kept
        self.assertNotIn("1111111111", out)                 # domain SID vaulted
        self.assertNotIn("mrossi", anon.process(r"CORP\mrossi"))  # real DOMAIN\user masked
        tmp.cleanup()

    def test_end_to_end_structured_safe_mode(self):
        tmp, vault, anon = make_engine(ip_mode="internal")
        payload = json.dumps({
            "alert.att&ck_tactic": "Execution",
            "alert.id": "AAA-BBB-CCC",
            "email.sender_address": "attacker@evil.example",
            "other.sensor_name": "SRV-EDR-01",
            "network.domain_name": "malicious.example.com",
            "resource.name": "notepad.exe",
        })
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="bitdefender")
        self.assertNotIn("[ELIDED]", result.output)          # nothing fail-closed
        parsed = json.loads(result.output)
        self.assertEqual(parsed["alert.att&ck_tactic"], "Execution")   # MITRE kept
        self.assertNotIn("SRV-EDR-01", result.output)        # sensor masked
        self.assertNotIn("attacker@evil.example", result.output)  # email masked
        tmp.cleanup()


class SaasAuditKitTests(unittest.TestCase):
    """v0.10.18 — Cortex XDM saas_audit_logs schema is detected + classified."""

    FIELDS = ["_time", "event_timestamp", "identity_name", "identity_orig",
              "identity_type", "identity_sub_type", "caller_ip", "operation_name",
              "operation_name_orig", "operation_status",
              "operation_status_reason_provided", "service_type", "service_sub_type",
              "referenced_resource", "referenced_resource_name",
              "referenced_resources_count", "resource_type", "resource_type_orig",
              "user_agent", "correlation_id", "event_id", "product", "vendor",
              "ingestion_time"]

    def test_saas_audit_schema_autodetects_cortex(self):
        from vendor_kits import detect_vendor_kit
        self.assertEqual(detect_vendor_kit(self.FIELDS)["id"], "cortex")

    def test_no_operational_field_is_fail_closed(self):
        from logmask import default_policy, apply_safe_policy
        samples = {f: ["x"] for f in self.FIELDS}
        pol = apply_safe_policy(default_policy(self.FIELDS, samples, "cortex"), samples)
        elided = [c for c in self.FIELDS
                  if pol["columns"].get(c, {}).get("action") == "redact"]
        self.assertEqual(elided, [])
        expect = {
            "identity_name": ("mask", "user"), "identity_orig": ("mask", "user"),
            "identity_type": ("keep", None), "operation_name": ("keep", None),
            "operation_name_orig": ("keep", None), "service_type": ("keep", None),
            "resource_type": ("keep", None), "resource_type_orig": ("keep", None),
            "referenced_resource": ("mask", "opaque"),
            "referenced_resource_name": ("text", None),
        }
        for f, (a, k) in expect.items():
            r, _ = match_rule(f, "cortex")
            self.assertEqual((r.action, r.kind), (a, k), f)

    def test_end_to_end_row_keeps_enums_masks_identity(self):
        tmp, vault, anon = make_engine(ip_mode="internal")
        payload = json.dumps({"identity_name": "admin@contoso.example",
                              "operation_name": "UserLoggedIn",
                              "service_type": "AzureActiveDirectory",
                              "resource_type": "Application"})
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="cortex")
        self.assertNotIn("[ELIDED]", result.output)
        parsed = json.loads(result.output)
        self.assertEqual(parsed["operation_name"], "UserLoggedIn")       # enum kept
        self.assertEqual(parsed["service_type"], "AzureActiveDirectory")  # enum kept
        self.assertNotIn("admin@contoso.example", result.output)          # identity masked
        tmp.cleanup()


class SaasAuditFullSchemaTests(unittest.TestCase):
    """v0.10.19 — the full XDM saas_audit_logs export (IP enrichment, identity
    backtrace, normalized identity, tenant domain) leaves nothing fail-closed."""

    FIELDS = ["_time", "_reception_time", "backtrace_identities", "caller_ip",
              "caller_ip_asn", "caller_ip_asn_org", "caller_ip_enrichment",
              "caller_ip_geolocation", "correlation_id", "domain_name", "event_id",
              "event_timestamp", "identity_invoked_by_name",
              "identity_invoked_by_sub_type", "identity_invoked_by_type",
              "identity_invoked_by_uuid", "identity_name", "identity_normalized",
              "identity_orig", "identity_uuid", "ingestion_time", "operation_name_orig",
              "operation_status_reason_provided", "product", "project", "raw_log",
              "referenced_resource", "referenced_resource_name",
              "referenced_resources_count", "resource_type", "resource_type_orig",
              "story_publish_timestamp", "user_agent", "user_agent_data", "vendor",
              "event_type", "operation_name", "identity_type", "identity_sub_type",
              "operation_status", "service_type", "service_sub_type"]

    OUT_FIELDS = {
        "backtrace_identities": ("text", None), "caller_ip_asn": ("keep", None),
        "caller_ip_asn_org": ("text", None), "caller_ip_enrichment": ("text", None),
        "caller_ip_geolocation": ("text", None), "domain_name": ("mask", "fqdn"),
        "identity_normalized": ("mask", "user"), "user_agent_data": ("keep", None),
    }

    def test_formerly_out_fields_are_classified(self):
        for f, (a, k) in self.OUT_FIELDS.items():
            r, kit = match_rule(f, "cortex")
            self.assertEqual((kit, r.action, r.kind), ("cortex", a, k), f)

    def test_full_schema_has_zero_fail_closed(self):
        from vendor_kits import detect_vendor_kit
        from logmask import default_policy, apply_safe_policy
        self.assertEqual(detect_vendor_kit(self.FIELDS)["id"], "cortex")
        samples = {f: ["x"] for f in self.FIELDS}
        pol = apply_safe_policy(default_policy(self.FIELDS, samples, "cortex"), samples)
        elided = [c for c in self.FIELDS
                  if pol["columns"].get(c, {}).get("action") == "redact"]
        self.assertEqual(elided, [])
        # raw_log must NOT be kept in clear (would leak the whole event)
        r, _ = match_rule("raw_log", "cortex")
        self.assertEqual(r.action, "text")

    def test_end_to_end_masks_domain_identity_and_scrubs_rawlog(self):
        tmp, vault, anon = make_engine(ip_mode="internal",
                                       tenant_networks=("93.57.78.0/24",))
        row = {
            "identity_normalized": "mario.rossi@contoso.example",
            "backtrace_identities": "admin@contoso.example; svc@contoso.example",
            "domain_name": "contoso.example",
            "caller_ip": "20.190.160.25", "caller_ip_asn": "8075",
            "caller_ip_asn_org": "MICROSOFT-CORP-AS", "caller_ip_geolocation": "IE, Dublin",
            "caller_ip_enrichment": "host=nat-93.57.78.5",
            "user_agent_data": "Chrome 126 on Windows 10",
            "raw_log": "user=mario.rossi@contoso.example src=93.57.78.5 host=SRV-DC01",
        }
        result = anonymize_structured("json", json.dumps(row), anon, vault,
                                      safe=True, source="test", family="cortex")
        self.assertNotIn("[ELIDED]", result.output)          # no client term in this row
        p = json.loads(result.output)
        self.assertTrue(p["domain_name"].endswith(".masked.local"))    # tenant domain masked
        self.assertTrue(p["identity_normalized"].endswith(".masked"))  # canonical identity masked
        self.assertNotIn("admin@contoso", result.output)               # backtrace scrubbed
        self.assertEqual(p["caller_ip"], "20.190.160.25")              # public caller kept
        self.assertEqual(p["caller_ip_asn"], "8075")                   # ASN kept
        self.assertEqual(p["caller_ip_geolocation"], "IE, Dublin")     # geo kept
        self.assertEqual(p["user_agent_data"], "Chrome 126 on Windows 10")
        self.assertNotIn("93.57.78.5", result.output)                  # tenant NAT ip masked
        self.assertNotIn("mario.rossi@contoso", p["raw_log"])          # raw_log scrubbed
        self.assertNotIn("SRV-DC01", p["raw_log"])
        tmp.cleanup()


class XdrFileProcessFamilyTests(unittest.TestCase):
    """v0.10.20 — xdr_data file/process/transfer fields don't fail closed."""

    KEEP = ["action_file_size", "action_file_size_bytes", "action_file_length",
            "actor_process_image_name", "action_process_image_name",
            "os_actor_process_image_name", "causality_actor_process_image_name",
            "action_total_upload", "action_total_download", "action_network_bytes"]
    TEXT = ["action_file_name", "action_file_previous_file_name"]

    def test_size_and_process_names_are_kept(self):
        for f in self.KEEP:
            r, kit = match_rule(f, "cortex")
            self.assertEqual((kit, r.action), ("cortex", "keep"), f)

    def test_file_names_are_visible_but_scrubbed(self):
        for f in self.TEXT:
            r, kit = match_rule(f, "cortex")
            self.assertEqual((kit, r.action), ("cortex", "text"), f)

    def test_container_image_name_and_paths_unchanged(self):
        # regression guard: the process rule must NOT swallow container image_name,
        # and *_image_path must stay text (path, scrub the user)
        r, _ = match_rule("image_name", "cortex")
        self.assertEqual((r.action, r.kind), ("mask", "opaque"))
        for f in ("actor_process_image_path", "action_process_image_path"):
            r, _ = match_rule(f, "cortex")
            self.assertEqual(r.action, "text", f)

    def test_end_to_end_file_name_visible_size_kept(self):
        tmp, vault, anon = make_engine(client_terms=("ClienteAlfa",))
        payload = json.dumps({"action_file_name": "invoice_ClienteAlfa.xlsx",
                              "actor_process_image_name": "powershell.exe",
                              "action_file_size": "4096"})
        result = anonymize_structured("json", payload, anon, vault,
                                      safe=True, source="test", family="cortex")
        p = json.loads(result.output)
        self.assertEqual(p["action_file_size"], "4096")                   # numeric kept
        self.assertEqual(p["actor_process_image_name"], "powershell.exe")  # IOC kept
        self.assertIn(".xlsx", p["action_file_name"])                     # file name visible
        self.assertNotIn("ClienteAlfa", result.output)                       # client term scrubbed
        tmp.cleanup()


class ClientTermModeTests(unittest.TestCase):
    """v0.10.21 — configured client names become a generic, tenant-keyed,
    irreversible token by default (readable, clients stay distinct); the
    'elide' and 'label' modes remain available."""

    TERMS = ("ClienteBeta", "AcmeCalcio", "Ente Esempio")

    def test_default_pseudonymizes_distinct_and_stable(self):
        import re
        tmp, vault, anon = make_engine(client_terms=self.TERMS)
        out = anon.process("ClienteBeta e AcmeCalcio; ancora ClienteBeta; Ente Esempio")
        self.assertNotIn("ClienteBeta", out)
        self.assertNotIn("AcmeCalcio", out)
        toks = re.findall(r"CLIENT-[a-z2-7]{6}", out)
        self.assertEqual(len(set(toks)), 3)          # 3 distinct clients
        self.assertEqual(toks[0], toks[2])           # same client -> same token
        deanon = Deanonymizer(vault, anon.opt)       # irreversible: inert on reverse
        self.assertEqual(deanon.process(out), out)
        tmp.cleanup()

    def test_formatting_variants_map_to_same_token(self):
        tmp, vault, anon = make_engine(client_terms=self.TERMS)
        self.assertEqual(anon.process("AcmeCalcio"), anon.process("Acme Calcio"))
        self.assertEqual(anon.process("AcmeCalcio"), anon.process("acme-calcio"))
        tmp.cleanup()

    def test_token_is_tenant_specific(self):
        import tempfile
        from pathlib import Path
        from logmask import Vault as _V, Anonymizer as _A, Options as _O, ORDER as _ORD

        def tok(kb):
            tmp = tempfile.TemporaryDirectory()
            v = _V(Path(tmp.name) / "v.db", bytes([kb]) * 32)
            out = _A(v, set(_ORD), _O(client_terms=self.TERMS)).process("ClienteBeta")
            tmp.cleanup()
            return out
        self.assertNotEqual(tok(1), tok(2))

    def test_elide_mode_still_available(self):
        tmp, vault, anon = make_engine(client_terms=self.TERMS, client_term_mode="elide")
        self.assertIn("[ELIDED]", anon.process("per ClienteBeta"))
        tmp.cleanup()

    def test_label_mode_fixed_label(self):
        tmp, vault, anon = make_engine(client_terms=self.TERMS,
                                       client_term_mode="label",
                                       client_term_label="[CLIENTE]")
        self.assertEqual(anon.process("ClienteBeta e AcmeCalcio").count("[CLIENTE]"), 2)
        tmp.cleanup()

    def test_invalid_mode_falls_back_to_pseudonymize(self):
        tmp, vault, anon = make_engine(client_terms=self.TERMS, client_term_mode="bogus")
        self.assertIn("CLIENT-", anon.process("ClienteBeta"))
        tmp.cleanup()


class BitdefenderConsoleKitTests(unittest.TestCase):
    """v0.10.22 — GravityZone console (display-name) export is detected and
    fully classified; the dotted-schema kit only covered the API export."""

    COLS = ["Category", "Details", "Command-line", "Action taken", "Eventi",
            "Threat type", "Endpoint name", "Tag", "Company", "IP", "Endpoint type",
            "Detected on", "User", "Detecting module", "Detecting technology",
            "Threat name", "Fileless attack", "SHA256", "Container host"]

    def test_console_export_autodetects_bitdefender(self):
        from vendor_kits import detect_vendor_kit
        self.assertEqual(detect_vendor_kit(self.COLS)["id"], "bitdefender")

    def test_no_populated_field_is_fail_closed(self):
        from logmask import default_policy, apply_safe_policy
        samples = {c: ["x"] for c in self.COLS}
        pol = apply_safe_policy(default_policy(self.COLS, samples, "bitdefender"), samples)
        elided = [c for c in self.COLS
                  if pol["columns"].get(c, {}).get("action") == "redact"]
        self.assertEqual(elided, [])

    def test_key_display_fields(self):
        expect = {"SHA256": ("keep", None), "Threat name": ("keep", None),
                  "Action taken": ("keep", None), "Endpoint name": ("mask", "endpoint"),
                  "Container host": ("mask", "endpoint"), "Company": ("mask", "opaque"),
                  "Command-line": ("text", None), "Tag": ("text", None),
                  "Fileless attack": ("keep", None), "Detecting technology": ("keep", None)}
        for f, (a, k) in expect.items():
            fd = resolve_field(f, ["x"], "bitdefender")
            self.assertEqual((fd.action, fd.kind), (a, k), f)

    def test_dotted_schema_still_detected(self):
        # regression guard: adding console fingerprints must not break the
        # original dotted-schema detection.
        from vendor_kits import detect_vendor_kit
        dotted = ["alert.att&ck_technique_id", "other.sensor_name",
                  "network.container_id", "alert.incident_number", "alert.mark"]
        self.assertEqual(detect_vendor_kit(dotted)["id"], "bitdefender")

    def test_end_to_end_ioc_kept_identity_masked(self):
        tmp, vault, anon = make_engine(ip_mode="internal")
        row = {"SHA256": "dbba9d524a35b1136152573444d686aa07b2c53e779909d1c8be8802ad2f081b",
               "Threat name": "Trojan.GenericKD", "Endpoint name": "WKS-FIN-07",
               "Company": "Acme Manufacturing Srl",
               "Command-line": "powershell.exe -u CORP\\jdoe",
               "User": "CORP\\jdoe", "Action taken": "Blocked"}
        result = anonymize_structured("json", json.dumps(row), anon, vault,
                                      safe=True, source="test", family="bitdefender")
        self.assertNotIn("[ELIDED]", result.output)
        p = json.loads(result.output)
        self.assertEqual(p["SHA256"], row["SHA256"])            # IOC kept
        self.assertEqual(p["Threat name"], "Trojan.GenericKD")   # IOC kept
        self.assertEqual(p["Action taken"], "Blocked")           # enum kept
        self.assertIn("powershell.exe", p["Command-line"])       # binary kept
        self.assertNotIn("WKS-FIN-07", result.output)            # endpoint masked
        self.assertNotIn("Acme Manufacturing", result.output)    # company masked
        self.assertNotIn("jdoe", result.output)                  # user masked
        tmp.cleanup()


class HostTermSweepTests(unittest.TestCase):
    """v0.10.23 — operator host naming conventions (and client names) also
    apply to fields KEPT IN CLEAR, not only free-text / text columns."""

    def test_host_term_masks_bare_host_in_kept_field(self):
        tmp, vault, anon = make_engine(host_terms=("XWS*", "srv-*", "KWX*"))
        result = anonymize_structured("json", json.dumps({"PortHost": "KWX01"}),
                                      anon, vault, safe=False, source="t", family=None)
        p = json.loads(result.output)
        self.assertTrue(p["PortHost"].startswith("host-"))
        deanon = Deanonymizer(vault, anon.opt)               # reversible
        self.assertEqual(deanon.process(p["PortHost"]), "KWX01")
        tmp.cleanup()

    def test_client_name_scrubbed_in_kept_field(self):
        tmp, vault, anon = make_engine(client_terms=("ClienteBeta",))
        result = anonymize_structured("json", json.dumps({"Note": "attivita ClienteBeta"}),
                                      anon, vault, safe=False, source="t", family=None)
        p = json.loads(result.output)
        self.assertNotIn("ClienteBeta", p["Note"])
        self.assertIn("CLIENT-", p["Note"])
        tmp.cleanup()

    def test_host_term_in_vendor_keep_column(self):
        tmp, vault, anon = make_engine(host_terms=("KWX*",))
        result = anonymize_structured("json", json.dumps({"operation_name": "exec on KWX01"}),
                                      anon, vault, safe=True, source="t", family="cortex")
        self.assertNotIn("KWX01", json.loads(result.output)["operation_name"])
        tmp.cleanup()

    def test_plain_enum_kept_untouched(self):
        tmp, vault, anon = make_engine(host_terms=("KWX*",))
        result = anonymize_structured("json", json.dumps({"status": "Blocked"}),
                                      anon, vault, safe=True, source="t", family="cortex")
        self.assertEqual(json.loads(result.output)["status"], "Blocked")
        tmp.cleanup()

    def test_free_text_heuristic_still_works(self):
        tmp, vault, anon = make_engine()                     # fuzzy heuristic, free text only
        out = anon.process("nodo dc01 e server-sso attivi")
        self.assertNotIn("dc01", out)
        self.assertNotIn("server-sso", out)
        tmp.cleanup()


class HostTermGlobTests(unittest.TestCase):
    """v0.10.24 — host_terms support '*' anywhere (prefix / suffix / middle /
    domain), not only a trailing prefix."""

    TERMS = ("WKS*", "KDA*QNS", "*QNS", "*.WORKGROUP", "*ZCORP.DOM", "XL-*")

    def _mask(self, text):
        tmp, vault, anon = make_engine(host_terms=self.TERMS)
        out = anon.process(text)
        tmp.cleanup()
        return out

    def test_trailing_prefix(self):
        self.assertNotIn("WKS04417", self._mask("nodo WKS04417 giu"))

    def test_middle_wildcard(self):
        self.assertNotIn("KDA0001QNS", self._mask("host KDA0001QNS"))

    def test_leading_suffix_wildcard(self):
        out = self._mask("SRVQNS e BACKUPQNS")
        self.assertNotIn("SRVQNS", out)
        self.assertNotIn("BACKUPQNS", out)

    def test_domain_suffix(self):
        self.assertNotIn("WORKGROUP", self._mask("PC01.WORKGROUP"))
        self.assertNotIn("ZCORP", self._mask("srv07.ZCORP.DOM"))

    def test_lone_star_is_ignored(self):
        tmp, vault, anon = make_engine(host_terms=("*", "WKS*"))
        out = anon.process("parola normale e WKS01")
        self.assertIn("parola", out)
        self.assertIn("normale", out)
        self.assertNotIn("WKS01", out)
        tmp.cleanup()

    def test_reversible(self):
        tmp, vault, anon = make_engine(host_terms=("WKS*",))
        masked = anon.process("WKS04417")
        deanon = Deanonymizer(vault, anon.opt)
        self.assertEqual(deanon.process(masked), "WKS04417")
        tmp.cleanup()


class UpnMaskingTests(unittest.TestCase):
    """v0.10.25 — UPN / e-mail with a single-label domain (user@COMPANY, no
    public TLD) is fully pseudonymized instead of leaking the local part or
    being elided in Safe mode."""

    def test_free_text_upn_client_domain(self):
        tmp, vault, anon = make_engine(client_terms=("ClienteGamma",))
        out = anon.process("login user125@ClienteGamma ok")
        self.assertNotIn("user125", out)          # local masked
        self.assertNotIn("ClienteGamma", out)          # client masked
        self.assertIn("@CLIENT-", out)            # client shown as token
        tmp.cleanup()

    def test_free_text_upn_non_client_domain(self):
        tmp, vault, anon = make_engine()
        out = anon.process("admin@INTERNAL")
        self.assertNotIn("admin@INTERNAL", out)
        self.assertTrue(out.startswith("usr-"))
        tmp.cleanup()

    def test_tld_email_unchanged(self):
        tmp, vault, anon = make_engine()
        out = anon.process("jdoe@corp.example.com")
        self.assertTrue(out.endswith(".masked"))
        self.assertIn("usr-", out)
        tmp.cleanup()

    def test_upn_not_elided_in_any_column(self):
        for fam in ("cortex", "bitdefender", None):
            for col in ("email", "User", "Details", "identity_name", "userPrincipalName"):
                tmp, vault, anon = make_engine(client_terms=("ClienteGamma",))
                r = anonymize_structured("json", json.dumps({col: "user125@ClienteGamma"}),
                                         anon, vault, safe=True, source="t", family=fam)
                out = json.loads(r.output)[col]
                self.assertNotIn("[ELIDED]", out, (fam, col))
                self.assertNotIn("user125", out, (fam, col))    # local never leaks
                self.assertNotIn("ClienteGamma", out, (fam, col))
                tmp.cleanup()

    def test_enum_untouched(self):
        tmp, vault, anon = make_engine()
        r = anonymize_structured("json", json.dumps({"status": "Blocked"}),
                                 anon, vault, safe=True, source="t", family="cortex")
        self.assertEqual(json.loads(r.output)["status"], "Blocked")
        tmp.cleanup()

    def test_reversible_local_client_stays(self):
        tmp, vault, anon = make_engine(client_terms=("ClienteGamma",))
        masked = anon.process("user125@ClienteGamma")
        deanon = Deanonymizer(vault, anon.opt)
        rev = deanon.process(masked)
        self.assertIn("user125", rev)        # local part reverses
        self.assertNotIn("ClienteGamma", rev)     # client token stays irreversible
        tmp.cleanup()


class MicrosoftEntraKitTests(unittest.TestCase):
    """v0.10.26 — Microsoft Entra ID (Azure AD) sign-in / audit logs, incl.
    Italian display-name exports, are detected and fully classified."""

    SIGNIN = ["Data (UTC)", "Utente", "Nome utente", "Nome del tenant principale",
              "Indirizzo IP", "Stato", "Metodo di autenticazione", "Applicazione",
              "Località", "Conforme", "Browser", "Accesso condizionale",
              "Numero del sistema autonomo", "Requisito per l'autenticazione",
              "ID sessione", "Agente utente"]
    AUDIT = ["Data (UTC)", "ActorDisplayName", "ActorUserPrincipalName", "IPAddress",
             "Target1Type", "Target1DisplayName", "Target1UserPrincipalName",
             "Target1ModifiedProperty1NewValue", "AdditionalDetail6Key",
             "AdditionalDetail6Value"]

    def test_signin_and_audit_autodetect_entra(self):
        from vendor_kits import detect_vendor_kit
        self.assertEqual(detect_vendor_kit(self.SIGNIN)["id"], "microsoft_entra")
        self.assertEqual(detect_vendor_kit(self.AUDIT)["id"], "microsoft_entra")

    def test_no_field_is_fail_closed(self):
        from logmask import default_policy, apply_safe_policy
        for fields in (self.SIGNIN, self.AUDIT):
            samples = {c: ["x"] for c in fields}
            pol = apply_safe_policy(default_policy(fields, samples, "microsoft_entra"), samples)
            elided = [c for c in fields
                      if pol["columns"].get(c, {}).get("action") == "redact"]
            self.assertEqual(elided, [])

    def test_identities_masked_enums_kept(self):
        from logmask import norm_col
        expect = {
            "Utente": ("mask", "user"), "Nome utente": ("mask", "email"),
            "Nome del tenant principale": ("mask", "opaque"),
            "ActorDisplayName": ("mask", "user"),
            "ActorUserPrincipalName": ("mask", "email"), "IPAddress": ("mask", "ip"),
            "Target1ModifiedProperty1NewValue": ("text", None),
            "Data (UTC)": ("keep", None), "Stato": ("keep", None),
            "Metodo di autenticazione": ("keep", None), "Browser": ("keep", None),
        }
        for f, (a, k) in expect.items():
            r, kit = match_rule(norm_col(f), "microsoft_entra")
            self.assertEqual((kit, r.action, r.kind), ("microsoft_entra", a, k), f)

    def test_end_to_end_signin_no_leak(self):
        tmp, vault, anon = make_engine(ip_mode="internal", client_terms=("Contoso",))
        row = {"Utente": "Mario Rossi",
               "Nome utente": "mario.rossi@contoso.onmicrosoft.com",
               "Nome del tenant principale": "Contoso", "Stato": "Success",
               "Metodo di autenticazione": "Password"}
        result = anonymize_structured("json", json.dumps(row), anon, vault,
                                      safe=True, source="test", family="microsoft_entra")
        self.assertNotIn("[ELIDED]", result.output)
        p = json.loads(result.output)
        self.assertEqual(p["Stato"], "Success")                       # enum kept
        self.assertEqual(p["Metodo di autenticazione"], "Password")    # enum kept
        self.assertNotIn("Mario Rossi", result.output)                 # user masked
        self.assertNotIn("mario.rossi@contoso", result.output)         # UPN masked
        self.assertTrue(p["Nome del tenant principale"].startswith("id-"))  # tenant masked
        tmp.cleanup()


class ElasticEcsExtensionTests(unittest.TestCase):
    """v0.10.27 — ECS extension fields (nested AWS Security Hub json.*, O365
    o365audit.*, enrichment/organization/watcher/cloud) don't fail closed;
    client-identifying families are masked, the rest kept."""

    FIELDS = ["@timestamp", "ecs.version", "source.ip", "host.name", "user.name",
              "enrichment.customer_prefix", "enrichment.organization_name",
              "organization.name", "organization.code", "json.CompanyName",
              "group.name", "device.name", "cloud.provider", "cloud.instance.name",
              "cloud.resource_arn", "file.name", "file.owner", "email.subject",
              "email.message_id", "destination.user.job_position", "user.key",
              "o365audit.EmailInfo.subject", "o365audit.LabelName", "o365audit.AuthType",
              "source.geo.city_name", "threat.tactic.name", "event.start", "event.end",
              "json.CreatedAt", "source.as.organization.name"]

    def test_no_ecs_extension_field_is_fail_closed(self):
        from vendor_kits import detect_vendor_kit
        from logmask import default_policy, apply_safe_policy
        self.assertEqual(detect_vendor_kit(self.FIELDS)["id"], "elastic_ecs")
        samples = {c: ["x"] for c in self.FIELDS}
        pol = apply_safe_policy(default_policy(self.FIELDS, samples, "elastic_ecs"), samples)
        elided = [c for c in self.FIELDS
                  if pol["columns"].get(c, {}).get("action") == "redact"]
        self.assertEqual(elided, [])

    def test_client_identity_masked_isp_kept(self):
        from logmask import norm_col
        for f in ["enrichment.customer_prefix", "enrichment.organization_name",
                  "organization.name", "organization.code", "json.CompanyName",
                  "group.name", "device.name", "user.key", "o365audit.OrganizationName"]:
            r, kit = match_rule(norm_col(f), "elastic_ecs")
            self.assertEqual(kit, "elastic_ecs", f)
            self.assertIn(r.action, ("mask", "text"), f)   # never kept in clear
        r, _ = match_rule(norm_col("source.as.organization.name"), "elastic_ecs")
        self.assertEqual(r.action, "keep")                 # ISP org, not the client

    def test_end_to_end_ecs_no_leak(self):
        tmp, vault, anon = make_engine(client_terms=("Acme",))
        row = {"cloud.provider": "aws", "event.start": "2026-07-16T14:00:00Z",
               "enrichment.customer_prefix": "acmeprefix",
               "enrichment.organization_name": "Acme Corp",
               "organization.name": "Acme Corp", "json.CompanyName": "AcmeInc",
               "email.subject": "Q3 salaries Acme", "source.geo.city_name": "Milan",
               "o365audit.AuthType": "OAuth"}
        result = anonymize_structured("json", json.dumps(row), anon, vault,
                                      safe=True, source="t", family="elastic_ecs")
        self.assertNotIn("[ELIDED]", result.output)
        p = json.loads(result.output)
        self.assertEqual(p["cloud.provider"], "aws")              # enum kept
        self.assertEqual(p["source.geo.city_name"], "Milan")      # geo kept
        self.assertEqual(p["o365audit.AuthType"], "OAuth")        # enum kept
        self.assertNotIn("Acme Corp", result.output)              # org masked
        self.assertNotIn("acmeprefix", result.output)             # customer prefix masked
        self.assertTrue(p["enrichment.customer_prefix"].startswith("id-"))
        tmp.cleanup()


class PassthroughCacheTests(unittest.TestCase):
    """v0.10.28 — the perf caches (passthrough + per-column decision) must not
    change output: only UNCHANGED values are cached, masked ones still mask."""

    def test_repeated_values_stable_and_masked(self):
        tmp, vault, anon = make_engine(client_terms=("ClienteBeta",), host_terms=("WKS*",))
        # client name must mask both times (not wrongly cached as passthrough)
        self.assertEqual(anon.process("ticket per ClienteBeta"), anon.process("ticket per ClienteBeta"))
        self.assertNotIn("ClienteBeta", anon.process("ticket per ClienteBeta"))
        # enum passes through and is cached; a masked value is never passthrough
        self.assertEqual(anon.process_dlp_field("status", "Success"), "Success")
        self.assertEqual(anon.process_dlp_field("status", "Success"), "Success")
        self.assertNotIn("ClienteBeta", anon.process_dlp_field("note", "per ClienteBeta"))
        self.assertNotIn("WKS0421", anon.process_dlp_field("host", "WKS0421"))
        tmp.cleanup()

    def test_structured_decision_cache_consistent(self):
        tmp, vault, anon = make_engine(client_terms=("ClienteBeta",))
        rows = "\n".join(json.dumps({"Stato": "Success", "Utente": "u%d" % i}) for i in range(5))
        result = anonymize_structured("ndjson", rows, anon, vault,
                                      safe=True, source="t", family="microsoft_entra")
        for line in result.output.splitlines():
            p = json.loads(line)
            self.assertEqual(p["Stato"], "Success")       # enum kept every row
            self.assertTrue(p["Utente"].startswith("usr-"))  # user masked every row
        tmp.cleanup()


class CortexSmallAuthExportTests(unittest.TestCase):
    """v0.10.29 — a small Cortex xdr_data auth/actor export (few columns) is
    detected and masks the identities instead of leaking/eliding them."""

    FIELDS = ["_time", "dst_actor_effective_username", "auth_identity",
              "action_remote_ip", "action_country", "_product", "_vendor",
              "insert_timestamp"]

    def test_small_export_autodetects_cortex(self):
        from vendor_kits import detect_vendor_kit
        self.assertEqual(detect_vendor_kit(self.FIELDS)["id"], "cortex")

    def test_identities_masked_metadata_kept(self):
        from logmask import default_policy, apply_safe_policy
        samples = {c: ["x"] for c in self.FIELDS}
        pol = apply_safe_policy(default_policy(self.FIELDS, samples, "cortex"), samples)
        elided = [c for c in self.FIELDS
                  if pol["columns"].get(c, {}).get("action") == "redact"]
        self.assertEqual(elided, [])
        for f in ("auth_identity", "dst_actor_effective_username"):
            r, _ = match_rule(f, "cortex")
            self.assertEqual((r.action, r.kind), ("mask", "user"), f)
        for f in ("action_country", "_product", "_vendor"):
            r, _ = match_rule(f, "cortex")
            self.assertEqual(r.action, "keep", f)

    def test_end_to_end_no_username_leak(self):
        tmp, vault, anon = make_engine(ip_mode="internal")
        row = {"auth_identity": "CORP\\jdoe", "dst_actor_effective_username": "asmith",
               "action_country": "IT", "_product": "XDR Agent", "_vendor": "PANW"}
        result = anonymize_structured("json", json.dumps(row), anon, vault,
                                      safe=True, source="test", family="cortex")
        self.assertNotIn("[ELIDED]", result.output)
        p = json.loads(result.output)
        self.assertNotIn("jdoe", result.output)           # auth identity masked
        self.assertNotIn("asmith", result.output)         # username masked
        self.assertEqual(p["action_country"], "IT")        # enum kept
        self.assertEqual(p["_vendor"], "PANW")             # metadata kept
        tmp.cleanup()


class CortexAuthStoryTests(unittest.TestCase):
    """v0.10.30 — Cortex 'authentication_story' export (auth_service,
    auth_client, auth_identity, n) detects and classifies without eliding or
    leaking; DOMAIN\\user identities mask as user (not email-fail -> elide)."""

    FIELDS = ["auth_service", "auth_identity", "auth_client", "n"]

    def test_detects_and_no_elision(self):
        from vendor_kits import detect_vendor_kit
        from logmask import default_policy, apply_safe_policy
        self.assertEqual(detect_vendor_kit(self.FIELDS)["id"], "cortex")
        samples = {c: ["x"] for c in self.FIELDS}
        pol = apply_safe_policy(default_policy(self.FIELDS, samples, "cortex"), samples)
        elided = [c for c in self.FIELDS
                  if pol["columns"].get(c, {}).get("action") == "redact"]
        self.assertEqual(elided, [])
        for f in ("auth_service", "auth_client", "n"):
            r, _ = match_rule(f, "cortex")
            self.assertEqual(r.action, "keep", f)

    def test_auth_identity_domain_user_masked_not_elided(self):
        r, _ = match_rule("auth_identity", "cortex")
        self.assertEqual((r.action, r.kind), ("mask", "user"))
        tmp, vault, anon = make_engine()
        result = anonymize_structured("json", json.dumps(
            {"auth_identity": "CORP\\jdoe", "auth_service": "AzureAD",
             "auth_client": "Web", "n": "42"}),
            anon, vault, safe=True, source="test", family="cortex")
        self.assertNotIn("[ELIDED]", result.output)   # DOMAIN\user no longer fails
        self.assertNotIn("jdoe", result.output)
        p = json.loads(result.output)
        self.assertEqual(p["auth_service"], "AzureAD")
        self.assertEqual(p["auth_client"], "Web")
        self.assertEqual(p["n"], "42")
        tmp.cleanup()


class Office365MailKitTests(unittest.TestCase):
    """v0.10.31 — Microsoft Graph / O365 mail export (msft_o365_emails_raw):
    recipient/header fields scrubbed, enums kept, mailbox owner masked."""

    FIELDS = ["ccRecipients", "from", "hasAttachments", "inferenceClassification",
              "internetMessageHeaders", "n", "toRecipients", "mailboxOwner"]

    def test_detects_and_no_elision(self):
        from vendor_kits import detect_vendor_kit
        from logmask import default_policy, apply_safe_policy
        self.assertEqual(detect_vendor_kit(self.FIELDS)["id"], "cortex")
        samples = {c: ["x"] for c in self.FIELDS}
        pol = apply_safe_policy(default_policy(self.FIELDS, samples, "cortex"), samples)
        elided = [c for c in self.FIELDS
                  if pol["columns"].get(c, {}).get("action") == "redact"]
        self.assertEqual(elided, [])

    def test_field_classification(self):
        from logmask import norm_col
        expect = {"from": ("text", None), "toRecipients": ("text", None),
                  "ccRecipients": ("text", None), "internetMessageHeaders": ("text", None),
                  "mailboxOwner": ("mask", "email"), "hasAttachments": ("keep", None),
                  "inferenceClassification": ("keep", None), "n": ("keep", None)}
        for f, (a, k) in expect.items():
            r, _ = match_rule(norm_col(f), "cortex")
            self.assertEqual((r.action, r.kind), (a, k), f)

    def test_end_to_end_emails_masked(self):
        tmp, vault, anon = make_engine(ip_mode="internal")
        row = {"from": "mario@contoso.com",
               "toRecipients": "anna@contoso.com, luca@contoso.com",
               "mailboxOwner": "owner@contoso.com", "hasAttachments": "true",
               "inferenceClassification": "focused",
               "internetMessageHeaders": "Received: from mail.contoso.com (10.1.2.3)"}
        result = anonymize_structured("json", json.dumps(row), anon, vault,
                                      safe=True, source="test", family="cortex")
        self.assertNotIn("[ELIDED]", result.output)
        self.assertNotIn("mario@contoso.com", result.output)
        self.assertNotIn("anna@contoso.com", result.output)
        self.assertNotIn("owner@contoso.com", result.output)
        self.assertNotIn("10.1.2.3", result.output)            # tenant IP in headers masked
        p = json.loads(result.output)
        self.assertEqual(p["hasAttachments"], "true")
        self.assertEqual(p["inferenceClassification"], "focused")
        tmp.cleanup()


class EmailDomainConstantTests(unittest.TestCase):
    """v0.10.32 — every address at the same domain gets the SAME masked domain,
    while the local part stays unique; still reversible."""

    def test_same_domain_constant_local_unique(self):
        tmp, vault, anon = make_engine()
        outs = {e: anon.process(e) for e in
                ("mario@contoso.com", "anna@contoso.com", "bob@other.com")}
        dom = lambda s: s.split("@", 1)[1]
        self.assertEqual(dom(outs["mario@contoso.com"]), dom(outs["anna@contoso.com"]))
        self.assertNotEqual(dom(outs["mario@contoso.com"]), dom(outs["bob@other.com"]))
        self.assertEqual(len({s.split("@", 1)[0] for s in outs.values()}), 3)
        deanon = Deanonymizer(vault, anon.opt)
        self.assertEqual(deanon.process(outs["mario@contoso.com"]), "mario@contoso.com")
        tmp.cleanup()

    def test_domain_constant_across_columns(self):
        tmp, vault, anon = make_engine()
        r = anonymize_structured("json", json.dumps(
            {"user.email": "a@corp.example", "o365audit.Sender": "b@corp.example"}),
            anon, vault, safe=True, source="t", family="elastic_ecs")
        p = json.loads(r.output)
        self.assertEqual(p["user.email"].split("@", 1)[1],
                         p["o365audit.Sender"].split("@", 1)[1])
        tmp.cleanup()
