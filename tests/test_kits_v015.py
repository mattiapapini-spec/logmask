"""v0.15.0 — otto nuovi kit: crowdstrike, wazuh, microsoft_sentinel,
splunk_cim, okta, proofpoint, zscaler, aws_cloudtrail.
Per ognuno: detection dal proprio header, copertura completa (0 elisi in Safe
mode) e mascheramento end-to-end dei campi identità/host/IP con IOC preservati."""
import json
import tempfile
import unittest
from pathlib import Path

from logmask import Anonymizer, ORDER, Options, Vault, kit_dry_run
from vendor_kits import detect_vendor_kit, match_rule
from structured import anonymize_structured


def make_engine(**opt_kwargs):
    tmp = tempfile.TemporaryDirectory()
    vault = Vault(Path(tmp.name) / "vault.db", b"A" * 32)
    return tmp, vault, Anonymizer(vault, set(ORDER), Options(**opt_kwargs))

HEADERS = {
    "crowdstrike": ["DetectDate", "Detect Name", "Severity", "Tactic", "Technique", "Host Name",
                    "User Name", "File Name", "File Path", "CommandLine", "SHA256", "LocalIP",
                    "MAC Address", "Machine Domain", "aid", "cid", "FalconHostLink", "Status",
                    "event_simpleName", "Sensor Version"],
    "wazuh": ["timestamp", "id", "rule.level", "rule.description", "rule.id", "rule.mitre.id",
              "agent.id", "agent.name", "agent.ip", "manager.name", "decoder.name", "location",
              "full_log", "data.srcip", "data.srcuser", "data.srcport", "syscheck.path",
              "syscheck.sha256_after"],
    "microsoft_sentinel": ["TimeGenerated", "Computer", "Account", "AccountName", "EventID",
                           "Activity", "LogonType", "IpAddress", "WorkstationName", "TargetUserName",
                           "TargetDomainName", "SubjectUserName", "Process", "CommandLine",
                           "TenantId", "SourceComputerId", "_ResourceId", "AlertSeverity",
                           "SystemAlertId"],
    "splunk_cim": ["_time", "host", "source", "sourcetype", "index", "_raw", "src", "dest",
                   "src_ip", "dest_ip", "src_port", "dest_port", "user", "action", "app",
                   "signature", "severity", "process_name", "file_hash", "url", "bytes_in"],
    "okta": ["published", "eventType", "displayMessage", "severity", "actor.id", "actor.type",
             "actor.alternateId", "actor.displayName", "client.ipAddress",
             "client.userAgent.rawUserAgent", "client.device", "client.geographicalContext.city",
             "client.geographicalContext.country", "outcome.result", "outcome.reason",
             "transaction.id", "uuid", "authenticationContext.externalSessionId"],
    "proofpoint": ["GUID", "messageTime", "sender", "recipient", "fromAddress", "headerFrom",
                   "headerTo", "subject", "senderIP", "threatType", "threatURL", "threatStatus",
                   "classification", "phishScore", "spamScore", "malwareScore", "quarantineFolder",
                   "messageID", "urls"],
    "zscaler": ["datetime", "user", "department", "location", "urlcategory", "urlsupercategory",
                "url", "action", "appname", "appclass", "malwarecategory", "threatname",
                "riskscore", "clientIP", "serverip", "requestsize", "responsesize", "useragent",
                "hostname", "md5"],
    "aws_cloudtrail": ["eventTime", "eventVersion", "eventSource", "eventName", "awsRegion",
                       "sourceIPAddress", "userAgent", "userIdentity.type",
                       "userIdentity.principalId", "userIdentity.arn", "userIdentity.accountId",
                       "userIdentity.accessKeyId", "userIdentity.userName",
                       "requestParameters.bucketName", "responseElements.x", "requestID",
                       "eventID", "errorCode", "errorMessage", "recipientAccountId"],
}


class NewKitsDetectionTests(unittest.TestCase):
    def test_each_kit_detected_from_own_header_with_full_coverage(self):
        for kid, cols in HEADERS.items():
            with self.subTest(kit=kid):
                res = kit_dry_run(cols)
                self.assertEqual((res["detected"] or {}).get("id"), kid)
                self.assertEqual(res["elided"], [], f"{kid}: campi non coperti")

    def test_no_cross_detection_regression(self):
        # gli header dei kit storici continuano a rilevare il kit giusto
        self.assertEqual(detect_vendor_kit(["agent_hostname", "actor_effective_username",
                                            "action_local_ip", "causality_actor_process_image_name"]
                                           )["id"], "cortex")
        self.assertEqual(detect_vendor_kit(["srcip", "dstip", "devname", "logid",
                                            "srcintf"])["id"], "fortinet")

    def test_rule_spot_checks(self):
        for field, kit, action, kind in [
            ("user_name", "crowdstrike", "mask", "user"),
            ("sha256hashdata", "crowdstrike", "keep", None),
            ("falconhostlink", "crowdstrike", "mask", "opaque"),
            ("agent.name", "wazuh", "mask", "endpoint"),
            ("full_log", "wazuh", "text", None),
            ("syscheck.path", "wazuh", "keep", None),
            ("computer", "microsoft_sentinel", "mask", "endpoint"),
            ("_resourceid", "microsoft_sentinel", "mask", "opaque"),
            ("_raw", "splunk_cim", "text", None),
            ("dest", "splunk_cim", "mask", "endpoint"),
            ("actor.alternateid", "okta", "mask", "email"),
            ("client.geographicalcontext.country", "okta", "keep", None),
            ("headerfrom", "proofpoint", "mask", "email"),
            ("threaturl", "proofpoint", "keep", None),
            ("user", "zscaler", "mask", "email"),
            ("department", "zscaler", "mask", "opaque"),
            ("useridentity.arn", "aws_cloudtrail", "mask", "opaque"),
            ("useridentity.username", "aws_cloudtrail", "mask", "user"),
        ]:
            with self.subTest(field=field, kit=kit):
                r, _ = match_rule(field, kit)
                self.assertIsNotNone(r, f"{kit}:{field} senza regola")
                self.assertEqual((r.action, r.kind), (action, kind))


class NewKitsEndToEndTests(unittest.TestCase):
    def _run(self, family, payload):
        tmp, vault, anon = make_engine()
        result = anonymize_structured("json", json.dumps(payload), anon, vault,
                                      safe=True, source="test", family=family)
        tmp.cleanup()
        return result.output

    def test_crowdstrike_identity_masked_ioc_kept(self):
        out = self._run("crowdstrike", {
            "User Name": "m.bianchi", "Host Name": "WKS-042", "LocalIP": "10.1.2.3",
            "SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "File Name": "dropper.exe", "Severity": "High", "aid": "a1b2c3d4e5f6"})
        self.assertNotIn("m.bianchi", out)
        self.assertNotIn("WKS-042", out)
        self.assertNotIn("10.1.2.3", out)
        self.assertNotIn("a1b2c3d4e5f6", out)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", out)
        self.assertIn("dropper.exe", out)
        self.assertIn("High", out)

    def test_wazuh_nested_masked_rule_kept(self):
        out = self._run("wazuh", {
            "agent.name": "srv-web01", "agent.ip": "192.168.7.7", "data.srcuser": "root",
            "rule.description": "PAM: Login session opened.", "rule.level": "3",
            "syscheck.path": "/etc/passwd"})
        self.assertNotIn("srv-web01", out)
        self.assertNotIn("192.168.7.7", out)
        self.assertIn("PAM: Login session opened.", out)
        self.assertIn("/etc/passwd", out)

    def test_okta_email_constant_domain(self):
        tmp, vault, anon = make_engine()
        rows = "\n".join(json.dumps({"actor.alternateId": u, "eventType": "user.session.start"})
                         for u in ("mario.rossi@example.com", "anna.verdi@example.com"))
        result = anonymize_structured("ndjson", rows, anon, vault,
                                      safe=True, source="test", family="okta")
        lines = [json.loads(l) for l in result.output.splitlines()]
        doms = {l["actor.alternateId"].split("@", 1)[1] for l in lines}
        self.assertEqual(len(doms), 1)          # stesso dominio -> stesso mascherato
        self.assertNotIn("example.com", result.output)
        self.assertIn("user.session.start", result.output)
        tmp.cleanup()

    def test_cloudtrail_arn_masked_event_kept(self):
        out = self._run("aws_cloudtrail", {
            "userIdentity.arn": "arn:aws:iam::123456789012:user/deploy-bot",
            "userIdentity.accountId": "123456789012",
            "sourceIPAddress": "203.0.113.99", "eventName": "PutObject",
            "eventSource": "s3.amazonaws.com", "awsRegion": "eu-south-1"})
        self.assertNotIn("123456789012", out)
        self.assertNotIn("deploy-bot", out)
        self.assertNotIn("203.0.113.99", out)
        self.assertIn("PutObject", out)
        self.assertIn("s3.amazonaws.com", out)


class MicrosoftLocalizedExportTests(unittest.TestCase):
    """v0.15.0 — gli export dei portali Microsoft cambiano lingua: Entra e
    Defender devono coprire sia le intestazioni italiane sia quelle inglesi."""

    ENTRA_SIGNIN_EN = ["Date (UTC)", "Request ID", "User agent", "Correlation ID", "User ID",
                       "User", "Username", "User type", "Incoming token type",
                       "Authentication requirement", "Multifactor authentication result",
                       "IP address", "Location", "Status", "Sign-in error code", "Failure reason",
                       "Client app", "Browser", "Operating System", "Conditional Access",
                       "Autonomous system number", "Flagged for review", "Application",
                       "Application ID", "Resource", "Session ID",
                       "IP address (seen by resource)", "Through Global Secure Access",
                       "Sign-in identifier"]
    ENTRA_AUDIT_EN = ["Date (UTC)", "Correlation ID", "Service", "Category", "Activity", "Result",
                      "Result reason", "Actor type", "Actor display name", "Actor object ID",
                      "Actor user principal name", "IP address", "Target1 type",
                      "Target1 display name", "Target1 object ID", "Target1 user principal name"]
    DEFENDER_EN = ["Alert ID", "Title", "Tags", "Severity", "Investigation state", "Status",
                   "Category", "Detection source", "Impacted assets", "First activity",
                   "Last activity", "Classification", "Determination", "Assigned to",
                   "Incident id", "Incident name"]
    DEFENDER_IT = ["ID avviso", "Titolo", "Tag", "Gravit\u00e0", "Stato indagine", "Stato",
                   "Categoria", "Origine rilevamento", "Asset interessati", "Prima attivit\u00e0",
                   "Ultima attivit\u00e0", "Classificazione", "Determinazione", "Assegnato a",
                   "ID evento imprevisto", "Nome evento imprevisto"]

    def test_detection_and_full_coverage(self):
        for name, cols, want in (("signin_en", self.ENTRA_SIGNIN_EN, "microsoft_entra"),
                                 ("audit_en", self.ENTRA_AUDIT_EN, "microsoft_entra"),
                                 ("defender_en", self.DEFENDER_EN, "microsoft_defender"),
                                 ("defender_it", self.DEFENDER_IT, "microsoft_defender")):
            with self.subTest(export=name):
                res = kit_dry_run(cols)
                self.assertEqual((res["detected"] or {}).get("id"), want)
                self.assertEqual(res["elided"], [])

    def test_identity_masked_enums_kept(self):
        by = {f["column"]: f["action"] for f in kit_dry_run(self.ENTRA_SIGNIN_EN)["fields"]}
        self.assertEqual(by["Username"], "mask")
        self.assertEqual(by["User"], "mask")
        self.assertEqual(by["IP address"], "mask")
        self.assertEqual(by["IP address (seen by resource)"], "mask")
        self.assertEqual(by["Status"], "keep")
        by = {f["column"]: f["action"] for f in kit_dry_run(self.DEFENDER_IT)["fields"]}
        self.assertEqual(by["Assegnato a"], "mask")        # e-mail analista
        self.assertEqual(by["Asset interessati"], "text")  # device+utenti -> scrub
        self.assertEqual(by["Gravit\u00e0"], "keep")


class SessionProseGuardTests(unittest.TestCase):
    """v0.15.0 — "Login session opened." (PAM/Wazuh) non e' un token di
    sessione: il guard vale solo per la chiave nuda "session" + parola in
    prosa; password/token e le assegnazioni con :/= restano aggressive."""

    def test_prose_untouched_secrets_still_masked(self):
        from logmask import redact_residuals
        for text, masked in [("Login session opened.", False),
                             ("Login session closed.", False),
                             ("session established for user", False),
                             ("session=abc123secret", True),
                             ("sessionid abc123x", True),
                             ("session_id: 9f8e7d6c", True),
                             ("password hunter2x", True),
                             ("session a8f3k2j9x1", True)]:
            with self.subTest(text=text):
                _, n, _ = redact_residuals(text)
                self.assertEqual(n > 0, masked)


if __name__ == "__main__":
    unittest.main()
