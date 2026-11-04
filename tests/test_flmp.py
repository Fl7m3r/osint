"""Offline tests for FLMP; no DNS, RDAP, or Nmap requests are made."""

from __future__ import annotations

import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import fivem_config_audit  # noqa: E402
import fivem_remote_check as flmp  # noqa: E402
import larp_osint  # noqa: E402


class ParsePortsTests(unittest.TestCase):
    def test_list_and_range(self) -> None:
        self.assertEqual(flmp.parse_ports("443, 80,1-3"), [1, 2, 3, 80, 443])

    def test_rejects_invalid_input(self) -> None:
        for spec in ("", "0", "70000", "10-5", "abc", "1-2000"):
            with self.subTest(spec=spec), self.assertRaises(flmp.ScanInputError):
                flmp.parse_ports(spec)


class DiscordTests(unittest.TestCase):
    def test_snowflake_decode_from_all_input_formats(self) -> None:
        for value in ("175928847299117063", "<@!175928847299117063>", "https://discord.com/users/175928847299117063"):
            with self.subTest(value=value):
                result = larp_osint.check_discord_id(value)
                self.assertEqual(result["account_created_utc"], "2016-04-30T11:18:25+00:00")

    def test_username_format(self) -> None:
        self.assertEqual(larp_osint.check_discord_username("@Sample_User")["format_status"], "plausible")
        self.assertEqual(larp_osint.check_discord_username("bad..name")["format_status"], "invalid")


class DetectionTests(unittest.TestCase):
    def test_domain_detection(self) -> None:
        self.assertTrue(flmp.looks_like_domain("example.org"))
        self.assertFalse(flmp.looks_like_domain("max_power.x"))
        self.assertFalse(flmp.looks_like_domain("1.2.3"))


class ReportTests(unittest.TestCase):
    def ip_result(self, geolocation: dict) -> dict:
        return {"input": "1.1.1.1", "version": 4, "rdap": {}, "reverse_dns_ptr": [], "geolocation": geolocation, "scope_note": ""}

    def test_geo_line(self) -> None:
        self.assertIn("| GEO     : unavailable", flmp.render_report("ip", self.ip_result({"status": "unavailable"})))
        self.assertIn("| GEO     : Berlin, DE", flmp.render_report("ip", self.ip_result({"city": "Berlin", "country": "DE"})))

    def test_tls_context_verifies_chain_without_hostname(self) -> None:
        context = flmp.tls_context_for_ip()
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, flmp.ssl.CERT_REQUIRED)

    def test_findings(self) -> None:
        findings = flmp.port_findings({30120, 40120, 3306})
        self.assertEqual(findings[0]["level"], "INFO")  # 30120
        exposed = [f for f in findings if f["level"] == "HIGH"]
        self.assertEqual({"txAdmin web panel", "MySQL/MariaDB database"}, {t for f in exposed for t in [f["title"].split("(")[1].rstrip(")")]})
        self.assertTrue(all(f["fix"] for f in findings))  # every finding carries a fix
        web = [{"port": 443, "checks": [{"path": "/", "error": "boom", "tls": True}]}, {"port": 80, "checks": [{"path": "/", "error": "x"}]}]
        self.assertEqual(len(flmp.web_findings(web)), 1)

    def test_plaintext_admin_panel_is_high(self) -> None:
        web = [{"port": 40120, "checks": [{"path": "/", "status": 200, "tls": False}]}]
        self.assertEqual([f["level"] for f in flmp.web_findings(web)], ["HIGH"])


class WebFindingTests(unittest.TestCase):
    def test_certificate_summary_and_expiry_finding(self) -> None:
        cert = {
            "subject": ((("commonName", "example.org"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "subjectAltName": (("DNS", "example.org"), ("DNS", "www.example.org")),
            "notAfter": "Jan  1 00:00:00 2020 GMT",
        }
        summary = flmp.summarize_certificate(cert)
        self.assertEqual((summary["subject_cn"], summary["issuer_cn"]), ("example.org", "Example CA"))
        self.assertLess(summary["days_left"], 0)
        findings = flmp.web_findings([{"port": 443, "checks": [{"path": "/", "certificate": summary, "missing_security_headers": ["x-frame-options"]}]}])
        self.assertEqual([f["title"] for f in findings], ["TLS certificate on port 443 has expired", "Missing browser security headers on port 443"])


class DomainLookupTests(unittest.TestCase):
    def test_rdap_summary(self) -> None:
        rdap = {
            "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}, {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]]}],
            "status": ["client transfer prohibited"],
            "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
        }
        with mock.patch.object(larp_osint, "get_json", return_value=rdap):
            result = larp_osint.check_domain_rdap("example.org")
        self.assertEqual(result["registrar"], "Example Registrar")
        self.assertEqual(result["expires"], "2030-08-13T04:00:00Z")
        self.assertEqual(result["nameservers"], ["a.iana-servers.net"])

    def test_ct_subdomains_are_deduplicated_and_scoped(self) -> None:
        entries = [{"name_value": "*.example.org\nwww.example.org"}, {"name_value": "WWW.example.org\nexample.org.evil.test"}]
        with mock.patch.object(larp_osint, "fetch_json", return_value=entries):
            result = larp_osint.check_ct_subdomains("example.org")
        self.assertEqual(result["hostnames"], ["example.org", "www.example.org"])


class ConfigAuditTests(unittest.TestCase):
    def test_weak_rcon_is_high(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "server.cfg"
            path.write_text('rcon_password "changeme"\nsv_scriptHookAllowed 0\n', encoding="utf-8")
            findings = fivem_config_audit.audit(fivem_config_audit.parse_config(path))
        self.assertIn(("HIGH", "RCON password is missing, a placeholder, or too short"), [(s, t) for s, t, _ in findings])


class DashboardGuardTests(unittest.TestCase):
    PORT = 8798

    @classmethod
    def setUpClass(cls) -> None:
        threading.Thread(target=flmp.start_dashboard, args=("127.0.0.1", cls.PORT), daemon=True).start()
        time.sleep(0.5)

    def post(self, headers: dict[str, str]) -> int:
        connection = http.client.HTTPConnection("127.0.0.1", self.PORT, timeout=5)
        connection.request("POST", "/osint", body=json.dumps({"query": "@sample_user"}), headers=headers)
        status = connection.getresponse().status
        connection.close()
        return status

    def test_local_json_request_allowed(self) -> None:
        self.assertEqual(self.post({"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.PORT}"}), 200)

    def test_cross_site_requests_blocked(self) -> None:
        self.assertEqual(self.post({"Content-Type": "text/plain"}), 415)
        self.assertEqual(self.post({"Content-Type": "application/json", "Origin": "https://evil.example"}), 403)
        self.assertEqual(self.post({"Content-Type": "application/json", "Host": f"evil.example:{self.PORT}"}), 403)


if __name__ == "__main__":
    unittest.main()
