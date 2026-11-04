#!/usr/bin/env python3
"""Low-impact TCP and web exposure checks for an explicitly authorized host."""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from larp_osint import LookupErrorMessage, normalize_domain

DEFAULT_PORTS = "80,443,30120,40120"
WEB_PORTS = (80, 443, 30120, 40120)
WEB_UI_PORTS = (80, 443, 40120)
SECURITY_HEADERS = ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy")
CERT_WARN_DAYS = 21
MAX_PORTS = 1024
MAX_WORKERS = 16


class ScanInputError(Exception):
    pass


def looks_like_domain(value: str) -> bool:
    """Dashboard auto-detection; a leading @ always forces a username check instead."""
    try:
        normalize_domain(value)
    except LookupErrorMessage:
        return False
    return True


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                start, end = map(int, bounds)
            except ValueError as exc:
                raise ScanInputError(f"Invalid port range: {part}") from exc
            if start > end:
                raise ScanInputError(f"Port range is reversed: {part}")
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError as exc:
                raise ScanInputError(f"Invalid port: {part}") from exc
        if any(port < 1 or port > 65535 for port in ports):
            raise ScanInputError("Ports must be between 1 and 65535.")
        if len(ports) > MAX_PORTS:
            raise ScanInputError(f"A maximum of {MAX_PORTS} TCP ports is allowed per run.")
    if not ports:
        raise ScanInputError("Provide at least one port.")
    return sorted(ports)


def probe_tcp(host: str, port: int, timeout: float) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return {"port": port, "protocol": "tcp", "state": "open", "service_hint": service}
    except (TimeoutError, socket.timeout):
        return {"port": port, "protocol": "tcp", "state": "filtered_or_timeout"}
    except ConnectionRefusedError:
        return {"port": port, "protocol": "tcp", "state": "closed"}
    except OSError as exc:
        return {"port": port, "protocol": "tcp", "state": "unavailable", "detail": str(exc)}


def tls_context_for_ip() -> ssl.SSLContext:
    """Verify the certificate chain; skip hostname matching because targets are bare IPs."""
    context = ssl.create_default_context()
    context.check_hostname = False
    return context


def open_http_connection(host: str, port: int, timeout: float, secure: bool) -> http.client.HTTPConnection:
    if secure:
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=tls_context_for_ip())
    return http.client.HTTPConnection(host, port, timeout=timeout)


def summarize_certificate(cert: dict[str, Any]) -> dict[str, Any]:
    def common_name(field: str) -> str | None:
        return next((value for rdn in cert.get(field, ()) for key, value in rdn if key == "commonName"), None)

    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    return {
        "subject_cn": common_name("subject"),
        "issuer_cn": common_name("issuer"),
        "subject_alt_names": [value for kind, value in cert.get("subjectAltName", ()) if kind in {"DNS", "IP Address"}][:20],
        "not_after_utc": not_after.isoformat(timespec="seconds"),
        "days_left": (not_after - datetime.now(timezone.utc)).days,
    }


def check_http(host: str, port: int, timeout: float) -> dict[str, Any]:
    secure = port == 443
    connection = open_http_connection(host, port, timeout, secure)
    paths = ["/", "/info.json"] if port == 30120 else ["/"]
    checks: list[dict[str, Any]] = []
    try:
        for path in paths:
            try:
                connection.request("GET", path, headers={"User-Agent": "flmp-authorized-check/0.1", "Connection": "close"})
                peer_cert = connection.sock.getpeercert() if secure and connection.sock else None
                response = connection.getresponse()
                headers = {key.lower(): value[:256] for key, value in response.getheaders()}
                response.read(1024)  # Bound response handling; never save page content.
                check: dict[str, Any] = {
                    "path": path,
                    "status": response.status,
                    "server_header": headers.get("server"),
                    "content_type": headers.get("content-type"),
                    "tls": secure,
                }
                if port in WEB_UI_PORTS and path == "/" and 200 <= response.status < 300:  # redirects rarely carry page headers
                    expected = SECURITY_HEADERS + (("strict-transport-security",) if secure else ())
                    check["missing_security_headers"] = [name for name in expected if name not in headers]
                if peer_cert:
                    check["certificate"] = summarize_certificate(peer_cert)
                checks.append(check)
                connection.close()
                if path != paths[-1]:
                    connection = open_http_connection(host, port, timeout, secure)
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                checks.append({"path": path, "error": str(exc)[:256], "tls": secure})
                connection.close()
                break
    finally:
        connection.close()
    return {"port": port, "checks": checks}


# Exposed-service hardening map: TCP port -> (level, what it usually is, how to fix the exposure).
# These are exposure/misconfiguration checks for an authorized server, never exploit attempts.
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    40120: ("HIGH", "txAdmin web panel", "Do not expose txAdmin to the internet. Bind it to localhost and reach it over a VPN or SSH tunnel, or restrict the port to your admin IPs with a firewall. Use a strong, unique admin password and enable 2FA."),
    22: ("REVIEW", "SSH", "Allow SSH only from known admin IPs, disable password login in favour of keys, and disable root login (PermitRootLogin no)."),
    3389: ("HIGH", "Windows Remote Desktop (RDP)", "Never expose RDP directly to the internet. Put it behind a VPN, enforce Network Level Authentication, and restrict the source IPs."),
    3306: ("HIGH", "MySQL/MariaDB database", "A database should not be reachable from the internet. Bind it to 127.0.0.1 or restrict it to the app server's IP by firewall."),
    5432: ("HIGH", "PostgreSQL database", "Bind the database to localhost or the app server only; never expose it publicly. Review pg_hba.conf and firewall rules."),
    27017: ("HIGH", "MongoDB database", "Do not expose MongoDB publicly. Bind it to localhost, enable authentication, and firewall the port."),
    6379: ("HIGH", "Redis", "Redis has no auth by default and must never be public. Bind it to localhost, set requirepass, and firewall the port."),
    21: ("REVIEW", "FTP", "FTP sends credentials in clear text. Replace it with SFTP/FTPS and restrict access to known IPs."),
    23: ("HIGH", "Telnet", "Telnet is unencrypted and should be disabled entirely; use SSH instead."),
}


def finding(level: str, title: str, detail: str, fix: str) -> dict[str, str]:
    return {"level": level, "title": title, "detail": detail, "fix": fix}


def port_findings(open_ports: set[int]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if 30120 in open_ports:
        findings.append(finding("INFO", "FiveM-typical TCP port 30120 is reachable", "Reachability confirmed; this alone does not indicate a vulnerability.", "Expected for a public FiveM server. Keep FXServer updated and review your resources for known-vulnerable scripts."))
    for port in sorted(open_ports):
        if port in RISKY_PORTS:
            level, service, fix = RISKY_PORTS[port]
            findings.append(finding(level, f"Sensitive service exposed on TCP/{port} ({service})", f"Port {port} is typically {service} and is reachable from this scan location. Internet-exposed admin and database services are a common break-in path.", fix))
    return findings


def web_findings(web_checks: list[dict[str, Any]]) -> list[dict[str, str]]:
    """TLS validation, certificate expiry, plaintext admin UIs, and missing browser security headers."""
    findings: list[dict[str, str]] = []
    for web in web_checks:
        for check in web["checks"]:
            if check.get("error") and web["port"] == 443:
                findings.append(finding("REVIEW", "HTTPS/TLS connection could not be validated", "Review the certificate chain and server-side TLS configuration; the hostname is not checked for IP targets.", "Install a valid certificate from a trusted CA (e.g. Let's Encrypt) and disable outdated protocols (SSLv3, TLS 1.0/1.1)."))
            if web["port"] == 40120 and not check.get("tls") and check.get("status"):
                findings.append(finding("HIGH", "txAdmin panel served over plain HTTP", "The admin panel answered over unencrypted HTTP; credentials and session cookies could be read on the network path.", "Put the panel behind an HTTPS reverse proxy (e.g. Caddy/nginx with a valid certificate) and, better still, keep it off the public internet entirely."))
            certificate = check.get("certificate")
            if certificate and certificate["days_left"] < CERT_WARN_DAYS:
                state = "has expired" if certificate["days_left"] < 0 else f"expires in {certificate['days_left']} days"
                findings.append(finding("REVIEW", f"TLS certificate on port {web['port']} {state}", f"Valid until {certificate['not_after_utc']}.", "Renew the certificate now and set up automatic renewal (e.g. certbot or your proxy's built-in ACME) so it cannot lapse again."))
            if check.get("missing_security_headers"):
                missing = ", ".join(check["missing_security_headers"])
                findings.append(finding("INFO", f"Missing browser security headers on port {web['port']}", f"Not set: {missing}. Relevant for web UIs, not for game traffic.", f"Add the headers at your web server or reverse proxy: {missing}. Start with X-Content-Type-Options: nosniff and X-Frame-Options: DENY, then a Content-Security-Policy."))
    return findings


def run_scan(host_arg: str, ports: list[int], timeout: float) -> dict[str, Any]:
    try:
        host = str(ipaddress.ip_address(host_arg))
    except ValueError as exc:
        raise ScanInputError("Enter an IPv4 or IPv6 address; DNS names are not accepted.") from exc

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(lambda port: probe_tcp(host, port, timeout), ports))
    open_ports = {item["port"] for item in results if item["state"] == "open"}
    web_checks = [check_http(host, port, timeout) for port in WEB_PORTS if port in open_ports]

    findings = port_findings(open_ports)
    for web in web_checks:
        for check in web["checks"]:
            server = check.get("server_header")
            if server and any(char.isdigit() for char in server):
                findings.append(finding("REVIEW", f"Version-like server header on port {web['port']}", "A version number in the Server header helps attackers pick matching exploits; a banner alone does not prove a vulnerable version.", "Hide the version in your web server config (e.g. nginx server_tokens off; Apache ServerTokens Prod) and keep the software patched."))
    findings.extend(web_findings(web_checks))

    return {
        "target": host,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": {"protocol": "TCP", "ports_requested": ports, "timeout_seconds": timeout, "max_parallel_connections": MAX_WORKERS},
        "ports": results,
        "http_checks": web_checks,
        "findings": findings,
        "limitations": [
            "TCP connection checks and limited HTTP/TLS requests only; no UDP scan.",
            "No exploit or password tests; this is not a complete vulnerability scan.",
            "An open port or banner is not proof of a vulnerability.",
        ],
    }


def run_nmap_scan(host_arg: str, ports: list[int], timeout: float) -> dict[str, Any]:
    try:
        host = str(ipaddress.ip_address(host_arg))
    except ValueError as exc:
        raise ScanInputError("Enter an IPv4 or IPv6 address; DNS names are not accepted.") from exc
    nmap = shutil.which("nmap") or shutil.which("nmap.exe")
    if not nmap:
        raise ScanInputError("Nmap was not found. Install Nmap or use --engine tcp.")

    command = [
        nmap, "-sT", "-sV", "--version-light", "-T2", "-Pn", "--reason",
        "--max-retries", "1", "--host-timeout", "5m", "--stats-every", "1s",
        "-p", ",".join(map(str, ports)), "--script", "ssl-cert,http-title,http-headers",
    ]
    xml_temp = tempfile.NamedTemporaryFile(prefix="flmp-", suffix=".xml", delete=False)
    xml_path = xml_temp.name
    xml_temp.close()
    command.extend(["-oX", xml_path, host])
    process: subprocess.Popen[str] | None = None
    output_tail: list[str] = []

    def show_progress(percent: int) -> None:
        width = 32
        value = max(0, min(percent, 100))
        filled = round(width * value / 100)
        bar = "=" * filled + ">" + " " * max(0, width - filled - 1)
        line = f"Nmap [{bar}] {value:3d}%"
        if sys.stdout.isatty():
            sys.stdout.write("\r" + line)
            sys.stdout.flush()
        else:
            print(line, flush=True)

    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace", bufsize=1,
        )
        show_progress(0)
        assert process.stdout is not None
        for output_line in process.stdout:
            clean_line = output_line.strip()
            if clean_line:
                output_tail.append(clean_line)
                if len(output_tail) > 40:
                    output_tail.pop(0)
            match = re.search(r"(?:About\s+)?(\d+(?:\.\d+)?)%\s+done", clean_line, re.IGNORECASE)
            if match:
                show_progress(int(float(match.group(1))))
        return_code = process.wait(timeout=310)
        if return_code in (0, 1):
            show_progress(100)
            if sys.stdout.isatty():
                print()
        if return_code not in (0, 1) or not Path(xml_path).is_file():
            detail = "\n".join(output_tail)[-1200:] or f"Nmap-Exitcode {return_code}"
            raise ScanInputError(f"Nmap scan failed: {detail}")
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError as exc:
            raise ScanInputError("Nmap did not produce readable XML output.") from exc
    except subprocess.TimeoutExpired as exc:
        if process is not None:
            process.kill()
            process.wait()
        raise ScanInputError("Nmap exceeded the 310-second time limit.") from exc
    except OSError as exc:
        raise ScanInputError(f"Could not start Nmap: {exc}") from exc
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()
        if sys.stdout.isatty():
            print()
        raise
    finally:
        try:
            os.unlink(xml_path)
        except FileNotFoundError:
            pass

    ports_found: list[dict[str, Any]] = []
    open_ports: set[int] = set()
    for entry in root.findall(".//port"):
        state = entry.find("state")
        service = entry.find("service")
        port_number = int(entry.attrib["portid"])
        state_name = state.get("state", "unknown") if state is not None else "unknown"
        item: dict[str, Any] = {
            "port": port_number,
            "protocol": entry.get("protocol", "tcp"),
            "state": state_name,
            "reason": state.get("reason") if state is not None else None,
        }
        if service is not None:
            item["service"] = service.get("name")
            item["product"] = service.get("product")
            item["version"] = service.get("version")
            item["tunnel"] = service.get("tunnel")
        script_results = [
            {"id": script.get("id"), "output": (script.get("output") or "")[:1200]}
            for script in entry.findall("script")
        ]
        if script_results:
            item["scripts"] = script_results
        ports_found.append(item)
        if state_name == "open":
            open_ports.add(port_number)

    web_checks = [check_http(host, port, min(timeout, 3.0)) for port in WEB_PORTS if port in open_ports]
    findings = port_findings(open_ports)
    for entry in ports_found:
        version = entry.get("version")
        product = entry.get("product") or entry.get("service")
        if entry["state"] == "open" and version:
            findings.append(finding("REVIEW", f"Service banner on TCP/{entry['port']}: {product} {version}", "An exposed version lets attackers look up known CVEs for it; banner detection may be wrong and is not itself a CVE finding.", f"Confirm the running version of {product}, update it to a supported release, and suppress the version banner where the service allows it."))
    findings.extend(web_findings(web_checks))

    finished = root.find(".//runstats/finished")
    return {
        "target": host,
        "engine": "nmap",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": {"protocol": "TCP connect + light service detection", "ports_requested": ports, "timing": "T2", "scripts": ["ssl-cert", "http-title", "http-headers"]},
        "ports": ports_found,
        "http_checks": web_checks,
        "findings": findings,
        "nmap_summary": finished.get("summary") if finished is not None else None,
        "limitations": [
            "Only ssl-cert, http-title, and http-headers run; no exploit or password tests.",
            "Only the selected TCP ports are checked; UDP is not included.",
            "Service banners are clues, not reliable proof of a vulnerability.",
        ],
    }


def start_dashboard(bind: str, port: int) -> None:
    if bind not in {"127.0.0.1", "::1", "localhost"}:
        raise ScanInputError("The dashboard can only bind to localhost.")
    # Reject requests whose Host/Origin is not this local dashboard (DNS rebinding and cross-site requests).
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    allowed_origins = {f"http://{host}" for host in allowed_hosts}

    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def host_is_allowed(self) -> bool:
            return (self.headers.get("Host") or "").lower() in allowed_hosts

        def send_json(self, status: int, value: dict[str, Any]) -> None:
            payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            if not self.host_is_allowed():
                self.send_error(403)
                return
            if self.path not in {"/", "/index.html"}:
                self.send_error(404)
                return
            page = Path(__file__).with_name("dashboard.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self) -> None:
            if self.path not in {"/scan", "/osint"}:
                self.send_error(404)
                return
            try:
                peer = ipaddress.ip_address(self.client_address[0])
                if not peer.is_loopback:
                    self.send_json(403, {"error": "The dashboard only accepts local connections."})
                    return
                origin = self.headers.get("Origin")
                if not self.host_is_allowed() or (origin is not None and origin.lower() not in allowed_origins):
                    self.send_json(403, {"error": "Request did not come from the local dashboard."})
                    return
                content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    self.send_json(415, {"error": "Expected Content-Type: application/json."})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 8192:
                    self.send_json(400, {"error": "Invalid request size."})
                    return
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    self.send_json(400, {"error": "Expected a JSON object."})
                    return
                if self.path == "/scan":
                    if body.get("authorized") is not True:
                        self.send_json(400, {"error": "Confirm that this server IP is explicitly authorized for scanning."})
                        return
                    target = str(ipaddress.ip_address(str(body.get("ip", ""))))
                    selected_ports = parse_ports(str(body.get("ports", DEFAULT_PORTS)))
                    result = run_nmap_scan(target, selected_ports, 1.5)
                else:
                    from larp_osint import check_discord_id, check_discord_username, check_domain, check_email, check_ip, check_phone_number, normalize_discord_id

                    query = str(body.get("query", "")).strip()
                    if not query or len(query) > 320:
                        self.send_json(400, {"error": "Enter an email, domain, public IP, Discord ID, mention, or profile URL (max. 320 characters)."})
                        return
                    if "@" in query and not query.startswith(("<@", "@")):
                        kind = "email"
                        result = check_email(query)
                        sources = ["DNS MX", "Domain TXT (SPF)", "_dmarc TXT"]
                    else:
                        try:
                            ipaddress.ip_address(query)
                            kind = "ip"
                        except ValueError:
                            try:
                                normalize_discord_id(query)
                                kind = "discord"
                            except LookupErrorMessage:
                                kind = "phone" if query.startswith("+") else "username" if query.startswith("@") else "domain" if looks_like_domain(query) else "username"
                        if kind == "ip":
                            include_geo = body.get("include_geo") is True
                            result = check_ip(query, include_geo=include_geo)
                            sources = ["RDAP", "Reverse DNS PTR"] + (["ipwho.is"] if include_geo else [])
                        elif kind == "discord":
                            result = check_discord_id(query)
                            sources = ["Local Snowflake decode"]
                        elif kind == "username":
                            result = check_discord_username(query)
                            sources = ["Local Discord username format check"]
                        elif kind == "phone":
                            result = check_phone_number(query)
                            sources = ["Local phone numbering-plan metadata"]
                        else:
                            include_ct = body.get("include_ct") is True
                            result = check_domain(query, include_ct)
                            sources = ["Public DNS: A, AAAA, MX, NS, TXT, CAA, SOA", "RDAP domain registry"] + (["crt.sh certificate transparency"] if include_ct else [])
                    self.send_json(200, {
                        "query": query,
                        "detected_type": kind,
                        "sources_queried": sources,
                        "result": result,
                        "limitations": [
                            "No breach, stealer-log, private-account, owner-lookup, or cross-platform username databases are queried.",
                            "Phone data uses offline numbering-plan metadata; it does not identify an owner, current carrier, or device location.",
                            "Discord metadata is decoded locally; it does not verify account status or reveal identity, email, IP, messages, or server membership.",
                        ],
                    })
                    return
                self.send_json(200, result)
            except (ValueError, ScanInputError, LookupErrorMessage, json.JSONDecodeError) as exc:
                self.send_json(400, {"error": str(exc)})

    server = ThreadingHTTPServer((bind, port), DashboardHandler)
    print(f"flmp 3D dashboard is running locally: http://{bind}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()


COLOR_NAMES = ("reset", "cyan", "green", "yellow", "red", "dim", "bold", "magenta", "blue", "gray")


def terminal_style() -> dict[str, str]:
    if not sys.stdout.isatty() or "NO_COLOR" in os.environ:
        return {name: "" for name in COLOR_NAMES}
    if sys.platform == "win32":
        os.system("")  # enable ANSI escape processing in legacy Windows consoles
    return {
        "reset": "\033[0m", "cyan": "\033[96m", "green": "\033[92m", "yellow": "\033[93m",
        "red": "\033[91m", "dim": "\033[2m", "bold": "\033[1m", "magenta": "\033[95m",
        "blue": "\033[94m", "gray": "\033[90m",
    }


def render_discord_report(result: dict[str, Any]) -> str:
    """Render locally decoded Discord Snowflake metadata as a compact terminal graphic."""
    snowflake = result.get("snowflake_metadata", {})
    lines = [
        "+--------------------------------------------------------------------+",
        "| FLMP // DISCORD PUBLIC METADATA                                    |",
        "+--------------------------------------------------------------------+",
        f"| ID             : {result.get('discord_id', '—')}",
        f"| Input format   : {result.get('input_format', '—')}",
        f"| Created (UTC)  : {result.get('account_created_utc', '—')}",
        f"| Age estimate   : {result.get('account_age_days', '—')} days",
        f"| Worker / Proc  : {snowflake.get('worker_id', '—')} / {snowflake.get('process_id', '—')}",
        f"| Increment      : {snowflake.get('increment', '—')}",
        "+--------------------------------------------------------------------+",
        "| GRAPH: ID -> Snowflake timestamp -> account creation estimate     |",
        "|        ID -> generated Discord profile link                        |",
        "+--------------------------------------------------------------------+",
        "| NAME / USERNAME: Not encoded in this ID.                         |",
        f"| PROFILE: {result.get('profile_url', '—')}",
        "| OFFICIAL REFERENCES (account owner):                               |",
        f"| Name rules: {result.get('official_references', {}).get('username_and_display_name_rules', '—')}",
        f"| Data export: {result.get('official_references', {}).get('data_package_for_account_owner', '—')}",
        f"| Privacy: {result.get('official_references', {}).get('privacy_controls_for_account_owner', '—')}",
        "+--------------------------------------------------------------------+",
        "| NOTE: Snowflake metadata only; no identity or private data lookup.|",
        "+--------------------------------------------------------------------+",
    ]
    return "\n".join(lines)


def render_username_report(result: dict[str, Any]) -> str:
    """Render a local-only Discord username format check."""
    status = str(result.get("format_status", "unknown")).upper()
    issues = result.get("format_issues", [])
    lines = [
        "+--------------------------------------------------------------------+",
        "| FLMP // DISCORD USERNAME FORMAT                                    |",
        "+--------------------------------------------------------------------+",
        f"| Input      : {result.get('input', '—')}",
        f"| Normalized : {result.get('normalized_handle', '—')}",
        f"| Length     : {result.get('length', '—')} / 32",
        f"| Allowed set: {result.get('allowed_characters', '—')}",
        f"| Double dot : {result.get('has_consecutive_periods', '—')}",
        f"| Format     : {status}",
        "| Availability: NOT CHECKED                                          |",
        "| Identity   : No name or account matching performed.                |",
    ]
    for issue in issues:
        lines.append(f"| - {issue}")
    lines.extend([
        "+--------------------------------------------------------------------+",
        "| GRAPH: typed handle -> local format rules -> report                |",
        "+--------------------------------------------------------------------+",
    ])
    return "\n".join(lines)


def render_display_name_report(result: dict[str, Any]) -> str:
    """Render local-only Discord display-name formatting details."""
    lines = [
        "+--------------------------------------------------------------------+",
        "| FLMP // DISCORD DISPLAY NAME CHECK                                |",
        "+--------------------------------------------------------------------+",
        f"| Input      : {result.get('input', '—')}",
        f"| Normalized : {result.get('normalized_display_name', '—')}",
        f"| Length     : {result.get('length', '—')} / 32",
        f"| Format     : {str(result.get('format_status', 'unknown')).upper()}",
        "| Account lookup: NOT PERFORMED                                    |",
    ]
    for issue in result.get("format_issues", []):
        lines.append(f"| - {issue}")
    lines.extend([
        "+--------------------------------------------------------------------+",
        f"| Rules: {result.get('official_reference', '—')}",
        f"| NOTE: {result.get('scope_note', '')}",
        "+--------------------------------------------------------------------+",
    ])
    return "\n".join(lines)


def render_phone_report(result: dict[str, Any]) -> str:
    """Render offline phone numbering-plan metadata without implying subscriber identification."""
    lines = [
        "+--------------------------------------------------------------------+",
        "| FLMP // PHONE NUMBER METADATA                                      |",
        "+--------------------------------------------------------------------+",
        f"| International : {result.get('international_format', '—')}",
        f"| E.164         : {result.get('e164_format', '—')}",
        f"| Country code  : +{result.get('country_calling_code', '—')}",
        f"| Region        : {result.get('numbering_region', '—')}",
        f"| Possible      : {result.get('possible', '—')}",
        f"| Plan match    : {result.get('valid_numbering_plan_match', '—')}",
        f"| Number type   : {result.get('number_type', '—')}",
        "+--------------------------------------------------------------------+",
        "| GRAPH: supplied number -> local numbering plan -> report          |",
        "| OWNER / CURRENT LOCATION: NOT IDENTIFIED                           |",
        "+--------------------------------------------------------------------+",
        f"| NOTE: {result.get('scope_note', '')}",
        "+--------------------------------------------------------------------+",
    ]
    return "\n".join(lines)


def render_osint_report(kind: str, result: dict[str, Any]) -> str:
    """Render readable terminal reports for public DNS and RDAP lookups."""
    titles = {"email": "EMAIL DNS", "domain": "DOMAIN DNS", "ip": "PUBLIC IP INTELLIGENCE"}
    lines = [
        "+--------------------------------------------------------------------+",
        f"| FLMP // {titles.get(kind, 'PUBLIC OSINT REPORT'):<61}|",
        "+--------------------------------------------------------------------+",
    ]
    if kind == "email":
        lines.extend([
            f"| Address : {result.get('input', '—')}",
            f"| Domain  : {result.get('domain', '—')}",
            f"| MX      : {result.get('status', '—')}",
            "| GRAPH   : email -> domain -> MX / SPF / DMARC",
        ])
        for record in result.get("mx_records", []):
            lines.append(f"|   MX {record.get('priority', '?')} -> {record.get('host', '?')}")
        for policy_name, policy in result.get("mail_dns_policy", {}).items():
            lines.append(f"|   {policy_name.upper()} -> {policy.get('status', '—')}")
            for record in policy.get("records", []):
                lines.append(f"|     {record}")
    elif kind == "domain":
        lines.extend([
            f"| Domain : {result.get('domain', '—')}",
            f"| Status : {result.get('status', '—')}",
            "| GRAPH  : domain -> A / AAAA / MX / NS / TXT / CAA / SOA",
        ])
        for record_type, values in result.get("dns_records", {}).items():
            if isinstance(values, dict):
                lines.append(f"|   {record_type} -> lookup error: {values.get('lookup_error', 'unknown')}")
            elif values:
                for value in values:
                    if isinstance(value, dict):  # MX
                        value = f"{value['priority']} {value['host'] or '(null MX: domain accepts no mail)'}"
                    lines.append(f"|   {record_type} -> {value}")
            else:
                lines.append(f"|   {record_type} -> no record returned")
        registration = result.get("registration") or {}
        if registration.get("status") == "available":
            lines.extend([
                "| RDAP   : registry data",
                f"|   Registrar -> {registration.get('registrar') or '—'}",
                f"|   Registered -> {registration.get('registered') or '—'}",
                f"|   Expires -> {registration.get('expires') or '—'}",
                f"|   Status -> {', '.join(registration.get('registry_status') or []) or '—'}",
            ])
        else:
            lines.append(f"| RDAP   : unavailable ({registration.get('message', 'no data')})")
        ct = result.get("certificate_transparency")
        if ct and ct.get("status") == "available":
            lines.append(f"| CT LOGS: {ct['unique_hostnames']} hostnames from {ct['certificates_seen']} certificates (crt.sh)")
            lines.extend(f"|   {name}" for name in ct["hostnames"])
            if ct.get("truncated"):
                lines.append(f"|   … only the first {len(ct['hostnames'])} are shown; use --json")
        elif ct:
            lines.append(f"| CT LOGS: unavailable ({ct.get('message', 'no data')})")
    else:
        rdap = result.get("rdap", {})
        lines.extend([
            f"| Address : {result.get('input', '—')} / IPv{result.get('version', '?')}",
            f"| Network : {rdap.get('network_name') or rdap.get('handle') or '—'}",
            f"| Range   : {rdap.get('start_address', '—')} - {rdap.get('end_address', '—')}",
            f"| Country : {rdap.get('country') or '—'}",
            f"| PTR     : {result.get('reverse_dns_ptr', '—')}",
        ])
        geo = result.get("geolocation")
        if geo:
            place = ", ".join(str(geo.get(key)) for key in ("city", "region", "country") if geo.get(key))
            lines.append(f"| GEO     : {place or 'unavailable'}")
        lines.append("| GRAPH   : IP -> RDAP network -> reverse DNS / optional approximate geo")
    lines.extend(["+--------------------------------------------------------------------+", f"| NOTE: {result.get('scope_note', '')}", "+--------------------------------------------------------------------+"])
    return "\n".join(lines)


def render_report(kind: str, result: dict[str, Any]) -> str:
    """Pick the terminal report for a lookup kind (email, ip, domain, discord, username, display-name, phone)."""
    renderers = {
        "discord": render_discord_report,
        "username": render_username_report,
        "display-name": render_display_name_report,
        "phone": render_phone_report,
    }
    renderer = renderers.get(kind)
    return renderer(result) if renderer else render_osint_report(kind, result)


def print_banner(colors: dict[str, str]) -> None:
    c, g, m, r, d, b = colors["cyan"], colors["green"], colors["magenta"], colors["reset"], colors["dim"], colors["bold"]
    animate = sys.stdout.isatty()
    logo = [
        "███████╗██╗     ███╗   ███╗██████╗ ",
        "██╔════╝██║     ████╗ ████║██╔══██╗",
        "█████╗  ██║     ██╔████╔██║██████╔╝",
        "██╔══╝  ██║     ██║╚██╔╝██║██╔═══╝ ",
        "██║     ███████╗██║ ╚═╝ ██║██║     ",
        "╚═╝     ╚══════╝╚═╝     ╚═╝╚═╝     ",
    ]
    tints = (colors["blue"], c, c, g, g, colors["green"])
    print(f"{c}╔══════════════════════════════════════════════════════════╗{r}")
    for line, tint in zip(logo, tints):
        print(f"{c}║  {b}{tint}{line}{r}            {c}║{r}")
        if animate:
            sys.stdout.flush()
            time.sleep(0.04)
    print(f"{c}║{r}  {m}SENTINEL{r} {d}//{r} FiveM exposure & OSINT console {d}· local mode{r}  {c}  ║{r}")
    print(f"{c}╚══════════════════════════════════════════════════════════╝{r}")
    print(f"{d}  TCP connect · service detection · TLS/header checks · public OSINT{r}")
    print(f"{d}  Made by plbct0 and {b}sauceyC4{r}{d} · authorized scope only{r}\n")


def spinner(message: str, work, colors: dict[str, str]):
    """Run work() while showing an animated spinner; return its result."""
    if not sys.stdout.isatty():
        return work()
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    done = threading.Event()
    box: dict[str, Any] = {}

    def runner() -> None:
        try:
            box["result"] = work()
        except BaseException as exc:  # re-raised on the main thread
            box["error"] = exc
        finally:
            done.set()

    thread = threading.Thread(target=runner)
    thread.start()
    index = 0
    while not done.wait(0.08):
        sys.stdout.write(f"\r{colors['cyan']}{frames[index % len(frames)]}{colors['reset']} {message} …")
        sys.stdout.flush()
        index += 1
    thread.join()
    sys.stdout.write("\r\033[2K")  # clear the spinner line
    sys.stdout.flush()
    if "error" in box:
        raise box["error"]
    return box.get("result")


def print_welcome_screen(colors: dict[str, str]) -> None:
    """Show a one-time animated splash, then clear it before the menu."""
    g, d, r = colors["green"], colors["dim"], colors["reset"]
    from flmp_menu_art import MENU_IMAGE

    print_banner(colors)
    print(f"{d}FLMP // PUBLIC OSINT CONSOLE{r}")
    animate = sys.stdout.isatty()
    for line in MENU_IMAGE:
        print(f"{g}{line}{r}", flush=True)
        if animate:
            time.sleep(0.025)
    if animate:
        for percent in range(0, 101, 20):
            filled = percent // 10
            bar = "█" * filled + "░" * (10 - filled)
            sys.stdout.write(f"\r{g}STARTING FLMP  [{bar}] {percent:>3}%{r}")
            sys.stdout.flush()
            time.sleep(0.07)
        sys.stdout.write("\n")
        time.sleep(0.2)
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def print_scan_report(report: dict[str, Any], colors: dict[str, str]) -> None:
    g, y, c, r = colors["green"], colors["yellow"], colors["cyan"], colors["reset"]
    print(f"\n{c}TARGET {report['target']}   ENGINE {report.get('engine', 'tcp').upper()}{r}")
    print(f"{c}{'PORT':<8} {'PROTO':<7} {'STATE':<20} SERVICE / VERSION{r}")
    print(f"{'-' * 76}")
    for item in report["ports"]:
        service = " ".join(filter(None, (item.get("service"), item.get("product"), item.get("version")))) or item.get("service_hint", "")
        tint = g if item["state"] == "open" else y if item["state"] in {"filtered", "filtered_or_timeout"} else ""
        print(f"{tint}{item['port']:<8} {item.get('protocol', 'tcp'):<7} {item['state']:<20} {service}{r}")
        for script in item.get("scripts", []):
            print(f"  {c}{script['id']}: {script['output']}{r}")
    if report.get("findings"):
        print(f"\n{c}CHECK RESULTS{r}")
        for item in report["findings"]:
            tint = colors["red"] if item["level"] == "HIGH" else y if item["level"] == "REVIEW" else g
            print(f"{tint}[{item['level']}] {item['title']}{r}\n  {item['detail']}")
            if item.get("fix"):
                print(f"  {g}FIX ▶ {item['fix']}{r}")
    print(f"\n{colors['dim']}Findings are exposure/configuration signals, not confirmed CVEs. No exploit or password tests were run.{r}\n")


def run_menu() -> int:
    colors = terminal_style()
    g, y, c, r = colors["green"], colors["yellow"], colors["cyan"], colors["reset"]
    print_welcome_screen(colors)
    d, m, b, bl = colors["dim"], colors["magenta"], colors["bold"], colors["blue"]
    width = 58
    groups = (
        ("SERVER SECURITY", [
            ("1", "Quick scan", "common FiveM / web TCP ports"),
            ("2", "Custom ports", f"list or range, max. {MAX_PORTS}"),
            ("3", "Config audit", "local server.cfg baseline"),
            ("4", "Dashboard", "hacker-style browser UI (local)"),
        ]),
        ("NETWORK OSINT", [
            ("5", "Email DNS", "MX / SPF / DMARC policy"),
            ("6", "IP intel", "RDAP / reverse DNS / geo"),
            ("8", "Domain intel", "DNS / RDAP / CT subdomains"),
        ]),
        ("LOCAL METADATA", [
            ("7", "Discord ID", "Snowflake / profile metadata"),
            ("9", "Username", "Discord handle format"),
            ("10", "Phone", "offline numbering plan"),
            ("11", "Display name", "Discord display-name format"),
        ]),
    )

    def bar(plain: str, colored: str) -> str:
        """Frame one inner row, padding by visible (uncolored) length."""
        return f"{c}║{r} {colored}{' ' * max(0, width - 1 - len(plain))}{c}║{r}"

    while True:
        nmap_ready = bool(shutil.which("nmap") or shutil.which("nmap.exe"))
        state_plain = "ready" if nmap_ready else "not found"
        head_plain = "MAIN MENU"
        head = f"{b}{m}MAIN MENU{r}{' ' * (width - 1 - len(head_plain) - 6 - len(state_plain))}{d}Nmap: {r}{(g if nmap_ready else y)}{state_plain}{r}"
        print(f"{c}╔{'═' * width}╗{r}")
        print(f"{c}║{r} {head}{c}║{r}")
        for label, items in groups:
            print(f"{c}╟{'─' * width}╢{r}")
            print(bar(f"▸ {label}", f"{bl}▸ {label}{r}"))
            for key, name, desc in items:
                plain = f"[{key:>2}] {name:<13}{desc}"
                colored = f"{c}[{key:>2}]{r} {g}{name:<13}{r}{d}{desc}{r}"
                print(bar(plain, colored))
        print(f"{c}╟{'─' * width}╢{r}")
        print(bar("[ 0] Exit", f"{c}[ 0]{r} {y}Exit{r}"))
        print(f"{c}╚{'═' * width}╝{r}")
        try:
            sys.stdout.flush()
            choice = input(f"\n{g}flmp>{r} ").strip()
            if choice == "0":
                print("Goodbye.")
                return 0
            if choice == "4":
                start_dashboard("127.0.0.1", 8765)
                continue
            if choice == "3":
                from fivem_config_audit import audit, parse_config
                path = Path(input("Path to server.cfg: ").strip().strip('"'))
                if not path.is_file():
                    print(f"{colors['red']}File not found.{r}\n")
                    continue
                print(f"\nFiveM config check: {path.name}")
                for severity, title, advice in audit(parse_config(path)):
                    tint = colors["red"] if severity == "HIGH" else y if severity == "REVIEW" else g
                    print(f"{tint}[{severity}] {title}{r}\n  {advice}")
                input("\nPress Enter for menu …")
                continue
            if choice in {"5", "6", "7", "8", "9", "10", "11"}:
                from larp_osint import check_discord_display_name, check_discord_id, check_discord_username, check_domain, check_email, check_ip, check_phone_number
                if choice == "5":
                    value = input("Email address: ").strip()
                    result = spinner("Resolving MX / SPF / DMARC", lambda: check_email(value), colors)
                elif choice == "6":
                    value = input("Public IP address: ").strip()
                    include_geo = input("Also query approximate geolocation via ipwho.is? [y/N]: ").strip().lower() in {"y", "yes", "j", "ja"}
                    result = spinner("Querying RDAP / reverse DNS", lambda: check_ip(value, include_geo), colors)
                elif choice == "7":
                    value = input("Discord ID, mention, or profile URL: ").strip()
                    result = check_discord_id(value)
                elif choice == "9":
                    value = input("Discord username to check locally: ").strip()
                    result = check_discord_username(value)
                elif choice == "10":
                    value = input("International phone number (+country code): ").strip()
                    result = check_phone_number(value)
                elif choice == "11":
                    value = input("Discord display name to check locally: ")
                    result = check_discord_display_name(value)
                else:
                    value = input("Domain name: ").strip()
                    include_ct = input("Also list subdomains from certificate transparency logs (crt.sh)? [y/N]: ").strip().lower() in {"y", "yes", "j", "ja"}
                    result = spinner("Querying DNS / RDAP" + (" / crt.sh" if include_ct else ""), lambda: check_domain(value, include_ct), colors)
                kind = {"5": "email", "6": "ip", "7": "discord", "8": "domain", "9": "username", "10": "phone", "11": "display-name"}[choice]
                print(render_report(kind, result))
                input("\nPress Enter for menu …")
                continue
            if choice not in {"1", "2"}:
                print("Selection not recognized.\n")
                continue
            target = input("Server IP: ").strip()
            port_spec = DEFAULT_PORTS if choice == "1" else input("TCP ports (e.g. 80,443,30120 or 1-1024): ").strip()
            if input("Type YES to confirm explicit authorization: ").strip().upper() != "YES":
                print(f"{y}Cancelled: authorization was not confirmed.{r}\n")
                continue
            report = run_nmap_scan(target, parse_ports(port_spec), 1.5)
            print_scan_report(report, colors)
            input("Press Enter for menu …")
        except (ScanInputError, OSError, LookupErrorMessage) as exc:
            print(f"{colors['red']}Error: {exc}{r}\n")
        except (EOFError, KeyboardInterrupt):
            print("\nMenu stopped.")
            return 0


def enable_utf8_output() -> None:
    """Render box-drawing and spinner glyphs on Windows consoles and when piped."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main() -> int:
    enable_utf8_output()
    parser = argparse.ArgumentParser(prog="flmp", description="Nmap and OSINT checks for user-supplied targets.")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("menu", help="open the interactive terminal menu")
    scan_parser = subparsers.add_parser("scan", help="run Nmap TCP scan and limited HTTP/TLS checks")
    scan_parser.add_argument("ip", help="server IP address (IPv4 or IPv6)")
    scan_parser.add_argument("--ports", default=DEFAULT_PORTS, help=f"TCP ports/list/ranges, max. {MAX_PORTS}; default: {DEFAULT_PORTS}")
    scan_parser.add_argument("--timeout", type=float, default=1.5, help="connection timeout in seconds (0.2 to 5)")
    scan_parser.add_argument("--engine", choices=("nmap", "tcp"), default="nmap", help="Nmap light (default) or built-in TCP checker")
    dash_parser = subparsers.add_parser("dashboard", help="start the local 3D dashboard")
    dash_parser.add_argument("--bind", default="127.0.0.1")
    dash_parser.add_argument("--port", type=int, default=8765)
    audit_parser = subparsers.add_parser("audit-config", help="audit a local server.cfg")
    audit_parser.add_argument("path", help="path to server.cfg")
    email_parser = subparsers.add_parser("email", help="check email format and domain MX records")
    email_parser.add_argument("address", help="email address to check")
    email_parser.add_argument("--json", action="store_true", help="print raw JSON instead of the text report")
    ip_parser = subparsers.add_parser("ip", help="query public IP RDAP and optional geolocation")
    ip_parser.add_argument("address", help="public IP address")
    ip_parser.add_argument("--no-geo", action="store_true", help="skip the ipwho.is geolocation lookup")
    ip_parser.add_argument("--json", action="store_true", help="print raw JSON instead of the text report")
    discord_parser = subparsers.add_parser("discord", help="analyze a Discord ID, mention, or profile URL")
    discord_parser.add_argument("id", nargs="?", help="numeric ID, <@ID> mention, or discord.com/users/<ID> URL")
    discord_parser.add_argument("--json", action="store_true", help="print raw JSON instead of the text graphic")
    username_parser = subparsers.add_parser("username", help="check a Discord handle's format locally")
    username_parser.add_argument("handle", help="user-supplied Discord handle; no account lookup is performed")
    username_parser.add_argument("--json", action="store_true", help="print raw JSON instead of the text graphic")
    display_name_parser = subparsers.add_parser("display-name", help="check a Discord display name's basic format locally")
    display_name_parser.add_argument("name", help="user-supplied display name; no account lookup is performed")
    display_name_parser.add_argument("--json", action="store_true", help="print raw JSON instead of the text graphic")
    phone_parser = subparsers.add_parser("phone", help="parse an international phone number using offline metadata")
    phone_parser.add_argument("number", help="international number beginning with +")
    phone_parser.add_argument("--json", action="store_true", help="print raw JSON instead of the text graphic")
    domain_parser = subparsers.add_parser("domain", help="check public DNS records for a domain")
    domain_parser.add_argument("name", help="domain name")
    domain_parser.add_argument("--ct", action="store_true", help="also list subdomains seen in certificate transparency logs (crt.sh)")
    domain_parser.add_argument("--json", action="store_true", help="print raw JSON instead of the text report")
    args = parser.parse_args()

    if args.command in {None, "menu"}:
        return run_menu()

    if args.command == "dashboard":
        try:
            if not 1024 <= args.port <= 65535:
                raise ScanInputError("Dashboard port must be between 1024 and 65535.")
            start_dashboard(args.bind, args.port)
        except (ScanInputError, OSError) as exc:
            parser.error(str(exc))
        return 0

    if args.command == "scan":
        try:
            if not 0.2 <= args.timeout <= 5:
                raise ScanInputError("Timeout must be between 0.2 and 5 seconds.")
            ports = parse_ports(args.ports)
            result = run_nmap_scan(args.ip, ports, args.timeout) if args.engine == "nmap" else run_scan(args.ip, ports, args.timeout)
        except ScanInputError as exc:
            parser.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command in {"email", "ip", "discord", "domain", "username", "display-name", "phone"}:
        from larp_osint import check_discord_display_name, check_discord_id, check_discord_username, check_domain, check_email, check_ip, check_phone_number
        try:
            if args.command == "email":
                result = check_email(args.address)
            elif args.command == "ip":
                result = check_ip(args.address, not args.no_geo)
            elif args.command == "domain":
                result = check_domain(args.name, args.ct)
            elif args.command == "username":
                result = check_discord_username(args.handle)
            elif args.command == "display-name":
                result = check_discord_display_name(args.name)
            elif args.command == "phone":
                result = check_phone_number(args.number)
            else:
                discord_input = args.id or input("Discord ID, mention, or profile URL: ").strip()
                result = check_discord_id(discord_input)
        except LookupErrorMessage as exc:
            parser.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else render_report(args.command, result))
        return 0

    # Keep the existing local configuration audit available under the same CLI.
    from fivem_config_audit import audit, parse_config

    path = Path(args.path)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2
    print(f"FiveM config check: {path.name}")
    findings = audit(parse_config(path))
    for severity, title, advice in findings:
        print(f"[{severity}] {title}\n  {advice}")
    return 1 if any(item[0] == "HIGH" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
