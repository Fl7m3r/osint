#!/usr/bin/env python3
"""Local, read-only baseline checks for a FiveM server.cfg."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SECRET_KEYS = {"rcon_password", "sv_licensekey"}
PLACEHOLDERS = {"changeme", "change_me", "password", "yourpassword", "none", ""}


def parse_config(path: Path) -> dict[str, list[str]]:
    """Parse simple FiveM key/value directives; ignore comments and redact secrets."""
    settings: dict[str, list[str]] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        match = re.match(r"([A-Za-z_][\w]*)\s+(.+?)\s*$", line)
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2).strip().strip('"\'')
        settings.setdefault(key, []).append(value)
    return settings


def audit(settings: dict[str, list[str]]) -> list[tuple[str, str, str]]:
    findings: list[tuple[str, str, str]] = []

    def last(key: str) -> str | None:
        values = settings.get(key)
        return values[-1].strip() if values else None

    script_hooks = (last("sv_scripthookallowed") or "").lower()
    if script_hooks in {"1", "true", "yes", "on"}:
        findings.append(("HIGH", "sv_scriptHookAllowed is enabled", "Set it to false unless you specifically need it."))
    elif script_hooks in {"0", "false", "no", "off"}:
        findings.append(("OK", "sv_scriptHookAllowed is disabled", "The config blocks client-side script hooks."))
    else:
        findings.append(("REVIEW", "sv_scriptHookAllowed is missing or unclear", "Set it explicitly to false and verify against your FXServer version."))

    rcon = last("rcon_password")
    if rcon is None:
        findings.append(("OK", "No RCON password found in this config", "If RCON is enabled elsewhere, secure that access separately."))
    elif rcon.lower() in PLACEHOLDERS or len(rcon) < 16:
        findings.append(("HIGH", "RCON password is missing, a placeholder, or too short", "Use a long random secret; the value was not printed."))
    else:
        findings.append(("REVIEW", "RCON password is set", "Length looks plausible; manually verify uniqueness and secure storage."))

    license_key = last("sv_licensekey")
    if not license_key or license_key.lower() in PLACEHOLDERS:
        findings.append(("REVIEW", "sv_licenseKey is missing or a placeholder", "Check the config and launch environment; never share the key in logs or screenshots."))
    else:
        findings.append(("OK", "sv_licenseKey is set", "The key value was not printed."))

    endpoint_privacy = (last("sv_endpointprivacy") or "").lower()
    if endpoint_privacy in {"1", "true", "yes", "on"}:
        findings.append(("OK", "sv_endpointPrivacy is enabled", "Keep it enabled and verify behavior against your server version."))
    else:
        findings.append(("REVIEW", "sv_endpointPrivacy is not explicitly enabled", "Consider enabling it to avoid unnecessary endpoint data exposure."))

    if settings.get("rcon_password") and len(settings["rcon_password"]) > 1:
        findings.append(("REVIEW", "Multiple rcon_password directives found", "Remove duplicates and verify which setting takes effect."))
    if settings.get("sv_licensekey") and len(settings["sv_licensekey"]) > 1:
        findings.append(("REVIEW", "Multiple sv_licenseKey directives found", "Remove duplicates; key values remain hidden."))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(prog="flmp", description="Read-only local baseline checks for a FiveM server.cfg.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    config_parser = subparsers.add_parser("audit-config", help="audit a local server.cfg")
    config_parser.add_argument("path", type=Path, help="path to server.cfg")
    args = parser.parse_args()

    if not args.path.is_file():
        print(f"Error: file not found: {args.path}", file=sys.stderr)
        return 2
    findings = audit(parse_config(args.path))
    print(f"FiveM config check: {args.path.name}")
    for severity, title, advice in findings:
        print(f"[{severity}] {title}\n  {advice}")
    print("\nLocal config baseline only; no network scan and not a complete security assessment.")
    return 1 if any(item[0] == "HIGH" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
