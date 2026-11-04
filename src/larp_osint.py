#!/usr/bin/env python3
"""Privacy-conscious public metadata checks for user-supplied OSINT indicators."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
import sys
import time
import unicodedata
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import dns.resolver

USER_AGENT = "LarpOSINT/0.1 (public metadata lookup)"
EMAIL_RE = re.compile(r"^[^\s@<>]+@([^\s@<>]+\.[^\s@<>]+)$")
TIMEOUT = 8
CT_TIMEOUT = 30
CT_MAX_BYTES = 25_000_000
CT_MAX_HOSTNAMES = 500
DOMAIN_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")
DISCORD_EPOCH_MS = 1_420_070_400_000
DISCORD_ID_RE = re.compile(
    r"^(?:<@!?(?P<mention>\d{17,20})>|"
    r"(?:https?://)?(?:www\.)?discord\.com/users/(?P<profile>\d{17,20})/?|"
    r"(?P<id>\d{17,20}))$",
    re.IGNORECASE,
)
DISCORD_USERNAME_RE = re.compile(r"^[a-z0-9_.]{2,32}$")


class LookupErrorMessage(Exception):
    """An expected error safe to show to a CLI user."""


def check_email(address: str) -> dict[str, Any]:
    match = EMAIL_RE.fullmatch(address)
    if not match:
        raise LookupErrorMessage("Invalid email address format.")

    domain = match.group(1).rstrip(".").encode("idna").decode("ascii").lower()
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        records = sorted(
            ({"priority": int(record.preference), "host": str(record.exchange).rstrip(".")}
             for record in answers),
            key=lambda item: (item["priority"], item["host"]),
        )
        status = "mx_found" if records else "no_mx_records"
    except dns.resolver.NoAnswer:
        records, status = [], "no_mx_records"
    except dns.resolver.NXDOMAIN:
        records, status = [], "domain_not_found"
    except (dns.exception.DNSException, OSError) as exc:
        raise LookupErrorMessage(f"DNS lookup failed: {exc}") from exc

    spf_records, spf_error = resolve_txt_records(domain)
    dmarc_records, dmarc_error = resolve_txt_records(f"_dmarc.{domain}")
    spf = [record for record in spf_records if record.lower().startswith("v=spf1")]
    dmarc = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]
    return {
        "input": address,
        "domain": domain,
        "status": status,
        "mx_records": records,
        "mail_dns_policy": {
            "spf": {"status": "lookup_error" if spf_error else "published" if spf else "not_found", "records": spf, "lookup_error": spf_error},
            "dmarc": {"status": "lookup_error" if dmarc_error else "published" if dmarc else "not_found", "records": dmarc, "lookup_error": dmarc_error},
        },
        "scope_note": "Domain DNS checked; mailbox existence and ownership were not checked.",
        "resource_directory": {
            "name": "Mail OSINT Framework",
            "url": "https://mail.osintframework.com/",
            "usage_note": "A directory of external resources. Choose and review tools manually; this app does not submit the email address to them.",
        },
    }


def resolve_txt_records(name: str) -> tuple[list[str], str | None]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT)
        records = sorted("".join(part.decode("utf-8", errors="replace") for part in answer.strings) for answer in answers)
        return records, None
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], None
    except dns.exception.DNSException as exc:
        return [], str(exc)


def normalize_domain(value: str) -> str:
    try:
        domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise LookupErrorMessage("Invalid domain name.") from exc
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or labels[-1].isdigit() or any(
        not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise LookupErrorMessage("Invalid domain name.")
    return domain


def resolve_domain_record(domain: str, record_type: str) -> tuple[list[Any] | dict[str, str], bool]:
    """Resolve one record type; the flag is True when the domain does not exist."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=TIMEOUT)
    except dns.resolver.NXDOMAIN:
        return [], True
    except dns.resolver.NoAnswer:
        return [], False
    except dns.exception.DNSException as exc:
        return {"lookup_error": str(exc)}, False
    if record_type == "MX":
        return sorted(
            ({"priority": int(answer.preference), "host": str(answer.exchange).rstrip(".")} for answer in answers),
            key=lambda item: (item["priority"], item["host"]),
        ), False
    return sorted(str(answer).rstrip(".") for answer in answers), False


def check_domain(value: str, include_ct: bool = False) -> dict[str, Any]:
    domain = normalize_domain(value)

    with ThreadPoolExecutor(max_workers=len(DOMAIN_RECORD_TYPES)) as pool:
        lookups = dict(zip(DOMAIN_RECORD_TYPES, pool.map(lambda record_type: resolve_domain_record(domain, record_type), DOMAIN_RECORD_TYPES)))
    records = {record_type: values for record_type, (values, _missing) in lookups.items()}
    domain_missing = any(missing for _values, missing in lookups.values())

    try:
        registration = check_domain_rdap(domain)
    except LookupErrorMessage as exc:
        registration = {"status": "unavailable", "message": str(exc)}

    result: dict[str, Any] = {
        "domain": domain,
        "status": "domain_not_found" if domain_missing else "checked",
        "dns_records": records,
        "registration": registration,
        "scope_note": "Public DNS and RDAP registry data only; redacted registrant contact data is not queried.",
    }
    if include_ct:
        try:
            result["certificate_transparency"] = check_ct_subdomains(domain)
        except LookupErrorMessage as exc:
            result["certificate_transparency"] = {"status": "unavailable", "message": str(exc)}
    return result


def check_domain_rdap(domain: str) -> dict[str, Any]:
    """Registrar, lifecycle dates, and registry status from public RDAP; registrant contacts are skipped."""
    rdap = get_json(f"https://rdap.org/domain/{quote(domain, safe='')}")
    events = {
        event.get("eventAction"): event.get("eventDate")
        for event in rdap.get("events", []) if isinstance(event, dict)
    }
    registrar = None
    for entity in rdap.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            registrar = next((field[3] for field in (vcard[1] if len(vcard) > 1 else []) if len(field) > 3 and field[0] == "fn"), None)
            break
    return {
        "status": "available",
        "registrar": registrar,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "registry_status": rdap.get("status", []),
        "nameservers": sorted(ns.get("ldhName", "").lower().rstrip(".") for ns in rdap.get("nameservers", []) if ns.get("ldhName")),
        "source": "https://rdap.org",
    }


def check_ct_subdomains(domain: str) -> dict[str, Any]:
    """List host names under a domain that appear in public Certificate Transparency logs (crt.sh)."""
    url = f"https://crt.sh/?q={quote('%.' + domain, safe='')}&output=json"
    try:
        entries = fetch_json(url, timeout=CT_TIMEOUT, max_bytes=CT_MAX_BYTES)
    except LookupErrorMessage:
        time.sleep(2)  # crt.sh often returns transient 502/503 errors
        entries = fetch_json(url, timeout=CT_TIMEOUT, max_bytes=CT_MAX_BYTES)
    if not isinstance(entries, list):
        raise LookupErrorMessage("Unexpected response from crt.sh.")
    names: set[str] = set()
    for entry in entries:
        for name in str(entry.get("name_value", "") if isinstance(entry, dict) else "").splitlines():
            name = name.strip().lower().removeprefix("*.")
            if name == domain or name.endswith("." + domain):
                names.add(name)
    subdomains = sorted(names)
    return {
        "status": "available",
        "certificates_seen": len(entries),
        "unique_hostnames": len(subdomains),
        "hostnames": subdomains[:CT_MAX_HOSTNAMES],
        "truncated": len(subdomains) > CT_MAX_HOSTNAMES,
        "source": "https://crt.sh",
        "accuracy_note": "Names come from issued certificates; they may be expired, internal, or no longer resolve.",
    }


def fetch_json(url: str, timeout: float = TIMEOUT, max_bytes: int = 1_000_000) -> Any:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise LookupErrorMessage(f"Lookup service returned HTTP {response.status}.")
            raw = response.read(max_bytes + 1)
    except HTTPError as exc:
        raise LookupErrorMessage(f"Lookup service returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError) as exc:
        raise LookupErrorMessage(f"Lookup failed: {exc}") from exc
    if len(raw) > max_bytes:
        raise LookupErrorMessage("Lookup service response is too large.")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LookupErrorMessage(f"Lookup failed: {exc}") from exc


def get_json(url: str) -> dict[str, Any]:
    data = fetch_json(url)
    if not isinstance(data, dict):
        raise LookupErrorMessage("Unexpected response from lookup service.")
    return data


def check_ip(value: str, include_geo: bool = True) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise LookupErrorMessage("Invalid IP address.") from exc
    if not address.is_global:
        raise LookupErrorMessage("Only globally routable public IP addresses can be queried.")

    encoded_ip = quote(str(address), safe="")
    rdap = get_json(f"https://rdap.org/ip/{encoded_ip}")
    try:
        ptr_answers = dns.resolver.resolve(address.reverse_pointer, "PTR", lifetime=TIMEOUT)
        ptr_records: list[str] | dict[str, str] = sorted(str(answer).rstrip(".") for answer in ptr_answers)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        ptr_records = []
    except dns.exception.DNSException as exc:
        ptr_records = {"lookup_error": str(exc)}
    entities = []
    for entity in rdap.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        name = None
        if len(vcard) > 1:
            for field in vcard[1]:
                if len(field) > 3 and field[0] == "fn":
                    name = field[3]
                    break
        if name or roles:
            entities.append({"name": name, "roles": roles})

    result: dict[str, Any] = {
        "input": str(address),
        "version": address.version,
        "reverse_dns_ptr": ptr_records,
        "rdap": {
            "network_name": rdap.get("name"),
            "start_address": rdap.get("startAddress"),
            "end_address": rdap.get("endAddress"),
            "handle": rdap.get("handle"),
            "country": rdap.get("country"),
            "entities": entities,
            "source": "https://rdap.org",
        },
        "scope_note": "RDAP network data does not identify an end user.",
    }

    if include_geo:
        geo = get_json(f"https://ipwho.is/{encoded_ip}")
        if geo.get("success") is False:
            result["geolocation"] = {"status": "unavailable", "message": geo.get("message")}
        else:
            connection = geo.get("connection") or {}
            result["geolocation"] = {
                "status": "available",
                "country": geo.get("country"),
                "region": geo.get("region"),
                "city": geo.get("city"),
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "asn": connection.get("asn"),
                "isp": connection.get("isp"),
                "source": "https://ipwho.is",
                "accuracy_note": "Location data is approximate and may show a VPN or proxy exit point.",
            }
    return result


def check_phone_number(value: str) -> dict[str, Any]:
    """Parse a user-supplied international phone number using offline numbering metadata."""
    try:
        import phonenumbers
    except ImportError as exc:
        raise LookupErrorMessage("Phone module dependency missing; run: python -m pip install -e .") from exc
    number_text = value.strip()
    if not number_text.startswith("+"):
        raise LookupErrorMessage("Use international format with a leading + and country calling code, e.g. +442083661177.")
    try:
        number = phonenumbers.parse(number_text, None)
    except phonenumbers.NumberParseException as exc:
        raise LookupErrorMessage(f"Could not parse phone number: {exc}") from exc
    region = phonenumbers.region_code_for_number(number)
    number_type = phonenumbers.number_type(number)
    type_names = {
        phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
        phonenumbers.PhoneNumberType.MOBILE: "mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
        phonenumbers.PhoneNumberType.VOIP: "voip",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
        phonenumbers.PhoneNumberType.PAGER: "pager",
        phonenumbers.PhoneNumberType.UAN: "uan",
        phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
        phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
    }
    return {
        "input": number_text,
        "international_format": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "e164_format": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
        "country_calling_code": number.country_code,
        "numbering_region": region or "unknown",
        "possible": phonenumbers.is_possible_number(number),
        "valid_numbering_plan_match": phonenumbers.is_valid_number(number),
        "number_type": type_names.get(number_type, "unknown"),
        "scope_note": (
            "Offline numbering-plan metadata only. This does not verify that the number is active, identify its owner, "
            "show its current carrier, or locate a device/person."
        ),
    }


def normalize_discord_id(value: str) -> str:
    match = DISCORD_ID_RE.fullmatch(value.strip())
    if not match:
        raise LookupErrorMessage("Enter a Discord ID, user mention, or discord.com/users/<ID> profile URL.")
    return next(group for group in match.groups() if group is not None)


def check_discord_id(value: str) -> dict[str, Any]:
    discord_id = normalize_discord_id(value)
    snowflake = int(discord_id)
    if snowflake >= 2**64:
        raise LookupErrorMessage("Discord ID is outside the valid Snowflake range.")
    timestamp_part = snowflake >> 22
    created_ms = timestamp_part + DISCORD_EPOCH_MS
    created_at = datetime.fromtimestamp(created_ms / 1000, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    if created_at > now + timedelta(minutes=5):
        raise LookupErrorMessage("Discord ID encodes a timestamp in the future; check the ID.")
    return {
        "discord_id": discord_id,
        "input_format": "mention" if value.strip().startswith("<@") else (
            "profile_url" if "discord.com/users/" in value.lower() else "numeric_id"
        ),
        "account_created_utc": created_at.isoformat(timespec="seconds"),
        "account_created_date_utc": created_at.date().isoformat(),
        "account_age_days": max(0, (now - created_at).days),
        "snowflake_metadata": {
            "timestamp_ms_since_discord_epoch": timestamp_part,
            "worker_id": (snowflake >> 17) & 0x1F,
            "process_id": (snowflake >> 12) & 0x1F,
            "increment": snowflake & 0xFFF,
        },
        "profile_url": f"https://discord.com/users/{discord_id}",
        "official_references": {
            "username_and_display_name_rules": "https://support.discord.com/hc/en-us/articles/12620128861463-New-Usernames-and-Display-Names",
            "data_package_for_account_owner": "https://support.discord.com/hc/en-us/articles/360004957991-Your-Discord-Data-Package",
            "privacy_controls_for_account_owner": "https://support.discord.com/hc/en-us/articles/360004109911-Data-Privacy-Controls",
        },
        "available_framework_checks": [
            {"command": "flmp email <EMAIL>", "checks": "Domain MX, SPF, and DMARC DNS policy"},
            {"command": "flmp domain <DOMAIN>", "checks": "Public A, AAAA, MX, NS, TXT, CAA, and SOA records"},
            {"command": "flmp ip <PUBLIC-IP>", "checks": "RDAP, reverse DNS PTR, and optional approximate geolocation"},
            {"command": "flmp username <HANDLE>", "checks": "Local Discord username format only"},
            {"command": "flmp phone <+NUMBER>", "checks": "Offline numbering-plan metadata only"},
        ],
        "scope_note": (
            "Snowflake fields are technical ID metadata and do not verify an active account or identify "
            "a person. Discord IDs do not reveal private email addresses, IP addresses, messages, or server membership."
        ),
    }


def check_discord_username(value: str) -> dict[str, Any]:
    """Check the shape of a user-supplied Discord handle locally; do not search for accounts."""
    supplied = value.strip()
    candidate = supplied[1:] if supplied.startswith("@") else supplied
    normalized = candidate.lower()
    issues: list[str] = []
    if not 2 <= len(candidate) <= 32:
        issues.append("Username length must be between 2 and 32 characters.")
    if not DISCORD_USERNAME_RE.fullmatch(normalized):
        issues.append("Use Latin letters, numbers, periods, and underscores only.")
    if ".." in normalized:
        issues.append("Two consecutive periods are not allowed.")
    return {
        "input": supplied,
        "normalized_handle": normalized,
        "length": len(candidate),
        "allowed_characters": bool(DISCORD_USERNAME_RE.fullmatch(normalized)),
        "has_consecutive_periods": ".." in normalized,
        "format_status": "plausible" if not issues else "invalid",
        "format_issues": issues,
        "availability": "not checked",
        "account_matches": [],
        "scope_note": (
            "Local format check only. No Discord request, username search, cross-platform matching, "
            "or real-name lookup was performed."
        ),
    }


def check_discord_display_name(value: str) -> dict[str, Any]:
    """Check a supplied Discord display name locally; never resolve it to an account."""
    supplied = value
    normalized = unicodedata.normalize("NFC", supplied.strip())
    issues: list[str] = []
    if not 1 <= len(normalized) <= 32:
        issues.append("Display name must contain 1–32 characters.")
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        issues.append("Display name contains a control character.")
    return {
        "input": supplied,
        "normalized_display_name": normalized,
        "length": len(normalized),
        "format_status": "within_basic_limits" if not issues else "review",
        "format_issues": issues,
        "account_lookup": "not performed",
        "official_reference": "https://support.discord.com/hc/en-us/articles/12620128861463-New-Usernames-and-Display-Names",
        "scope_note": "Local display-name formatting only. No account search, identity matching, or external request was made.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="plbct",
        description="Check user-supplied email addresses, domains, public IPs, or a Discord ID.",
    )
    parser.add_argument("-find", dest="discord_id", metavar="DISCORD_INPUT", help="analyze an ID, mention, or profile URL")
    subparsers = parser.add_subparsers(dest="command")
    email_parser = subparsers.add_parser("email", help="check email format and domain MX records")
    email_parser.add_argument("address")
    domain_parser = subparsers.add_parser("domain", help="check public DNS records for a domain")
    domain_parser.add_argument("address")
    ip_parser = subparsers.add_parser("ip", help="query RDAP and optional public geolocation metadata")
    ip_parser.add_argument("address")
    ip_parser.add_argument("--no-geo", action="store_true", help="do not query ipwho.is for geolocation")
    phone_parser = subparsers.add_parser("phone", help="parse international number using local numbering metadata")
    phone_parser.add_argument("number", help="international number beginning with +")
    args = parser.parse_args()

    try:
        if args.discord_id:
            result = check_discord_id(args.discord_id)
        elif args.command == "email":
            result = check_email(args.address)
        elif args.command == "domain":
            result = check_domain(args.address)
        elif args.command == "ip":
            result = check_ip(args.address, not args.no_geo)
        elif args.command == "phone":
            result = check_phone_number(args.number)
        else:
            parser.error("Command required: -find DISCORD_ID, email ADDRESS, domain NAME, ip ADDRESS, or phone NUMBER")
    except LookupErrorMessage as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
