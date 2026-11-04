# FLMP Sentinel

Made by plbct0 and **sauceyC4**.

A local command-line toolkit for authorized FiveM server checks and user-provided OSINT indicators.

## Features

- Nmap TCP connect scans with light service detection and a PowerShell progress bar.
- Fixed, read-only Nmap info scripts: `ssl-cert`, `http-title`, and `http-headers`.
- Local, read-only FiveM `server.cfg` baseline audit.
- Email format and public MX, SPF, and DMARC DNS checks. This does not verify mailbox existence or ownership.
- Email reports link to the Mail OSINT Framework directory for manual follow-up; FLMP does not submit the address to those external tools.
- Public domain A, AAAA, MX, NS, TXT, CAA, and SOA record checks (queried in parallel), plus RDAP registry data: registrar, registration/expiry dates, and registry status. Registrant contacts are not queried.
- Optional subdomain discovery from public Certificate Transparency logs via crt.sh (`flmp domain example.org --ct`). Names may be expired or internal and are not resolved.
- Scan web checks report the TLS certificate (CN, issuer, SANs, expiry), warn when it expires within 21 days, and list missing browser security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS on HTTPS) on ports 80, 443, and 40120.
- Public IP RDAP, reverse DNS PTR, and optional approximate geolocation lookups.
- Discord Snowflake timestamp, account-age estimate, and profile metadata from a numeric ID, user mention, or profile URL. This does not identify a person or reveal private email, IP, messages, or server membership.
- Discord username format check from the terminal menu or `flmp username`; it runs locally and does not search Discord or other platforms.
- Discord display-name format check from the terminal menu or `flmp display-name`; it runs locally and does not search for matching accounts.
- Discord reports include official username rules and account-owner privacy/data-export pages for manual self-review.
- Phone number parsing from international `+` format using offline numbering-plan metadata. It does not identify the owner, active carrier, or device location.
- Single-artifact lookup in the dashboard: it auto-detects an email, domain, public IP, international phone, Discord ID, or Discord username and runs the matching public checks.
- Relationship view for returned public attributes, plus one-click JSON report export.
- Local 3D-style browser dashboard, bound to `127.0.0.1`.

The tool does not run exploit or password tests, and it does not scan UDP ports. Domain lookups query public DNS and rdap.org, and `--ct` also queries crt.sh. IP lookups query RDAP and DNS PTR; unless `--no-geo` is used, they also send the address to ipwho.is. Phone and username checks run locally. Use inputs you are authorized to check.

## Install on Windows PowerShell

```powershell
Set-Location C:\Users\disof\Documents\osint
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Nmap must be installed and available on `PATH` for Nmap scans. The project also installs `plbct` as a compatibility alias, while `flmp` is the combined app.

## Start the app

Run `flmp` with no arguments to open the interactive terminal menu:

```powershell
flmp
```

Menu options include quick/custom TCP scans, a local config audit, the dashboard, email DNS policy, public domain and IP metadata, Discord Snowflake and username format checks, and offline phone number metadata. The dashboard combines these lookups with the server scan, shows public-attribute relationships, and exports reports as JSON.

When `flmp` starts in an interactive terminal, it briefly shows the logo and a green ASCII rendering of the supplied image with a short startup animation, then clears the splash before displaying the menu.

## Commands

```powershell
flmp scan 203.0.113.10 --ports "80,443,30120,40120"
flmp scan 203.0.113.10 --ports 1-1024
flmp audit-config "C:\FiveM\server-data\server.cfg"
flmp email someone@example.org
flmp domain example.org
flmp domain example.org --ct
flmp ip 8.8.8.8
flmp ip 8.8.8.8 --no-geo
flmp phone +442083661177
flmp discord 123456789012345678
flmp discord "<@123456789012345678>"
flmp discord https://discord.com/users/123456789012345678
flmp discord
flmp discord 123456789012345678 --json
flmp username sample_user
flmp display-name "Sample Display Name"
flmp dashboard
```

The interactive menu also has Discord username and display-name format options and a phone intelligence option. Name checks run locally; username availability, account identity, and cross-platform matching are not checked. Discord account-owner links point to Discord's own rules and self-service data/privacy controls. Phone metadata is parsed offline and reflects a numbering plan, not a subscriber or device location. Add `--json` to the email, domain, IP, phone, Discord, username, or display-name command for raw JSON.

`flmp scan` uses Nmap with TCP connect scan, light version detection, timing profile T2, and only the three listed info scripts. The script output and service banners are clues for review, not proof of a vulnerability. A scan is limited to 1,024 selected TCP ports per run.

`flmp dashboard` starts the local interface at `http://127.0.0.1:8765`. The browser form requires an authorization confirmation before running a scan. The dashboard only accepts JSON requests whose `Host`/`Origin` is the local dashboard itself, so other websites cannot trigger lookups or scans. In the lookup field, prefix a handle with `@` (e.g. `@max.power`) to force a username check instead of domain detection.

## Tests

The tests run offline (no DNS, RDAP, or Nmap requests):

```powershell
python -m unittest discover -s tests -v
```
