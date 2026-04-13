# Ultimate OSINT CLI

Passive intelligence gathering tool. **Zero direct requests to the target.**

All lookups go through third-party APIs, public databases, and cached sources.

---

## Features

| Command | What it does |
|---------|-------------|
| `osint domain <target>` | WHOIS · DNS · crt.sh subdomains · Wayback Machine · IP geo · Shodan · VirusTotal · Hunter.io · URLScan.io |
| `osint phone <+number>` | Format parsing · country/carrier detection · NumVerify · AbstractAPI · OpenCNAM |
| `osint username <handle>` | Hunt across 35+ platforms (GitHub, Instagram, Reddit, TikTok, Steam, Telegram…) |
| `osint person <first> <last>` | Search dorks · username variants · Gravatar permutations · Dehashed breach data |
| `osint breach <email>` | HaveIBeenPwned breaches + pastes |
| `osint full <domain>` | All of the above in one sweep |

---

## Installation

```bash
git clone https://github.com/nix-ia/ultimate-osint.git
cd ultimate-osint

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# edit .env and add your API keys
```

---

## Usage

```bash
# Domain / URL (passive only — never touches the target)
python osint.py domain example.com
python osint.py domain https://example.com/some/path

# Phone (include country code)
python osint.py phone +33612345678
python osint.py phone +14155552671

# Username hunt
python osint.py username johndoe
python osint.py username johndoe --workers 30

# Person (first + last name)
python osint.py person John Doe

# Email breach check
python osint.py breach john.doe@example.com

# Full sweep
python osint.py full example.com \
  --username johndoe \
  --first John --last Doe \
  --phone +33612345678 \
  --email john.doe@example.com
```

---

## API Keys (all optional)

Set them in `.env`:

| Variable | Service | Free tier |
|----------|---------|-----------|
| `SHODAN_API_KEY` | [shodan.io](https://shodan.io) | Free (limited) |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://virustotal.com) | Free (500 req/day) |
| `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io) | Free |
| `HUNTER_API_KEY` | [hunter.io](https://hunter.io) | Free (25 req/month) |
| `NUMVERIFY_API_KEY` | [numverify.com](https://numverify.com) | Free (100 req/month) |
| `ABSTRACTAPI_PHONE_KEY` | [abstractapi.com](https://app.abstractapi.com/api/phone-validation) | Free (250 req/month) |
| `HIBP_API_KEY` | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) | $3.50/month |
| `DEHASHED_API_KEY` + `DEHASHED_EMAIL` | [dehashed.com](https://dehashed.com) | Paid |

The tool works without any keys — the API modules are skipped gracefully.

---

## What is "passive"?

Passive OSINT means the target never receives a request from you:

- **Domain/URL** — WHOIS queries go to registrar servers, DNS queries go to `8.8.8.8`/`1.1.1.1`, subdomains come from `crt.sh`, page history from `archive.org`, IP data from `ip-api.com`. The target web server is never contacted.
- **Phone** — number parsing is done locally by the `phonenumbers` library. API calls go to NumVerify/AbstractAPI, not the carrier.
- **Username** — profile URLs on each platform are checked (e.g. `github.com/username`), not anything the target controls.
- **Person** — generates dork URLs for your browser and checks Gravatar hashes. No direct database of the target is queried without opt-in APIs.

---

## Legal notice

This tool is intended for **authorized security research, CTF competitions, and defensive use** only. Always ensure you have legal authorization before investigating any target. Misuse is your own responsibility.
