# 🔍 OSINT Intelligence Tool

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Education](https://img.shields.io/badge/Purpose-Educational-orange?style=for-the-badge)

**A comprehensive OSINT (Open Source Intelligence) tool built for ethical cybersecurity research.**


</div>

---

## ⚠️ Ethical Disclaimer

> This tool is built **strictly for educational and ethical research purposes**.
> Only investigate phone numbers, emails, IPs, and usernames that **you own**
> or have **explicit written consent** to investigate.
> Unauthorized use may violate the **IT Act 2000 (India)** and similar
> cybercrime laws in other jurisdictions. The author accepts no liability for misuse.

---

## 📸 Demo

```
╭──────── OSINT Intelligence Tool — v1.0 ────────╮
│  1   Phone Number Lookup    ✔  ready            │
│  2   IP Address Lookup      ✔  ready            │
│  3   Email Intel            ✔  ready            │
│  4   Social Media Mapper    ✔  ready            │
│  5   Image OSINT + Steg     ✔  ready            │
│  6   Generate PDF Report    ✔  ready            │
│                                                  │
│  0   Exit                                        │
╰──────────────────────────────────────────────────╯
```

---

## ✨ Features

### 📞 Module 1 — Phone Number Intelligence
- Country, region/state, carrier name detection (offline)
- Line type: Mobile / Landline / VOIP / Toll-free
- Timezone(s) from number prefix
- All standard formats: E164, International, National
- WhatsApp likelihood detection
- NumVerify API enrichment (carrier confirmation, location)
- Auto-generated Google, Truecaller, Sync.me, WhatsApp search links

### 🌐 Module 2 — IP Address Intelligence
- Dual-source lookup: ipinfo.io + ip-api.com (cross-verified)
- City, region, country, postal code
- **Exact GPS coordinates** (latitude & longitude)
- Timezone, ISP, ASN (Autonomous System Number)
- Hostname (reverse DNS)
- VPN / Proxy / Tor exit node detection
- Hosting/datacenter IP flagging
- Google Maps + Shodan + VirusTotal + AbuseIPDB links

### 📧 Module 3 — Email Intelligence
- Format validation with regex
- Disposable email detection (50+ known providers)
- DNS MX record lookup (can this domain receive email?)
- AbstractAPI: SMTP deliverability, quality score, catchall detection
- HaveIBeenPwned breach check (which breaches, what data exposed)
- Pastebin, LinkedIn, Google search links

### 🔍 Module 4 — Social Media Mapper
- **Async username search across 50+ platforms simultaneously**
- Platforms: GitHub, Reddit, Instagram, Twitter, LinkedIn,
  YouTube, TikTok, Telegram, Pinterest, Medium, Steam + more
- HTTP status + response time per platform
- Profile avatar URL extraction for fingerprinting
- Results in ~3-5 seconds (async vs 50s synchronous)

### 🖼️ Module 5 — Image OSINT + Steganography
**EXIF Metadata Extraction:**
- Camera make & model, lens model, serial number
- **Exact GPS coordinates + Google Maps / Satellite / OSM links**
- Date & time photo was taken (with timezone offset)
- ISO, shutter speed, aperture, focal length, flash
- Software / OS / firmware version (e.g. Android 13)
- Artist/owner tag, copyright, image unique ID

**Steganography Detection:**
- LSB (Least Significant Bit) statistical analysis
- File size compression ratio anomaly detection
- steghide integration (hidden data check)
- zsteg integration (PNG analysis)
- binwalk integration (embedded file detection)

**Perceptual Hashing (Avatar Fingerprinting):**
- pHash, aHash, dHash, wHash computation
- Compare two images — Hamming distance < 10 = same person
- MD5 + SHA1 file fingerprinting

**Reverse Image Search:**
- Auto-generated Google Lens, TinEye, Yandex, Bing links

### 📄 Module 6 — PDF Report Generator
- Professional cover page with target info and scan summary
- Separate section per module (phone, IP, email, social, image)
- Teal header + page numbers on every page
- Ethical disclaimer footer
- All OSINT links included
- Auto-loads all JSON scan files from output/ folder

---

## 🗂️ Project Structure

```
osint-tool/
├── main.py                    # Interactive menu (while True loop)
├── requirements.txt           # All Python dependencies
├── setup.py                   # Package installer
├── .env.example               # API key template (copy to .env)
├── .gitignore                 # Excludes secrets and output
│
├── utils/
│   ├── __init__.py
│   ├── config.py              # .env loader + API key validator
│   └── logger.py              # Coloured terminal output + banner
│
├── modules/
│   ├── __init__.py
│   ├── phone_lookup.py        # Phase 1 — Phone intelligence
│   ├── ip_intel.py            # Phase 2 — IP geolocation
│   ├── email_intel.py         # Phase 3 — Email analysis
│   ├── social_mapper.py       # Phase 4 — Username search
│   ├── avatar_fingerprint.py  # Phase 5 — Image OSINT + steg
│   └── report_generator.py    # Phase 6 — PDF report
│
├── data/
│   └── platforms.json         # 50+ social platform URL templates
│
├── tests/
│   ├── __init__.py
│   ├── test_phone.py          # Unit tests — phone module
│   └── test_ip.py             # Unit tests — IP module
│
├── output/                    # Scan results saved here (gitignored)
│   ├── scan_phone_*.json
│   ├── scan_ip_*.json
│   ├── scan_email_*.json
│   ├── scan_username_*.json
│   ├── scan_image_*.json
│   └── OSINT_Report_*.pdf
│
└── docs/
    └── USAGE.md               # Detailed usage guide
```

---

## 🚀 Installation

### Prerequisites
- Kali Linux (recommended) or any Linux/macOS
- Python 3.10 or higher
- pip (Python package manager)

### Step 1 — Clone the repository
```bash
git clone https://github.com/nandish123-tech/osint-tool.git
cd osint-tool
```

### Step 2 — Create virtual environment
```bash
python -m venv venv
source venv/bin/activate       # Linux/macOS
# venv\Scripts\activate        # Windows
```

### Step 3 — Install Python dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Install system tools (Kali Linux)
```bash
# Steganography tools
sudo apt install steghide binwalk -y

# zsteg (requires Ruby)
sudo apt install ruby -y
gem install zsteg
```

### Step 5 — Configure API keys
```bash
cp .env.example .env
nano .env
```

Fill in your keys (only NUMVERIFY and IPINFO needed to start):
```
NUMVERIFY_KEY=your_key_here    # numverify.com — free
IPINFO_KEY=your_key_here       # ipinfo.io — free
ABSTRACT_KEY=your_key_here     # abstractapi.com — free
HIBP_KEY=your_key_here         # haveibeenpwned.com — optional
```

### Step 6 — Run!
```bash
python main.py
```

---

## 🎯 Usage Examples

### Phone Number Lookup
```
Select option: 1
Enter phone number: +919876543210

Output:
  Country:   India (IN)
  Carrier:   Airtel
  Line type: Mobile
  Timezone:  Asia/Kolkata
  WhatsApp:  Likely
  Google:    https://google.com/search?q=...
  Truecaller: https://truecaller.com/search/in/...
```

### IP Address Lookup
```
Select option: 2
Enter IP address: 8.8.8.8

Output:
  City:       Mountain View
  Region:     California
  Country:    United States
  Coords:     37.386051, -122.083855
  ISP:        Google LLC
  ASN:        AS15169
  Proxy/VPN:  No
  Google Maps: https://maps.google.com/...
  Shodan:     https://shodan.io/host/8.8.8.8
```

### Generate PDF Report
```
Select option: 6
Enter report label: investigation_001

Output:
  ✔ PDF created → output/OSINT_Report_investigation_001_2024.pdf
```

---

## 🔑 API Keys — Where to Get Them Free

| Service | URL | Free Tier | Used For |
|---|---|---|---|
| NumVerify | numverify.com | 100 req/month | Phone carrier + line type |
| IPInfo | ipinfo.io | 50,000 req/month | IP geolocation + ASN |
| AbstractAPI | abstractapi.com | 100 req/month | Email validation + SMTP |
| HaveIBeenPwned | haveibeenpwned.com | ~$3.50/month | Email breach check |
| WhoisXML | whoisxmlapi.com | 500 req/month | Domain WHOIS |

> **Note:** The tool works without most API keys.
> `phonenumbers` library runs fully offline for phone data.
> `ip-api.com` is completely free with no key for IP lookups.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11 |
| Terminal UI | Rich |
| HTTP requests | requests + aiohttp (async) |
| Phone parsing | phonenumbers |
| DNS lookups | dnspython |
| Image analysis | Pillow + imagehash |
| Steganography | steghide + zsteg + binwalk |
| PDF generation | ReportLab |
| Environment | python-dotenv |
| Testing | pytest |

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 📚 What I Learned Building This

- **OSINT methodology** — passive intelligence gathering from public sources
- **Async programming** — `asyncio` + `aiohttp` for parallel requests
- **REST API integration** — HTTP requests, authentication, error handling
- **EXIF metadata** — how cameras embed hidden data in images
- **Steganography** — LSB analysis, binwalk, steghide
- **Perceptual hashing** — DCT-based image fingerprinting
- **DNS protocol** — MX records, A records, NXDOMAIN
- **PDF generation** — ReportLab canvas and flowable elements
- **Python packaging** — modules, imports, virtual environments
- **Security best practices** — .env files, .gitignore, API key management

---

## ⚖️ Legal & Ethics

This tool collects data **only from publicly available sources**:
- Public DNS records
- Public carrier databases
- Public social media profile URLs (existence check only)
- Published breach databases (HIBP)
- Publicly available WHOIS data

**It does NOT:**
- Access private user data
- Bypass authentication
- Scrape content behind login walls
- Store or transmit data to third parties

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

Y S Nandish
BE Cybersecurity 
Built on Kali Linux | June 2026

---

<div align="center">
<i>Built with ❤️ for learning. Use responsibly.</i>
</div>
