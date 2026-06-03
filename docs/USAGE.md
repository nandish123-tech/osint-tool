# OSINT Tool — Detailed Usage Guide

## Quick Start

```bash
cd osint-tool
source venv/bin/activate
python main.py
```

## Module Guide

### Module 1: Phone Lookup
- Always include country code: `+91` for India, `+1` for USA
- Works 100% offline without any API key
- NUMVERIFY_KEY adds carrier confirmation and location string
- Output saved to `output/scan_phone_*.json`

### Module 2: IP Lookup
- Only works with PUBLIC IPs (not 192.168.x.x or 10.x.x.x)
- ip-api.com is used as free fallback (no key needed)
- IPINFO_KEY adds hostname and more precise org data
- Try: 8.8.8.8 (Google), 1.1.1.1 (Cloudflare) for testing

### Module 3: Email Intel
- Works without any API key (format + DNS check)
- ABSTRACT_KEY adds SMTP deliverability check
- HIBP_KEY adds data breach history
- Test with your own email first

### Module 4: Social Mapper
- Do NOT include @ symbol in username
- Checks 50+ platforms simultaneously (~3-5 seconds)
- HTTP 403 results mean "possibly exists but blocks bots"
- Test with a common username like "johndoe"

### Module 5: Image OSINT
- Test with a real phone photo for EXIF data
- Web images / screenshots have no EXIF (normal)
- steghide/zsteg/binwalk are optional but recommended
- Works with local file path or direct image URL

### Module 6: Generate Report
- Run scans 1-5 first to have data
- All JSON files in output/ are automatically included
- PDF opens with: `evince output/OSINT_Report_*.pdf`
- Or: `xdg-open output/OSINT_Report_*.pdf`

## Troubleshooting

**"No module named X"**
```bash
pip install -r requirements.txt
```

**"NUMVERIFY_KEY not set"**
```bash
nano .env   # add your key
```

**"IP lookup failed"**
- Check it's a public IP
- Private: 192.168.x.x, 10.x.x.x, 172.16-31.x.x

**"No EXIF data"**
- Normal for web/blog/screenshot images
- Test with a photo taken by your phone camera
- WhatsApp-shared photos often preserve EXIF

**steghide not found**
```bash
sudo apt install steghide
```

**zsteg not found**
```bash
gem install zsteg
```
