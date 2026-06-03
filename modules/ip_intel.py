# ─────────────────────────────────────────────────────────────
#  modules/ip_intel.py  —  IP Address Intelligence Module
#
#  WHAT IT COLLECTS:
#
#  Layer 1 — ipinfo.io API (free: 50,000 req/month):
#    • Country, region/state, city
#    • Exact latitude & longitude coordinates
#    • Timezone
#    • ISP name (who owns this IP?)
#    • ASN — Autonomous System Number (network block owner)
#    • Hostname (reverse DNS)
#    • VPN / proxy / Tor detection (paid feature, graceful skip)
#
#  Layer 2 — ip-api.com (completely free, no key needed):
#    • Second source to cross-verify location
#    • ISP, org, mobile/proxy/hosting flags
#    • More detailed region info
#
#  Layer 3 — Logic (no API):
#    • Private IP detection (192.168.x.x, 10.x.x.x etc.)
#    • Loopback detection (127.0.0.1)
#    • Google Maps link from coordinates
#    • Shodan search link for open ports
#
#  WHAT IS NOT POSSIBLE:
#    ✗ Exact street address — IPs only resolve to city level
#    ✗ Who is currently using the IP — ISP knows, not public
#    ✗ Real-time device tracking
# ─────────────────────────────────────────────────────────────

import requests          # HTTP requests to APIs
import ipaddress         # built-in Python lib to validate/classify IPs
from urllib.parse import quote   # URL-encode for search links

from utils.config import get_key
from utils.logger import (
    log_module, log_result, log_link,
    log_success, log_warning, log_error, log_info,
    print_summary_panel,
)


# ── PRIVATE / SPECIAL IP RANGES ──────────────────────────────
# These are IP addresses that belong to private networks,
# loopback, or reserved ranges — they are never on the public
# internet and cannot be geolocated.

def classify_ip(ip_str: str) -> str | None:
    """
    Returns a string describing why the IP is special,
    or None if it's a normal public IP.

    ipaddress.ip_address() parses the string into an object
    that has properties like .is_private, .is_loopback etc.
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip.is_loopback:
            # 127.0.0.1 — your own machine talking to itself
            return "loopback (127.x.x.x) — this is your own machine"

        if ip.is_private:
            # 192.168.x.x, 10.x.x.x, 172.16-31.x.x
            # These are LAN addresses, not routable on the internet
            return (
                f"private/LAN address — not reachable from the internet.\n"
                f"   Common ranges: 192.168.x.x (home), 10.x.x.x (corporate)"
            )

        if ip.is_link_local:
            # 169.254.x.x — assigned when DHCP fails
            return "link-local address (169.254.x.x) — not internet routable"

        if ip.is_multicast:
            # 224.x.x.x — broadcast addresses
            return "multicast address — not a real host"

        if ip.is_reserved:
            return "reserved/special-use address"

        return None   # it's a normal public IP, proceed with lookup

    except ValueError:
        # ipaddress.ip_address() raises ValueError for invalid input
        return "invalid — not a recognisable IPv4 or IPv6 address"


# ── LAYER 1: ipinfo.io API ────────────────────────────────────
# ipinfo.io is the most reliable free IP intelligence API.
# Returns: city, region, country, coordinates, org, timezone
# Free tier: 50,000 requests/month — no credit card needed
# Get key at: ipinfo.io/signup

def _query_ipinfo(ip: str, api_key: str) -> dict:
    """
    Calls ipinfo.io API for the given IP.
    Returns parsed dict of results or {} on failure.
    """
    try:
        log_info("Querying ipinfo.io...")

        # The URL format: https://ipinfo.io/{ip}/json?token={key}
        # If no key is given, ipinfo still works but with a lower
        # rate limit (no key = 1000 req/day)
        url = f"https://ipinfo.io/{ip}/json"
        params = {}
        if api_key:
            params["token"] = api_key

        response = requests.get(url, params=params, timeout=8)

        # status_code 200 = success, anything else = problem
        if response.status_code != 200:
            log_warning(f"ipinfo.io returned status {response.status_code}")
            return {}

        data = response.json()

        # ipinfo returns coordinates as a single string "lat,lon"
        # We split it into separate values for easier use
        lat, lon = None, None
        if "loc" in data:
            # "loc": "12.9716,77.5946"  →  split on comma
            parts = data["loc"].split(",")
            if len(parts) == 2:
                lat = parts[0].strip()   # "12.9716"
                lon = parts[1].strip()   # "77.5946"

        # org field comes as "AS13335 Cloudflare, Inc."
        # We split it into ASN and org name
        asn, org_name = None, None
        if "org" in data:
            org_parts = data["org"].split(" ", 1)   # split on FIRST space only
            asn      = org_parts[0] if len(org_parts) > 0 else None
            org_name = org_parts[1] if len(org_parts) > 1 else data["org"]

        return {
            "source":   "ipinfo.io",
            "ip":       data.get("ip"),
            "hostname": data.get("hostname", "N/A"),
            "city":     data.get("city",     "Unknown"),
            "region":   data.get("region",   "Unknown"),
            "country":  data.get("country",  "Unknown"),
            "postal":   data.get("postal",   "N/A"),
            "timezone": data.get("timezone", "Unknown"),
            "lat":      lat,
            "lon":      lon,
            "asn":      asn,
            "org":      org_name,
        }

    except requests.exceptions.Timeout:
        log_warning("ipinfo.io timed out.")
        return {}
    except requests.exceptions.ConnectionError:
        log_warning("ipinfo.io: no internet connection.")
        return {}
    except Exception as e:
        log_warning(f"ipinfo.io error: {e}")
        return {}


# ── LAYER 2: ip-api.com (no key needed) ──────────────────────
# A completely free backup source — no API key required at all.
# Rate limit: 45 requests/minute on the free endpoint.
# Good for cross-checking and getting mobile/proxy/hosting flags.

def _query_ipapi(ip: str) -> dict:
    """
    Calls ip-api.com for the given IP.
    This API is completely free — no key needed.
    Returns parsed dict or {} on failure.
    """
    try:
        log_info("Querying ip-api.com (no key needed)...")

        # fields= parameter specifies which fields we want back.
        # This makes the response smaller and faster.
        url = f"http://ip-api.com/json/{ip}"
        params = {
            "fields": (
                "status,message,country,countryCode,region,"
                "regionName,city,zip,lat,lon,timezone,"
                "isp,org,as,hosting,proxy,mobile,query"
            )
        }

        response = requests.get(url, params=params, timeout=8)
        data = response.json()

        # ip-api returns "status": "success" or "status": "fail"
        if data.get("status") != "success":
            log_warning(f"ip-api.com: {data.get('message', 'failed')}")
            return {}

        return {
            "source":       "ip-api.com",
            "ip":           data.get("query"),
            "city":         data.get("city",       "Unknown"),
            "region":       data.get("regionName", "Unknown"),
            "region_code":  data.get("region",     ""),
            "country":      data.get("country",    "Unknown"),
            "country_code": data.get("countryCode",""),
            "zip":          data.get("zip",        "N/A"),
            "timezone":     data.get("timezone",   "Unknown"),
            "lat":          str(data.get("lat",    "")),
            "lon":          str(data.get("lon",    "")),
            "isp":          data.get("isp",        "Unknown"),
            "org":          data.get("org",        "Unknown"),
            "asn":          data.get("as",         "Unknown"),
            # Boolean flags — True/False
            "is_mobile":    data.get("mobile",   False),
            "is_proxy":     data.get("proxy",    False),
            "is_hosting":   data.get("hosting",  False),
        }

    except requests.exceptions.Timeout:
        log_warning("ip-api.com timed out.")
        return {}
    except Exception as e:
        log_warning(f"ip-api.com error: {e}")
        return {}


# ── LAYER 3: SEARCH & MAP LINKS ───────────────────────────────
# Build ready-to-open URLs for manual investigation.
# Google Maps uses lat,lon to show the location.
# Shodan shows what ports/services are open on this IP.

def _build_links(ip: str, lat: str, lon: str) -> dict:
    """Generate OSINT search links for the IP."""
    links = {
        "shodan":       f"https://www.shodan.io/host/{ip}",
        "censys":       f"https://search.censys.io/hosts/{ip}",
        "virustotal":   f"https://www.virustotal.com/gui/ip-address/{ip}",
        "abuseipdb":    f"https://www.abuseipdb.com/check/{ip}",
        "threatintel":  f"https://threatintelligenceplatform.com/ip/{ip}",
    }
    # Only add Google Maps link if we have coordinates
    if lat and lon:
        links["google_maps"] = (
            f"https://www.google.com/maps?q={lat},{lon}"
        )
        links["google_maps_satellite"] = (
            f"https://www.google.com/maps/@{lat},{lon},14z/data=!3m1!1e3"
        )
    return links


# ── MAIN FUNCTION ────────────────────────────────────────────
# Called by main.py:
#   result = lookup_ip("8.8.8.8", config)

def lookup_ip(ip_str: str, config: dict) -> dict:

    log_module("IP Intel")
    log_info(f"Target IP: {ip_str}")

    # ── Step 1: Validate the IP ───────────────────────────────
    # classify_ip() returns None for valid public IPs,
    # or a string explaining why it's special/invalid.

    classification = classify_ip(ip_str)
    if classification:
        log_error(f"Cannot look up this IP: {classification}")
        return {}

    log_success(f"Valid public IP address: {ip_str}")


    # ── Step 2: Query both APIs ───────────────────────────────
    ipinfo_key = get_key(config, "IPINFO_KEY")

    # Run both API queries
    ipinfo_data = _query_ipinfo(ip_str, ipinfo_key)
    ipapi_data  = _query_ipapi(ip_str)

    # If both failed, nothing to return
    if not ipinfo_data and not ipapi_data:
        log_error("Both IP APIs failed. Check your internet connection.")
        return {}


    # ── Step 3: Merge results ─────────────────────────────────
    # We prefer ipinfo.io data (more reliable) but fall back
    # to ip-api.com for fields that ipinfo didn't return.
    #
    # The "or" operator: A or B returns A if A is truthy,
    # otherwise returns B. So ipinfo_data.get(...) or ipapi_data.get(...)
    # gives us ipinfo's value if it exists, else ip-api's value.

    primary   = ipinfo_data if ipinfo_data else ipapi_data
    secondary = ipapi_data  if ipinfo_data else {}

    lat = primary.get("lat") or secondary.get("lat")
    lon = primary.get("lon") or secondary.get("lon")

    result = {
        "input":    ip_str,
        "ip":       primary.get("ip",       ip_str),
        "hostname": primary.get("hostname", "N/A"),

        # Location
        "city":     primary.get("city",     "Unknown"),
        "region":   primary.get("region",   "Unknown"),
        "country":  primary.get("country",  "Unknown"),
        "timezone": primary.get("timezone", "Unknown"),
        "postal":   primary.get("postal")   or secondary.get("zip", "N/A"),

        # Coordinates
        "latitude":  lat,
        "longitude": lon,
        "coordinates": f"{lat}, {lon}" if lat and lon else "N/A",

        # Network
        "isp":      primary.get("isp")  or primary.get("org",  "Unknown"),
        "org":      primary.get("org")  or secondary.get("org", "Unknown"),
        "asn":      primary.get("asn")  or secondary.get("asn", "Unknown"),

        # Threat flags (from ip-api.com)
        "is_mobile":  ipapi_data.get("is_mobile",  False),
        "is_proxy":   ipapi_data.get("is_proxy",   False),
        "is_hosting": ipapi_data.get("is_hosting", False),

        # Data sources used
        "sources": [
            s for s in ["ipinfo.io", "ip-api.com"]
            if (s == "ipinfo.io" and ipinfo_data)
            or (s == "ip-api.com" and ipapi_data)
        ],
    }


    # ── Step 4: Print findings to terminal ────────────────────

    log_success(f"Location resolved: {result['city']}, {result['region']}, {result['country']}")

    log_result("IP Address",     result["ip"])
    log_result("Hostname",       result["hostname"])
    log_result("City",           result["city"])
    log_result("Region / State", result["region"])
    log_result("Country",        result["country"])
    log_result("Postal code",    result["postal"])
    log_result("Timezone",       result["timezone"])
    log_result("Coordinates",    result["coordinates"])
    log_result("ISP",            result["isp"])
    log_result("Organisation",   result["org"])
    log_result("ASN",            result["asn"])

    # Threat flags — show with colour indicators
    flags = []
    if result["is_proxy"]:   flags.append("⚠  Proxy/VPN detected")
    if result["is_hosting"]: flags.append("⚠  Hosting/datacenter IP")
    if result["is_mobile"]:  flags.append("ℹ  Mobile network")
    if not flags:            flags.append("✔  No proxy/VPN/hosting flags")

    for flag in flags:
        log_result("Flags", flag)


    # ── Step 5: Build OSINT links ─────────────────────────────
    links = _build_links(ip_str, lat, lon)
    result["links"] = links

    log_info("OSINT investigation links:")
    log_link("Google Maps",   links.get("google_maps", "N/A (no coordinates)"))
    log_link("Shodan",        links["shodan"])
    log_link("VirusTotal",    links["virustotal"])
    log_link("AbuseIPDB",     links["abuseipdb"])


    # ── Step 6: Summary panel ─────────────────────────────────
    summary_rows = [
        ("IP Address",       result["ip"]),
        ("Hostname",         result["hostname"]),
        ("",                 ""),

        ("City",             result["city"]),
        ("Region / State",   result["region"]),
        ("Country",          result["country"]),
        ("Postal code",      result["postal"]),
        ("Timezone",         result["timezone"]),
        ("Coordinates",      result["coordinates"]),
        ("",                 ""),

        ("ISP",              result["isp"]),
        ("Organisation",     result["org"]),
        ("ASN",              result["asn"]),
        ("",                 ""),

        ("Proxy / VPN",      "YES ⚠" if result["is_proxy"]   else "No"),
        ("Hosting / DC",     "YES ⚠" if result["is_hosting"] else "No"),
        ("Mobile network",   "Yes"   if result["is_mobile"]  else "No"),
        ("",                 ""),

        ("Google Maps",      links.get("google_maps", "N/A")),
        ("Shodan",           links["shodan"]),
        ("VirusTotal",       links["virustotal"]),
        ("AbuseIPDB",        links["abuseipdb"]),

        ("",                 ""),
        ("Data sources",     " + ".join(result["sources"])),
    ]

    print_summary_panel("IP Intel Report", summary_rows, color="blue")

    return result
