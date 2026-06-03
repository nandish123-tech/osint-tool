# ─────────────────────────────────────────────────────────────
#  modules/email_intel.py  —  Email Intelligence Module
#
#  WHAT IT COLLECTS:
#
#  Layer 1 — Format validation (built-in, no API, no internet):
#    • Is the email format valid? (has @, has domain, no spaces)
#    • Extract username part  → johndoe
#    • Extract domain part    → gmail.com
#
#  Layer 2 — DNS checks (built-in dns/socket, no API key):
#    • Does the domain actually exist?
#    • Does it have MX records? (can it receive email?)
#    • What mail servers handle this domain?
#
#  Layer 3 — AbstractAPI (free: 100 req/month, needs key):
#    • Is this a disposable/temp email? (guerrillamail, tempmail etc.)
#    • Is it a free provider? (gmail, yahoo, hotmail)
#    • SMTP deliverability check (is this mailbox real?)
#    • Quality score (0-1)
#
#  Layer 4 — HaveIBeenPwned API (needs paid key ~$3.50/mo):
#    • Has this email appeared in any data breaches?
#    • Which breaches? (LinkedIn 2012, Adobe 2013 etc.)
#    • What data was exposed? (passwords, names, phones)
#
#  Layer 5 — Logic (no API):
#    • Identify email provider type (corporate/free/disposable)
#    • Generate OSINT search links
#    • Google, social media, paste sites
#
#  WHAT IS NOT POSSIBLE:
#    ✗ Reading the inbox — that requires login credentials
#    ✗ Who created the account — provider keeps this private
#    ✗ Linked phone number — private account data
# ─────────────────────────────────────────────────────────────

# ── IMPORTS ──────────────────────────────────────────────────

import re          # regular expressions — for email format validation
import socket      # built-in — for DNS lookups (MX records)
import requests    # HTTP requests to APIs
import dns.resolver  # pip install dnspython — proper MX record lookup

from urllib.parse import quote

from utils.config import get_key
from utils.logger import (
    log_module, log_result, log_link,
    log_success, log_warning, log_error, log_info,
    print_summary_panel,
)


# ── KNOWN PROVIDER LISTS ──────────────────────────────────────
# We classify email providers into categories.
# This lets us flag disposable emails and free providers
# even without an API call.

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "tutanota.com",
    "rediffmail.com", "ymail.com", "yahoo.in",
    "zoho.com", "aol.com", "mail.com",
}

# Common disposable / temporary email providers
# People use these to sign up for sites without using real email
DISPOSABLE_PROVIDERS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "spam4.me", "trashmail.com", "trashmail.me",
    "dispostable.com", "maildrop.cc", "mailnull.com",
    "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
    "10minutemail.com", "10minutemail.net", "minutemail.com",
    "getairmail.com", "filzmail.com", "discard.email",
    "fakeinbox.com", "mailnesia.com", "mailnull.com",
}


# ═════════════════════════════════════════════════════════════
#  LAYER 1: FORMAT VALIDATION
#  No internet needed — pure Python logic
# ═════════════════════════════════════════════════════════════

def validate_format(email: str) -> dict:
    """
    Checks if the email string is formatted correctly.

    We use a REGEX (regular expression) pattern.
    Regex is a mini-language for pattern matching in strings.

    Pattern breakdown:
    ^          = start of string
    [^@]+      = one or more characters that are NOT @
    @          = literal @ symbol
    [^@]+      = one or more characters (the domain name)
    \.         = literal dot (. has special meaning in regex so we escape it)
    [^@]+      = one or more characters (the TLD like com, org, in)
    $          = end of string

    re.match() returns a Match object if it matches, or None if it doesn't.
    bool() converts that to True/False.
    """

    # Basic regex pattern for email validation
    pattern = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'
    is_valid_format = bool(re.match(pattern, email.strip()))

    if not is_valid_format:
        return {"valid_format": False}

    # Split into username and domain
    # .split("@", 1) splits on FIRST @ only
    # maxsplit=1 handles edge case: "a@b@c.com" → ["a", "b@c.com"]
    parts       = email.strip().split("@", 1)
    username    = parts[0]
    domain      = parts[1].lower()   # always lowercase domain

    # Classify the provider
    if domain in DISPOSABLE_PROVIDERS:
        provider_type = "disposable"
    elif domain in FREE_PROVIDERS:
        provider_type = "free"
    else:
        provider_type = "corporate/custom"

    return {
        "valid_format":   True,
        "username":       username,
        "domain":         domain,
        "provider_type":  provider_type,
        "is_disposable":  domain in DISPOSABLE_PROVIDERS,
        "is_free":        domain in FREE_PROVIDERS,
    }


# ═════════════════════════════════════════════════════════════
#  LAYER 2: DNS / MX RECORD LOOKUP
#  Checks if the domain can actually receive email
#  Uses dnspython library — no API key needed
# ═════════════════════════════════════════════════════════════

def check_dns(domain: str) -> dict:
    """
    Looks up the domain's MX (Mail eXchange) records.

    MX records tell the internet which mail servers accept
    email for a domain. If a domain has no MX records,
    it cannot receive email — so the address is fake/unusable.

    dns.resolver.resolve(domain, "MX") sends a DNS query
    asking for the MX records of the domain.
    """

    result = {
        "domain_exists":  False,
        "has_mx":         False,
        "mx_records":     [],
        "mail_servers":   [],
    }

    try:
        # First check: does the domain exist at all?
        # We do a basic A record lookup (the most common DNS record)
        # socket.gethostbyname() raises socket.gaierror if not found
        socket.gethostbyname(domain)
        result["domain_exists"] = True

    except socket.gaierror:
        # Domain doesn't exist in DNS at all
        log_warning(f"Domain '{domain}' does not exist in DNS.")
        return result

    try:
        # Second check: does it have MX records?
        # MX records list mail servers for the domain.
        # Each record has:
        #   .preference — priority (lower = higher priority)
        #   .exchange   — the mail server hostname
        mx_records = dns.resolver.resolve(domain, "MX")

        # Sort by preference (lowest number = highest priority)
        sorted_mx = sorted(mx_records, key=lambda r: r.preference)

        result["has_mx"]   = True
        result["mx_records"] = [
            {
                "priority": r.preference,
                "server":   str(r.exchange).rstrip(".")
                # .rstrip(".") removes trailing dot that DNS adds
            }
            for r in sorted_mx
        ]
        result["mail_servers"] = [
            str(r.exchange).rstrip(".")
            for r in sorted_mx
        ]

        log_success(f"Domain has {len(sorted_mx)} MX record(s)")
        for r in sorted_mx[:3]:   # show top 3
            log_result(
                f"  MX (priority {r.preference})",
                str(r.exchange).rstrip(".")
            )

    except dns.resolver.NoAnswer:
        # Domain exists but has no MX records
        log_warning(f"'{domain}' exists but has no MX records — cannot receive email.")

    except dns.resolver.NXDOMAIN:
        # Domain doesn't exist
        log_warning(f"'{domain}' domain not found.")
        result["domain_exists"] = False

    except Exception as e:
        log_warning(f"MX lookup error: {e}")

    return result


# ═════════════════════════════════════════════════════════════
#  LAYER 3: ABSTRACT API — EMAIL VALIDATION
#  Deeper validation: disposable check, SMTP verify
#  Free: 100 req/month at abstractapi.com
# ═════════════════════════════════════════════════════════════

def check_abstract_api(email: str, api_key: str) -> dict:
    """
    Calls AbstractAPI's email validation endpoint.

    It checks:
    - is_valid_format     → format correct?
    - is_free_email       → gmail/yahoo etc?
    - is_disposable_email → temp mail service?
    - is_smtp_valid       → does the mailbox actually exist?
    - quality_score       → 0.0 to 1.0 (higher = more legitimate)
    - autocorrect         → did you mean "gmial.com"?
    """

    try:
        log_info("Querying AbstractAPI for email validation...")

        response = requests.get(
            "https://emailvalidation.abstractapi.com/v1/",
            params={
                "api_key": api_key,
                "email":   email,
            },
            timeout=10,
        )

        if response.status_code == 401:
            log_warning("AbstractAPI: invalid key.")
            return {}

        if response.status_code == 429:
            log_warning("AbstractAPI: rate limit reached (100/month on free tier).")
            return {}

        data = response.json()

        # AbstractAPI wraps boolean values in objects like:
        # {"value": true, "text": "TRUE"}
        # We extract the "value" key from each.
        def extract_bool(field):
            """Helper: get True/False from AbstractAPI's wrapped format."""
            val = data.get(field, {})
            if isinstance(val, dict):
                return val.get("value", False)
            return bool(val)

        result = {
            "deliverability":     data.get("deliverability", "UNKNOWN"),
            "quality_score":      float(data.get("quality_score", 0)),
            "is_valid_format":    extract_bool("is_valid_format"),
            "is_free_email":      extract_bool("is_free_email"),
            "is_disposable":      extract_bool("is_disposable_email"),
            "is_role_email":      extract_bool("is_role_email"),
            # Role emails = info@, admin@, support@ — not personal
            "is_catchall":        extract_bool("is_catchall_email"),
            # Catchall = domain accepts ALL emails even fake ones
            "is_smtp_valid":      extract_bool("is_smtp_valid"),
            "autocorrect":        data.get("autocorrect", ""),
        }

        log_success("AbstractAPI validation complete")
        log_result("Deliverability",   result["deliverability"])
        log_result("Quality score",    f"{result['quality_score']:.2f} / 1.0")
        log_result("SMTP valid",       "Yes" if result["is_smtp_valid"] else "No")
        log_result("Disposable email", "YES ⚠" if result["is_disposable"] else "No")
        log_result("Free provider",    "Yes" if result["is_free_email"] else "No (corporate)")
        log_result("Role email",       "Yes (info@/admin@)" if result["is_role_email"] else "No")

        if result["autocorrect"]:
            log_warning(f"Did you mean: {result['autocorrect']} ?")

        return result

    except requests.exceptions.Timeout:
        log_warning("AbstractAPI timed out.")
        return {}
    except Exception as e:
        log_warning(f"AbstractAPI error: {e}")
        return {}


# ═════════════════════════════════════════════════════════════
#  LAYER 4: HAVEIBEENPWNED — BREACH CHECK
#  Checks if email appeared in known data breaches
#  Requires paid key: ~$3.50/month at haveibeenpwned.com
# ═════════════════════════════════════════════════════════════

def check_hibp(email: str, api_key: str) -> dict:
    """
    Calls the HaveIBeenPwned (HIBP) API.

    HIBP is a database of billions of leaked credentials.
    When companies get hacked (LinkedIn 2012, Adobe 2013,
    Canva 2019 etc.), the leaked data often ends up here.

    If your email is in a breach, it means attackers may
    already have your old password from that site.

    The API returns a list of breach objects. Each has:
    - Name         → site name (e.g. "LinkedIn")
    - BreachDate   → when it happened
    - PwnCount     → how many accounts were in that breach
    - DataClasses  → what was leaked (passwords, names, IPs etc.)
    """

    try:
        log_info("Querying HaveIBeenPwned for breach data...")

        # HIBP requires the API key in the header, not URL params
        # This is more secure than putting it in the URL
        headers = {
            "hibp-api-key": api_key,
            "user-agent":   "osint-tool-student-project",
            # HIBP requires a user-agent header
        }

        # truncateResponse=false → get full breach details
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            headers=headers,
            params={"truncateResponse": "false"},
            timeout=10,
        )

        # 404 = email not found in any breach (GOOD NEWS)
        if response.status_code == 404:
            log_success("Email not found in any known data breaches.")
            return {
                "found_in_breaches": False,
                "breach_count":      0,
                "breaches":          [],
            }

        if response.status_code == 401:
            log_warning("HIBP: invalid or missing API key.")
            return {}

        if response.status_code == 429:
            log_warning("HIBP: rate limited — try again in a few seconds.")
            return {}

        if response.status_code != 200:
            log_warning(f"HIBP returned status {response.status_code}")
            return {}

        # Parse the list of breach objects
        breaches = response.json()

        # Extract key info from each breach
        breach_list = []
        for b in breaches:
            breach_list.append({
                "name":         b.get("Name", "Unknown"),
                "domain":       b.get("Domain", ""),
                "date":         b.get("BreachDate", "Unknown"),
                "pwn_count":    b.get("PwnCount", 0),
                "data_classes": b.get("DataClasses", []),
                # DataClasses = list of what was exposed:
                # ["Email addresses", "Passwords", "Usernames"]
            })

        # Sort by date (most recent first)
        breach_list.sort(key=lambda x: x["date"], reverse=True)

        log_warning(
            f"Email found in [bold]{len(breach_list)}[/bold] breach(es)!"
        )
        for b in breach_list[:5]:   # show top 5 most recent
            log_result(
                f"  {b['name']} ({b['date']})",
                f"Exposed: {', '.join(b['data_classes'][:3])}"
            )

        return {
            "found_in_breaches": True,
            "breach_count":      len(breach_list),
            "breaches":          breach_list,
        }

    except requests.exceptions.Timeout:
        log_warning("HIBP API timed out.")
        return {}
    except Exception as e:
        log_warning(f"HIBP error: {e}")
        return {}


# ═════════════════════════════════════════════════════════════
#  LAYER 5: OSINT SEARCH LINKS
#  Generate ready-to-open links for manual investigation
# ═════════════════════════════════════════════════════════════

def build_links(email: str, username: str, domain: str) -> dict:
    """
    Build search URLs for manual OSINT investigation.

    quote() URL-encodes special characters (@, +, spaces etc.)
    so they don't break the URL.
    """
    enc_email = quote(email)

    return {
        # Search the email directly
        "google":
            f"https://www.google.com/search?q={enc_email}",
        "google_exact":
            f"https://www.google.com/search?q=%22{enc_email}%22",

        # Search username (the part before @)
        "google_username":
            f"https://www.google.com/search?q=%22{quote(username)}%22",

        # Paste site searches — leaked data often appears here
        "pastebin_search":
            f"https://www.google.com/search?q=site:pastebin.com+{enc_email}",

        # Social platforms
        "linkedin":
            f"https://www.linkedin.com/search/results/people/?keywords={enc_email}",
        "twitter":
            f"https://twitter.com/search?q={enc_email}",

        # Email-specific OSINT tools
        "epieos":
            f"https://epieos.com/?q={enc_email}&t=email",
        # Epieos is a great free OSINT tool that finds
        # Google accounts and social profiles from email

        "holehe":
            f"https://github.com/megadose/holehe",
        # Holehe is a CLI tool that checks if an email
        # is registered on 120+ sites — install separately

        # Domain investigation
        "whois":
            f"https://www.whois.com/whois/{domain}",
        "mxtoolbox":
            f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}",
    }


# ═════════════════════════════════════════════════════════════
#  MAIN FUNCTION — Entry point called by main.py
# ═════════════════════════════════════════════════════════════

def lookup_email(email: str, config: dict) -> dict:
    """
    Master function that runs all layers and combines results.

    Called from main.py like:
        result = lookup_email("john@example.com", config)
    """

    log_module("Email Intel")
    log_info(f"Target: {email}")

    # Clean the input — strip spaces, lowercase
    email = email.strip().lower()

    # Final result dict — we fill this up layer by layer
    result = {"input": email}


    # ── LAYER 1: FORMAT CHECK ─────────────────────────────────
    format_data = validate_format(email)
    result.update(format_data)   # merge into result

    if not format_data.get("valid_format"):
        log_error(f"'{email}' is not a valid email format.")
        log_info("Example of valid format: john@example.com")
        return {}

    username = format_data["username"]
    domain   = format_data["domain"]

    log_success(f"Valid email format detected")
    log_result("Username part",   username)
    log_result("Domain part",     domain)
    log_result("Provider type",   format_data["provider_type"])

    if format_data["is_disposable"]:
        log_warning("DISPOSABLE EMAIL — likely fake/throwaway account")

    # ── LAYER 2: DNS / MX RECORDS ─────────────────────────────
    dns_data = check_dns(domain)
    result["dns"] = dns_data

    if not dns_data.get("domain_exists"):
        log_error(f"Domain '{domain}' does not exist. Email is likely fake.")
        # We still continue — maybe the domain is just slow DNS

    if not dns_data.get("has_mx"):
        log_warning(f"'{domain}' has no MX records — cannot receive email.")


    # ── LAYER 3: ABSTRACT API ─────────────────────────────────
    abstract_key = get_key(config, "ABSTRACT_KEY")
    if abstract_key:
        abstract_data = check_abstract_api(email, abstract_key)
        if abstract_data:
            result["abstract"] = abstract_data
    else:
        log_warning("ABSTRACT_KEY not in .env — skipping email validation API.")
        log_info("Get free key at abstractapi.com (100 req/month)")


    # ── LAYER 4: HAVEIBEENPWNED ───────────────────────────────
    hibp_key = get_key(config, "HIBP_KEY")
    if hibp_key:
        hibp_data = check_hibp(email, hibp_key)
        if hibp_data:
            result["hibp"] = hibp_data
    else:
        log_warning("HIBP_KEY not in .env — skipping breach check.")
        log_info("Get key at haveibeenpwned.com (~$3.50/month)")


    # ── LAYER 5: OSINT LINKS ──────────────────────────────────
    links = build_links(email, username, domain)
    result["links"] = links

    log_info("OSINT investigation links:")
    log_link("Google (exact)",   links["google_exact"])
    log_link("Epieos OSINT",     links["epieos"])
    log_link("Pastebin search",  links["pastebin_search"])
    log_link("WHOIS on domain",  links["whois"])
    log_link("MX Toolbox",       links["mxtoolbox"])


    # ── FINAL SUMMARY PANEL ───────────────────────────────────
    summary_rows = [
        ("Email",            email),
        ("Username",         username),
        ("Domain",           domain),
        ("Provider type",    format_data["provider_type"]),
        ("Disposable",       "YES ⚠ FAKE" if format_data["is_disposable"] else "No"),
        ("",                 ""),

        ("Domain exists",    "Yes" if result["dns"]["domain_exists"]  else "No ✖"),
        ("Can receive email","Yes" if result["dns"]["has_mx"]         else "No ✖"),
    ]

    # Add MX records if we got them
    if result["dns"].get("mail_servers"):
        summary_rows.append((
            "Mail server(s)",
            result["dns"]["mail_servers"][0]
            + (f" (+{len(result['dns']['mail_servers'])-1} more)"
               if len(result["dns"]["mail_servers"]) > 1 else "")
        ))

    # Add AbstractAPI results if available
    if "abstract" in result:
        ab = result["abstract"]
        summary_rows += [
            ("", ""),
            ("Deliverability",    ab.get("deliverability", "N/A")),
            ("Quality score",     f"{ab.get('quality_score', 0):.2f} / 1.0"),
            ("SMTP valid",        "Yes" if ab.get("is_smtp_valid") else "No"),
            ("Catchall domain",   "Yes (any address works)" if ab.get("is_catchall") else "No"),
        ]
        if ab.get("autocorrect"):
            summary_rows.append(("Did you mean?", ab["autocorrect"]))

    # Add HIBP results if available
    if "hibp" in result:
        hibp = result["hibp"]
        if hibp.get("found_in_breaches"):
            summary_rows += [
                ("", ""),
                ("Data breaches",    f"FOUND IN {hibp['breach_count']} BREACH(ES) ⚠"),
            ]
            for b in hibp.get("breaches", [])[:4]:
                summary_rows.append((
                    f"  {b['name']}",
                    f"{b['date']} — {', '.join(b['data_classes'][:2])}"
                ))
        else:
            summary_rows += [
                ("", ""),
                ("Data breaches", "Not found in any known breaches ✔"),
            ]

    # Add links
    summary_rows += [
        ("", ""),
        ("Google search",   links["google_exact"]),
        ("Epieos OSINT",    links["epieos"]),
        ("Pastebin check",  links["pastebin_search"]),
        ("Domain WHOIS",    links["whois"]),
    ]

    print_summary_panel("Email Intel Report", summary_rows, color="magenta")

    return result
