# ─────────────────────────────────────────────────────────────
#  modules/phone_lookup.py  —  Phone Intelligence Module
#
#  WHAT THIS MODULE COLLECTS:
#    Layer 1 — Offline (phonenumbers library, no API needed):
#      • Number validity
#      • Country + registered region/state
#      • Carrier (original network operator)
#      • Line type: Mobile / Landline / VOIP / Toll-free
#      • Timezone(s)
#      • All standard formats: E164, International, National
#
#    Layer 2 — NumVerify API (free tier, needs key in .env):
#      • Confirmed carrier name
#      • Confirmed line type
#      • Location string
#
#    Layer 3 — Logic (no API, no internet):
#      • WhatsApp likelihood (based on line type)
#      • Number type interpretation
#
#    Layer 4 — URL builder (no API):
#      • Ready-made Google, Truecaller, Sync.me search links
#      • So you can manually look up who owns the number
#
#  WHAT IS NOT POSSIBLE (and why):
#      ✗ Exact GPS coordinates — numbers aren't GPS-tagged
#      ✗ Registered owner name — private telecom data
#      ✗ Real-time location   — only carriers + law enforcement
#      ✗ Call / SMS history   — requires court order
# ─────────────────────────────────────────────────────────────

# ── IMPORTS ──────────────────────────────────────────────────

import phonenumbers
# Sub-modules of phonenumbers — each does one specific lookup:
from phonenumbers import geocoder  # country / region from number prefix
from phonenumbers import carrier   # network operator name
from phonenumbers import timezone  # timezone(s) for the number's region

import requests          # sends HTTP requests to APIs
from urllib.parse import quote  # URL-encodes strings (handles + and spaces)

# Our utilities
from utils.config import get_key
from utils.logger import (
    log_module, log_result, log_link,
    log_success, log_warning, log_error, log_info,
    print_summary_panel,
)

# ── LINE TYPE MAP ────────────────────────────────────────────
# phonenumbers.number_type() returns a number (0, 1, 2...).
# This dict converts those codes to human-readable strings.
# We use dict.get(code, "Unknown") so unrecognised codes
# don't crash — they just show "Unknown".

LINE_TYPE_MAP = {
    0:  "Fixed line",
    1:  "Mobile",
    2:  "Fixed line or Mobile",
    3:  "Toll-free",
    4:  "Premium rate",
    5:  "Shared cost",
    6:  "VOIP",
    7:  "Personal number",
    8:  "Pager",
    9:  "UAN (Universal Access Number)",
    10: "Voicemail",
    99: "Unknown",
}

# ── MAIN FUNCTION ────────────────────────────────────────────
# Entry point called by main.py like:
#   result = lookup_phone("+919876543210", config)
#
# Parameters:
#   number  → string, phone number with country code (+91...)
#   config  → dict from load_config(), holds API keys
#
# Returns:
#   dict with all collected data, OR {} if number was invalid

def lookup_phone(number: str, config: dict) -> dict:

    # Print a coloured section header to the terminal
    log_module("Phone Intel")

    # result{} is where we collect ALL findings.
    # We build it up step by step and return it at the end.
    result = {}


    # ── LAYER 1A: PARSE THE NUMBER ────────────────────────────
    # phonenumbers.parse() breaks "+919876543210" into:
    #   country_code    = 91
    #   national_number = 9876543210
    #
    # If the string can't be parsed at all (e.g. "hello"),
    # it raises NumberParseException.
    # The try/except catches this so the tool doesn't crash.

    try:
        parsed = phonenumbers.parse(number)

    except phonenumbers.NumberParseException as e:
        log_error(f"Cannot parse '{number}' — {e}")
        log_info("Tip: include country code, e.g. +91 for India, +1 for USA")
        return {}   # return empty dict → main.py sees "no result"


    # ── LAYER 1B: VALIDATE THE NUMBER ────────────────────────
    # is_valid_number() checks against real carrier allocation tables.
    # A number can parse successfully but still be invalid
    # (e.g. wrong length for that country).

    if not phonenumbers.is_valid_number(parsed):
        log_error(f"'{number}' is not a valid phone number.")
        log_info("Check the country code and number length.")
        return {}


    # ── LAYER 1C: EXTRACT OFFLINE DATA ───────────────────────

    # geocoder.description_for_number() returns the geographic area
    # for the number's prefix — usually country or telecom circle.
    # For Indian numbers: "Maharashtra", "Delhi", "Tamil Nadu" etc.
    # IMPORTANT: This is the REGISTRATION area, not current location.
    geo_area = geocoder.description_for_number(parsed, "en")

    # carrier.name_for_number() returns original network operator.
    # E.g. "Airtel", "Jio", "Vi", "BSNL".
    # If the SIM was ported to another carrier, this may show
    # the ORIGINAL carrier, not the current one.
    carrier_name = carrier.name_for_number(parsed, "en")

    # timezone.time_zones_for_number() returns a tuple of timezone
    # strings. Usually one entry like ("Asia/Kolkata",)
    # but some countries/regions have multiple possibilities.
    timezones = timezone.time_zones_for_number(parsed)

    # number_type() returns a numeric code (0-10 or 99).
    # We convert it to a string using LINE_TYPE_MAP above.
    number_type_code = phonenumbers.number_type(parsed)
    line_type = LINE_TYPE_MAP.get(number_type_code, "Unknown")

    # format_number() converts to different standard formats:
    # E164         = "+919876543210"  → used by APIs and databases
    # INTERNATIONAL= "+91 98765 43210" → human-readable with spaces
    # NATIONAL     = "098765 43210"   → local format without country code
    e164       = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl_fmt   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    natl_fmt   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

    # region_code_for_number() returns the 2-letter ISO country code.
    # "IN" for India, "US" for USA, "GB" for UK etc.
    region_code  = phonenumbers.region_code_for_number(parsed)

    # country_code is the numeric dialling prefix (91, 1, 44 etc.)
    country_code = str(parsed.country_code)


    # ── BUILD RESULT DICT (Layer 1) ───────────────────────────
    # We store everything in a flat dict.
    # or "Unknown" handles the case where the library
    # returns an empty string "" (not None) for some numbers.

    result = {
        # Input
        "input":         number,

        # Formats
        "e164":          e164,
        "international": intl_fmt,
        "national":      natl_fmt,

        # Geography
        "country_code":  country_code,
        "region_code":   region_code,
        "geo_area":      geo_area   or "Unknown",

        # Carrier & type
        "carrier":       carrier_name or "Unknown",
        "line_type":     line_type,

        # Timezone — stored as list (was a tuple, convert for JSON)
        "timezones":     list(timezones),

        # Validity flag
        "is_valid":      True,
    }

    # Print Layer 1 results to terminal
    log_success(f"Valid number → {intl_fmt}")
    log_result("Region / State",  f"{geo_area or 'Unknown'} ({region_code})")
    log_result("Country dial code", f"+{country_code}")
    log_result("Carrier",         carrier_name or "Unknown")
    log_result("Line type",       line_type)
    log_result("Timezone(s)",     ", ".join(timezones) if timezones else "Unknown")
    log_result("E164 format",     e164)
    log_result("International",   intl_fmt)
    log_result("National format", natl_fmt)


    # ── LAYER 2: NUMVERIFY API ────────────────────────────────
    # NumVerify has a larger, more up-to-date database than
    # the offline phonenumbers library.
    # It can confirm line type, carrier, and location string.
    # Free tier: 250 requests/month at numverify.com
    #
    # We only call it if the key exists in config.
    # get_key() returns None if not found — no crash.

    numverify_key = get_key(config,"cb4b6ce1fa9c5a31d1e8884f1a2cf297")

    if numverify_key:
        log_info("Querying NumVerify API for enrichment...")

        try:
            # requests.get() sends HTTP GET to the URL.
            # params={} are appended as ?key=val&key2=val2
            # timeout=8 = give up if no response in 8 seconds
            response = requests.get(
                "http://apilayer.net/api/validate",
                params={
                    "access_key": numverify_key,
                    "number":     e164,    # always use E164 with APIs
                    "format":     1,       # 1 = return JSON format
                },
                timeout=8,
            )

            # response.json() converts the JSON text response
            # into a Python dict we can read with .get()
            data = response.json()

            # data.get("valid") is True if NumVerify knows this number
            if data.get("valid"):
                result["api_location"]  = data.get("location",  "N/A")
                result["api_carrier"]   = data.get("carrier",   "N/A")
                result["api_line_type"] = data.get("line_type", "N/A")
                result["api_source"]    = "NumVerify"

                log_success("NumVerify returned data")
                log_result("Location (API)",  result["api_location"])
                log_result("Carrier (API)",   result["api_carrier"])
                log_result("Line type (API)", result["api_line_type"])

            else:
                # API responded but number not found —
                # could be free tier limit or unlisted number
                log_warning("NumVerify: number not in database "
                            "or free tier limit reached.")

        except requests.exceptions.Timeout:
            log_warning("NumVerify API timed out (>8s). Skipping.")

        except requests.exceptions.ConnectionError:
            log_warning("NumVerify: no internet connection.")

        except Exception as e:
            # Catch-all for unexpected errors (bad JSON, server error etc.)
            log_warning(f"NumVerify API unexpected error: {e}")

    else:
        log_warning("NUMVERIFY_KEY not in .env — skipping API enrichment.")
        log_info("Get a free key at numverify.com (250 lookups/month)")


    # ── LAYER 3: WHATSAPP LIKELIHOOD ─────────────────────────
    # WhatsApp is used on mobile numbers in most countries.
    # There is no public API to check this without automation.
    # We use line type as a reliable heuristic:
    #   Mobile or Fixed/Mobile → WhatsApp very likely
    #   Landline / VOIP / Toll-free → WhatsApp unlikely

    mobile_types = ("Mobile", "Fixed line or Mobile")

    if line_type in mobile_types:
        result["whatsapp_likely"] = True
        result["whatsapp_note"]   = "Mobile line — WhatsApp likely registered"
        log_result("WhatsApp",  "Likely (mobile number)")
    else:
        result["whatsapp_likely"] = False
        result["whatsapp_note"]   = f"Line type '{line_type}' — WhatsApp unlikely"
        log_result("WhatsApp",  f"Unlikely ({line_type})")


    # ── LAYER 4: OSINT SEARCH LINKS ──────────────────────────
    # We cannot look up the owner's name ourselves —
    # that data is private to telecoms.
    #
    # BUT: if someone ever posted their number publicly
    # (on Facebook, WhatsApp groups, classified ads, LinkedIn),
    # Google will have indexed it.
    #
    # We build ready-to-open search URLs so you (or the UI)
    # can click and check immediately.
    #
    # quote() URL-encodes special characters:
    #   "+" becomes "%2B" so it doesn't break the URL
    #   " " becomes "%20"

    e164_enc   = quote(e164)          # encodes +91... safely
    natl_clean = natl_fmt.replace(" ", "").replace("-", "")
    # natl_clean = "09876543210" — digits only for Truecaller URL

    result["search_links"] = {
        "google":
            f"https://www.google.com/search?q={e164_enc}",

        "google_quoted":
            # Quotes around the number → exact match search
            f'https://www.google.com/search?q="{quote(intl_fmt)}"',

        "truecaller":
            f"https://www.truecaller.com/search/{region_code.lower()}/{natl_clean}",

        "sync_me":
            f"https://sync.me/search/?number={e164_enc}",

        "eyecon":
            f"https://www.eyecon.mobi/search?q={e164_enc}",

        "whatsapp_click_to_chat":
            # WhatsApp's official URL scheme to open a chat
            # with this number (works even if not in your contacts)
            f"https://wa.me/{e164.replace('+', '')}",
    }

    log_info("OSINT search links generated:")
    log_link("Google (number)",    result["search_links"]["google"])
    log_link("Google (exact)",     result["search_links"]["google_quoted"])
    log_link("Truecaller",         result["search_links"]["truecaller"])
    log_link("WhatsApp chat",      result["search_links"]["whatsapp_click_to_chat"])


    # ── FINAL SUMMARY PANEL ───────────────────────────────────
    # print_summary_panel() from logger.py prints a boxed table.
    # We build the rows list here — only include API rows
    # if the API actually returned data (key exists in result).

    summary_rows = [
        # ── Number formats ──
        ("Input",              result["input"]),
        ("E164",               result["e164"]),
        ("International",      result["international"]),
        ("National",           result["national"]),
        ("",                   ""),  # blank separator

        # ── Geography ──
        ("Region / State",     f"{result['geo_area']} ({result['region_code']})"),
        ("Country dial code",  f"+{result['country_code']}"),
        ("Timezone(s)",        ", ".join(result["timezones"]) or "Unknown"),
        ("",                   ""),

        # ── Carrier & type ──
        ("Carrier",            result["carrier"]),
        ("Line type",          result["line_type"]),
        ("WhatsApp",           "Likely" if result["whatsapp_likely"] else "Unlikely"),
    ]

    # Conditionally add API rows only if they exist
    if "api_carrier" in result:
        summary_rows += [
            ("", ""),
            ("Carrier (NumVerify)",   result["api_carrier"]),
            ("Location (NumVerify)",  result["api_location"]),
            ("Line type (NumVerify)", result["api_line_type"]),
        ]

    # Add search links section
    links = result.get("search_links", {})
    if links:
        summary_rows += [
            ("", ""),
            ("[bold]OSINT Search Links[/bold]", ""),
            ("Google",       links["google"]),
            ("Google exact", links["google_quoted"]),
            ("Truecaller",   links["truecaller"]),
            ("WhatsApp",     links["whatsapp_click_to_chat"]),
        ]

    print_summary_panel("Phone Intel Report", summary_rows, color="cyan")

    # Return the full result dict to main.py
    # main.py will save it as JSON to the output/ folder
    return result
