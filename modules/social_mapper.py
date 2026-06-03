# ─────────────────────────────────────────────────────────────
#  modules/social_mapper.py  —  Username OSINT Module
#
#  WHAT IT DOES:
#    Takes a username (e.g. "johndoe") and checks 50+ social
#    platforms simultaneously to find where that person has
#    an active profile.
#
#  KEY CONCEPT — ASYNC:
#    Checking 50 sites one by one (synchronously) takes ~50 seconds.
#    Checking all 50 at the same time (asynchronously) takes ~3-5s.
#    We use asyncio + aiohttp for async HTTP requests.
#
#  HOW PROFILE DETECTION WORKS:
#    We request each platform's profile URL.
#    If we get HTTP 200 → profile likely exists.
#    If we get HTTP 404 → profile doesn't exist.
#    Some sites return 200 even for missing profiles —
#    for those we also check if an error phrase is in the page text.
#
#  WHAT IT COLLECTS PER FOUND PROFILE:
#    • Platform name
#    • Profile URL
#    • HTTP status code
#    • Response time (ms)
#    • Profile avatar URL (for fingerprinting later)
# ─────────────────────────────────────────────────────────────

# asyncio  = Python's async engine (built-in, no pip needed)
# aiohttp  = async HTTP library (pip install aiohttp)
# Both work together: asyncio manages the event loop,
# aiohttp does the actual HTTP requests inside it.
import asyncio
import aiohttp

import json        # to load platforms.json
import os          # to build the file path
import time        # to measure response time

from utils.logger import (
    log_module, log_result, log_success,
    log_warning, log_error, log_info,
    print_summary_panel,
)

# ── LOAD PLATFORMS ───────────────────────────────────────────
# platforms.json lives in data/ folder.
# __file__ = path of this script (modules/social_mapper.py)
# os.path.dirname(__file__) = the modules/ folder
# We go up one level (..) to reach the project root,
# then into data/platforms.json

PLATFORMS_FILE = os.path.join(
    os.path.dirname(__file__), "..", "data", "platforms.json"
)

def load_platforms() -> dict:
    """Load platform definitions from JSON file."""
    try:
        with open(PLATFORMS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        log_error(f"platforms.json not found at {PLATFORMS_FILE}")
        return {}
    except json.JSONDecodeError as e:
        log_error(f"platforms.json is invalid JSON: {e}")
        return {}


# ── SINGLE PLATFORM CHECK (async) ────────────────────────────
# This function checks ONE platform for a username.
# "async def" means it's a coroutine — it can pause
# while waiting for a network response, letting other
# checks run in parallel during that wait.
#
# Parameters:
#   session  → shared aiohttp session (reuses connections)
#   platform → platform name string (e.g. "github")
#   url      → profile URL with username already filled in
#   check    → error phrase to look for in page text
#              (some sites return 200 even for missing profiles)
#
# Returns:
#   dict with result data, or None if profile not found

async def check_platform(
    session: aiohttp.ClientSession,
    platform: str,
    url: str,
    error_phrase: str,
) -> dict | None:

    try:
        start = time.time()   # record start time

        # session.get() sends an async GET request.
        # "async with" = context manager for async code.
        # timeout= limits how long we wait per site.
        # allow_redirects=True follows 301/302 redirects.
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=8),
            allow_redirects=True,
            ssl=False,           # skip SSL verification (some sites have bad certs)
        ) as response:

            elapsed_ms = int((time.time() - start) * 1000)
            status     = response.status

            # Read the page text (needed for phrase checking)
            # We only read first 5000 chars — enough to find error phrases
            # without downloading the whole page.
            text = await response.text(errors="ignore")
            text_snippet = text[:5000].lower()

            # ── DETECTION LOGIC ──────────────────────────────
            # Case 1: HTTP 404 → definitely doesn't exist
            if status == 404:
                return None

            # Case 2: HTTP 200 BUT error phrase found in page
            # e.g. GitHub returns 200 for missing users but
            # the page says "Not Found" in the title
            if status == 200 and error_phrase.lower() in text_snippet:
                return None

            # Case 3: HTTP 200 and no error phrase → profile exists!
            if status == 200:
                # Try to extract avatar URL from og:image meta tag
                # This is a best-effort attempt — not all sites have it
                avatar_url = None
                if 'og:image' in text:
                    try:
                        # Find og:image content="..." in the HTML
                        idx = text.find('og:image')
                        chunk = text[idx:idx+300]
                        content_idx = chunk.find('content="')
                        if content_idx != -1:
                            start_idx = content_idx + 9
                            end_idx   = chunk.find('"', start_idx)
                            avatar_url = chunk[start_idx:end_idx]
                    except Exception:
                        pass  # avatar extraction failed — not critical

                return {
                    "platform":    platform,
                    "url":         url,
                    "status":      status,
                    "response_ms": elapsed_ms,
                    "avatar_url":  avatar_url,
                }

            # Case 4: Other status codes (403, 429, 503...)
            # 403 = Forbidden (site blocks bots — might exist)
            # 429 = Rate limited (we're being throttled)
            # We return a "maybe" result for 403
            if status == 403:
                return {
                    "platform":    platform,
                    "url":         url,
                    "status":      403,
                    "response_ms": elapsed_ms,
                    "avatar_url":  None,
                    "note":        "403 — may exist but blocks bots",
                }

            return None   # any other status = treat as not found

    except asyncio.TimeoutError:
        # Site didn't respond in 8 seconds — skip it
        return None
    except Exception:
        # Any other error (DNS failure, SSL error, etc.) — skip
        return None


# ── MAIN ASYNC FUNCTION ───────────────────────────────────────
# This runs all platform checks concurrently.
# "async def" again — this is also a coroutine.

async def _run_all_checks(username: str, platforms: dict) -> list:
    """
    Checks all platforms simultaneously using aiohttp.
    Returns list of found profile dicts.
    """

    # aiohttp.ClientSession() manages a pool of connections.
    # Reusing one session for all requests is much faster
    # than creating a new connection for each site.
    #
    # headers= makes us look like a real browser.
    # Some sites block requests without a User-Agent header.

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    }

    found = []   # we'll collect all found profiles here

    async with aiohttp.ClientSession(headers=headers) as session:

        # Build a list of coroutine tasks — one per platform.
        # At this point we're just CREATING the tasks, not running them yet.
        tasks = []
        for platform_name, platform_data in platforms.items():
            # Fill {username} placeholder in the URL template
            url = platform_data["url"].replace("{username}", username)
            error_phrase = platform_data.get("check", "404")

            # check_platform() returns a coroutine — add it to our task list
            tasks.append(
                check_platform(session, platform_name, url, error_phrase)
            )

        # asyncio.gather() runs ALL tasks at the same time.
        # It waits until ALL of them finish, then returns
        # a list of results in the same order as tasks.
        # return_exceptions=True means if one task crashes,
        # the others keep running.
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out None results (not found) and exceptions
        for result in results:
            if isinstance(result, dict):   # found profile
                found.append(result)
                log_success(
                    f"[bold]{result['platform']:<15}[/bold] "
                    f"{result['url']}"
                )

    return found


# ── PUBLIC ENTRY POINT ────────────────────────────────────────
# Called by main.py like:
#   result = lookup_username("johndoe", config)
#
# We wrap the async function here because main.py is
# synchronous — it can't use "await" directly.
# asyncio.run() creates an event loop, runs our async code,
# waits for it to finish, then returns the result normally.

def lookup_username(username: str, config: dict) -> dict:

    log_module("Social Mapper")
    log_info(f"Searching for username: [bold]{username}[/bold]")

    # Load platform list from platforms.json
    platforms = load_platforms()
    if not platforms:
        log_error("No platforms loaded. Check data/platforms.json")
        return {}

    total = len(platforms)
    log_info(f"Checking {total} platforms simultaneously...")

    # Run the async checks synchronously
    # asyncio.run() is the bridge between sync and async code
    found_profiles = asyncio.run(_run_all_checks(username, platforms))

    if not found_profiles:
        log_warning(f"No profiles found for username '{username}'")
        return {"username": username, "found": [], "total_checked": total}

    # ── Build result dict ─────────────────────────────────────
    result = {
        "username":       username,
        "total_checked":  total,
        "total_found":    len(found_profiles),
        "found":          found_profiles,
    }

    # ── Print summary panel ───────────────────────────────────
    summary_rows = [
        ("Username",        username),
        ("Platforms checked", str(total)),
        ("Profiles found",  str(len(found_profiles))),
        ("", ""),
    ]
    # Add each found platform as a row
    for profile in found_profiles:
        note = f" ({profile.get('note','')})" if profile.get("note") else ""
        summary_rows.append((
            profile["platform"],
            profile["url"] + note
        ))

    print_summary_panel(
        f"Social Mapper — {len(found_profiles)} profiles found",
        summary_rows,
        color="green"
    )

    return result
