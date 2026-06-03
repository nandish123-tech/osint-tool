# ─────────────────────────────────────────────────────────────
#  setup_check.py  —  Run this FIRST to verify everything works
#  
#  Place this in your osint-tool/ root folder and run:
#    python setup_check.py
# ─────────────────────────────────────────────────────────────

import sys
import importlib

print("\n" + "="*50)
print("  OSINT Tool — Setup Verification")
print("="*50)

# ── Check Python version ──────────────────────────────────────
print(f"\n[1] Python version: {sys.version}")
if sys.version_info < (3, 10):
    print("    ⚠  WARNING: Python 3.10+ recommended")
else:
    print("    ✔  Python version OK")

# ── Check required packages ───────────────────────────────────
packages = {
    "phonenumbers":  "phonenumbers",
    "requests":      "requests",
    "rich":          "rich",
    "dotenv":        "python-dotenv",
    "aiohttp":       "aiohttp",
    "imagehash":     "imagehash",
    "PIL":           "Pillow",
    "fastapi":       "fastapi",
    "uvicorn":       "uvicorn",
}

print("\n[2] Checking installed packages:")
missing_packages = []
for module_name, pip_name in packages.items():
    try:
        importlib.import_module(module_name)
        print(f"    ✔  {pip_name}")
    except ImportError:
        print(f"    ✖  {pip_name}  ← NOT INSTALLED")
        missing_packages.append(pip_name)

if missing_packages:
    print(f"\n    Run this to fix:")
    print(f"    pip install {' '.join(missing_packages)}")

# ── Check folder structure ────────────────────────────────────
import os
print("\n[3] Checking folder structure:")
required = [
    "utils/__init__.py",
    "utils/config.py",
    "utils/logger.py",
    "modules/__init__.py",
    "modules/phone_lookup.py",
    "modules/social_mapper.py",
    "modules/email_intel.py",
    "modules/ip_intel.py",
    "modules/avatar_fingerprint.py",
    "modules/report_generator.py",
    "main.py",
    ".env",
    "data/platforms.json",
]
missing_files = []
for path in required:
    if os.path.exists(path):
        print(f"    ✔  {path}")
    else:
        print(f"    ✖  {path}  ← MISSING")
        missing_files.append(path)

# ── Check .env keys ───────────────────────────────────────────
print("\n[4] Checking .env API keys:")
try:
    from dotenv import load_dotenv
    load_dotenv()
    keys = ["NUMVERIFY_KEY","ABSTRACT_KEY","HIBP_KEY","WHOIS_KEY","IPINFO_KEY"]
    for key in keys:
        val = os.getenv(key)
        if val and val != "your_key_here":
            print(f"    ✔  {key} is set")
        else:
            print(f"    ○  {key} not set (optional for now)")
except Exception as e:
    print(f"    ✖  Could not read .env: {e}")

# ── Check module imports ──────────────────────────────────────
print("\n[5] Checking our own modules import correctly:")
our_modules = [
    ("utils.config",          "load_config"),
    ("utils.logger",          "log_info"),
    ("modules.phone_lookup",  "lookup_phone"),
]
for mod_path, func_name in our_modules:
    try:
        mod = importlib.import_module(mod_path)
        getattr(mod, func_name)
        print(f"    ✔  {mod_path}.{func_name}")
    except ImportError as e:
        print(f"    ✖  {mod_path} — ImportError: {e}")
    except AttributeError as e:
        print(f"    ✖  {mod_path}.{func_name} — not found: {e}")
    except Exception as e:
        print(f"    ✖  {mod_path} — {e}")

# ── Final summary ─────────────────────────────────────────────
print("\n" + "="*50)
if not missing_packages and not missing_files:
    print("  ✔  ALL CHECKS PASSED — ready to run!")
    print("  Try: python main.py --phone +919876543210")
else:
    if missing_packages:
        print(f"  ✖  Fix {len(missing_packages)} missing package(s) above")
    if missing_files:
        print(f"  ✖  Fix {len(missing_files)} missing file(s) above")
print("="*50 + "\n")
