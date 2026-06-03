import os
from dotenv import load_dotenv
from rich.console import Console
from rich.table   import Table

load_dotenv()
console = Console()

KEYS = {
    "NUMVERIFY_KEY":  "Phone lookup       → numverify.com        (free 100/mo)",
    "IPINFO_KEY":     "IP geolocation     → ipinfo.io            (free 50k/mo)",
    "ABSTRACT_KEY":   "Email validation   → abstractapi.com      (free 100/mo)",
    "HIBP_KEY":       "Breach check       → haveibeenpwned.com   (~$3.50/mo)",
    "WHOIS_KEY":      "WHOIS lookup       → whoisxmlapi.com      (free 500/mo)",
}

def load_config() -> dict:
    config, missing = {}, []
    for key, desc in KEYS.items():
        val = os.getenv(key)
        if val and val not in ("your_key_here", ""):
            config[key] = val
        else:
            missing.append((key, desc))
    if missing:
        console.print("\n[bold yellow]⚠  Missing API keys:[/bold yellow]")
        t = Table(show_header=False, box=None, padding=(0,3))
        t.add_column("Key",  style="dim cyan", no_wrap=True)
        t.add_column("Info", style="dim")
        for k, d in missing:
            t.add_row(k, d)
        console.print(t)
        console.print("[dim]  Add to .env to unlock features.\n[/dim]")
    return config

def get_key(config: dict, key: str) -> str | None:
    return config.get(key)
