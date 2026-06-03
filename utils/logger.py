# ─────────────────────────────────────────────────────────────
#  utils/logger.py — Coloured terminal output + banner
# ─────────────────────────────────────────────────────────────

from rich.console import Console
from rich.theme   import Theme
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from datetime     import datetime

custom_theme = Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error":   "bold red",
    "module":  "bold magenta",
    "data":    "white",
    "muted":   "dim white",
    "link":    "underline cyan",
})
console = Console(theme=custom_theme)

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def log_info(msg: str):
    console.print(f"[muted]{_ts()}[/muted]  [info]ℹ  INFO   [/info]  {msg}")

def log_success(msg: str):
    console.print(f"[muted]{_ts()}[/muted]  [success]✔  FOUND  [/success]  {msg}")

def log_warning(msg: str):
    console.print(f"[muted]{_ts()}[/muted]  [warning]⚠  WARN   [/warning]  {msg}")

def log_error(msg: str):
    console.print(f"[muted]{_ts()}[/muted]  [error]✖  ERROR  [/error]  {msg}")

def log_module(name: str):
    console.print(f"\n[module]{'─'*12} {name.upper()} {'─'*12}[/module]")

def log_result(label: str, value: str):
    console.print(f"   [muted]{label:<26}[/muted]  [data]{value}[/data]")

def log_link(label: str, url: str):
    console.print(f"   [muted]{label:<26}[/muted]  [link]{url}[/link]")

def print_summary_panel(title: str, rows: list, color: str = "cyan"):
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="dim",   width=28)
    table.add_column("Value", style="white")
    for label, value in rows:
        table.add_row(str(label), str(value))
    console.print(Panel(
        table,
        title=f"[bold {color}]{title}[/bold {color}]",
        subtitle=f"[dim]Scanned at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        border_style=color,
        padding=(1, 2),
    ))

BANNER = r"""
  ___  ____ ___ _   _ _____    _____ ___   ___  _
 / _ \/ ___|_ _| \ | |_   _|  |_   _/ _ \ / _ \| |
| | | \___ \| ||  \| | | |      | || | | | | | | |
| |_| |___) | || |\  | | |      | || |_| | |_| | |___
 \___/|____/___|_| \_| |_|      |_| \___/ \___/|_____|

        OSINT Intelligence Tool  |  v1.0  |  Kali Linux
        Built by: [your name]    |  BE Cybersecurity Project
"""

def print_banner():
    console.print(Text(BANNER, style="bold cyan"))
    console.print(Panel(
        "[yellow]This tool is for educational and ethical research only.\n"
        "Only investigate targets you own or have explicit written consent.\n"
        "Unauthorized use may violate IT Act 2000 and similar laws.[/yellow]",
        title="[bold yellow]⚠  Ethical Use Disclaimer[/bold yellow]",
        border_style="yellow",
    ))
