# ─────────────────────────────────────────────────────────────
#  main.py  —  OSINT Tool  (FINAL VERSION — all modules live)
# ─────────────────────────────────────────────────────────────

import json
import os
import sys
from datetime import datetime

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.prompt  import Prompt

from utils.config  import load_config
from utils.logger  import (
    log_info, log_error, log_warning,
    log_success, log_module, print_banner
)

from modules.phone_lookup      import lookup_phone
from modules.social_mapper     import lookup_username
from modules.ip_intel          import lookup_ip
from modules.email_intel       import lookup_email
from modules.avatar_fingerprint import analyze_image
from modules.report_generator  import generate_report

console = Console()


def save_output(data: dict, label: str) -> str:
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename  = f"output/scan_{label}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log_success(f"Saved → [cyan]{filename}[/cyan]")
    return filename


def print_menu():
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Num",    style="bold cyan",  width=4,  no_wrap=True)
    table.add_column("Option", style="white",      width=26, no_wrap=True)
    table.add_column("Status", style="dim",        width=20, no_wrap=True)

    table.add_row("1", "Phone Number Lookup",   "✔  ready")
    table.add_row("2", "IP Address Lookup",     "✔  ready")
    table.add_row("3", "Email Intel",           "✔  ready")
    table.add_row("4", "Social Media Mapper",   "✔  ready")
    table.add_row("5", "Image OSINT + Steg",    "✔  ready")
    table.add_row("6", "Generate PDF Report",   "✔  ready")
    table.add_row("", "",                        "")
    table.add_row("0", "Exit",                  "")

    console.print(Panel(
        table,
        title="[bold cyan]  OSINT Intelligence Tool — v1.0  [/bold cyan]",
        subtitle="[dim]Type a number and press Enter[/dim]",
        border_style="cyan",
        padding=(1, 3),
    ))


def get_target(prompt_text: str, example: str) -> str | None:
    console.print(f"  [dim]Example: {example}[/dim]")
    value = Prompt.ask(
        f"  [bold cyan]  ›[/bold cyan] {prompt_text}"
    ).strip()
    if not value:
        log_warning("No input — returning to menu.")
        return None
    return value


# ── MODULE HANDLERS ───────────────────────────────────────────

def handle_phone(config):
    log_module("Phone Number Lookup")
    number = get_target("Enter phone number",
                        "+919876543210  or  +14155552671")
    if not number: return
    result = lookup_phone(number, config)
    if result:
        safe = number.replace("+","").replace(" ","").replace("-","")
        save_output(result, f"phone_{safe}")
    else:
        log_error("Phone lookup failed.")


def handle_ip(config):
    log_module("IP Address Lookup")
    ip = get_target("Enter IP address",
                    "8.8.8.8  or  1.1.1.1")
    if not ip: return
    result = lookup_ip(ip, config)
    if result:
        save_output(result, f"ip_{ip.replace('.','_')}")
    else:
        log_error("IP lookup failed.")


def handle_email(config):
    log_module("Email Intel")
    email = get_target("Enter email address",
                       "john@example.com")
    if not email: return
    result = lookup_email(email, config)
    if result:
        safe = email.replace("@","_").replace(".","_").lower()
        save_output(result, f"email_{safe}")
    else:
        log_error("Email lookup failed.")


def handle_social(config):
    log_module("Social Media Mapper")
    username = get_target("Enter username (no @ symbol)",
                          "johndoe  or  hackerman99")
    if not username: return
    username = username.lstrip("@")
    result = lookup_username(username, config)
    if result and result.get("found"):
        save_output(result, f"username_{username.lower()}")
    else:
        log_warning(f"No profiles found for '{username}'.")


def handle_image(config):
    log_module("Image OSINT + Steganography")

    console.print(Panel(
        "  [cyan]1.[/cyan] Full path to local image\n"
        "     [dim]/home/hacker/Downloads/photo.jpg[/dim]\n\n"
        "  [cyan]2.[/cyan] Direct URL to online image\n"
        "     [dim]https://example.com/photo.png[/dim]",
        title="[bold]Input options[/bold]",
        border_style="dim",
    ))

    image_input = get_target(
        "Enter image path or URL",
        "/home/hacker/photo.jpg"
    )
    if not image_input: return

    compare_raw = Prompt.ask(
        "  [bold cyan]  ›[/bold cyan] "
        "Second image for comparison? (Enter to skip)"
    ).strip()

    result = analyze_image(
        image_input, config,
        compare_with=compare_raw or None
    )
    if result:
        safe = (os.path.basename(image_input)
                .replace(" ","_").replace(".","_").lower()[:30])
        save_output(result, f"image_{safe}")
    else:
        log_error("Image analysis failed.")


def handle_report(config):
    log_module("PDF Report Generator")

    # Show what's available in output/
    if os.path.exists("output"):
        files = [f for f in os.listdir("output")
                 if f.endswith(".json") and f.startswith("scan_")]
        if files:
            console.print(
                f"\n  [green]Found {len(files)} scan file(s)"
                f" in output/[/green]"
            )
            for f in sorted(files)[:8]:
                console.print(f"  [dim]  • {f}[/dim]")
            if len(files) > 8:
                console.print(
                    f"  [dim]  ... and {len(files)-8} more[/dim]"
                )
        else:
            log_warning(
                "No scan files in output/ yet.\n"
                "  Run some scans first (options 1–5), "
                "then come back to generate the report."
            )
            return
    else:
        log_warning("output/ folder doesn't exist yet. Run some scans first.")
        return

    # Ask for target name
    target = Prompt.ask(
        "\n  [bold cyan]  ›[/bold cyan] "
        "Enter a label for this report "
        "(target name / case name)"
    ).strip() or "Unknown Target"

    # Generate the PDF
    pdf_path = generate_report(
        target=target,
        output_dir="output"
    )

    if pdf_path:
        console.print(Panel(
            f"[bold green]✔  PDF report created![/bold green]\n\n"
            f"  File: [cyan]{pdf_path}[/cyan]\n\n"
            f"  Open it with:\n"
            f"  [dim]evince {pdf_path}[/dim]\n"
            f"  [dim]xdg-open {pdf_path}[/dim]",
            title="[bold]Report Ready[/bold]",
            border_style="green",
        ))
    else:
        log_error(
            "Report generation failed.\n"
            "  Make sure reportlab is installed: "
            "pip install reportlab"
        )


# ── MAIN LOOP ─────────────────────────────────────────────────

def main():
    print_banner()
    config = load_config()
    console.print(
        "\n[bold green]✔  All modules loaded.[/bold green] "
        "Ready.\n"
    )

    handlers = {
        "1": handle_phone,
        "2": handle_ip,
        "3": handle_email,
        "4": handle_social,
        "5": handle_image,
        "6": handle_report,
    }

    while True:
        print_menu()
        try:
            choice = Prompt.ask(
                "  [bold cyan]Select option[/bold cyan]",
                choices=["0","1","2","3","4","5","6"],
                show_choices=False,
            ).strip()
        except KeyboardInterrupt:
            console.print(
                "\n\n[bold yellow]Ctrl+C — exiting.[/bold yellow]"
            )
            break

        if choice == "0":
            console.print(Panel(
                "[cyan]Thank you. Use this knowledge ethically.[/cyan]",
                title="[bold]Goodbye[/bold]",
                border_style="cyan",
            ))
            break

        handler = handlers.get(choice)
        if handler:
            try:
                handler(config)
            except KeyboardInterrupt:
                console.print(
                    "\n[yellow]Scan interrupted — back to menu.[/yellow]"
                )
            except Exception as e:
            	import traceback
            	
            	log_error(f"Module error: {e}")
            	traceback.print_exc()
            	log_info("Returning to menu...")

        console.print()


if __name__ == "__main__":
    main()
