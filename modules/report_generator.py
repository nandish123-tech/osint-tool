# ─────────────────────────────────────────────────────────────
#  modules/report_generator.py  —  PDF Report Generator
#
#  WHAT IT DOES:
#    Reads all saved JSON scan files from the output/ folder,
#    combines all findings, and generates a professional PDF
#    report with:
#      • Cover page (target summary, scan date, tool info)
#      • Table of contents
#      • Phone Intel section
#      • IP Intel section
#      • Email Intel section
#      • Social Media section
#      • Image OSINT section
#      • Combined findings & OSINT links
#      • Ethical disclaimer footer on every page
#
#  LIBRARY USED: reportlab
#    pip install reportlab
#    reportlab is the standard Python PDF generation library.
#    It works by drawing elements on a "canvas" — like painting
#    on paper. You set x,y coordinates and draw text/lines/shapes.
#
#  HOW PDF COORDINATES WORK IN REPORTLAB:
#    Origin (0,0) is at BOTTOM-LEFT of the page.
#    Y increases UPWARD (opposite of screen coordinates).
#    A4 page = 595 x 842 points (1 point = 1/72 inch)
#    So top of page = y=842, bottom = y=0
# ─────────────────────────────────────────────────────────────

import os
import json
import glob
from datetime import datetime

# reportlab imports
# pip install reportlab
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate,    # manages page layout automatically
    Paragraph,            # text block with word-wrap
    Spacer,               # empty vertical space
    Table,                # data table
    TableStyle,           # styling for tables
    PageBreak,            # forces a new page
    HRFlowable,           # horizontal line
    KeepTogether,         # keeps a block on one page
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing, Line

from utils.logger import (
    log_module, log_success, log_error,
    log_info, log_warning, log_result,
)


# ── COLOUR PALETTE ────────────────────────────────────────────
# reportlab uses colors.HexColor() for custom colours.
# We define our palette here so it's consistent everywhere.

C_PRIMARY    = colors.HexColor("#0F6E56")   # dark teal — headers
C_SECONDARY  = colors.HexColor("#1D9E75")   # mid teal — subheaders
C_ACCENT     = colors.HexColor("#185FA5")   # blue — links, highlights
C_DANGER     = colors.HexColor("#993C1D")   # coral — warnings
C_SUCCESS    = colors.HexColor("#3B6D11")   # green — positive findings
C_MUTED      = colors.HexColor("#888780")   # gray — secondary text
C_BORDER     = colors.HexColor("#D3D1C7")   # light gray — borders
C_BG_LIGHT   = colors.HexColor("#F1EFE8")   # off-white — table rows
C_BG_HEADER  = colors.HexColor("#0F6E56")   # teal — table headers
C_BLACK      = colors.HexColor("#2C2C2A")   # near-black — body text
C_WHITE      = colors.white


# ── PAGE DIMENSIONS ──────────────────────────────────────────
PAGE_W, PAGE_H = A4   # 595.27 x 841.89 points
MARGIN = 2.0 * cm     # 2cm margins on all sides


# ════════════════════════════════════════════════════════════
#  STYLE DEFINITIONS
#  reportlab uses ParagraphStyle objects to define how text
#  looks. We create our custom styles here.
# ════════════════════════════════════════════════════════════

def build_styles():
    """
    Creates and returns all paragraph styles used in the report.
    getSampleStyleSheet() gives us the built-in styles as a base.
    We add our own on top.
    """
    base = getSampleStyleSheet()

    styles = {

        # ── Cover page title ──────────────────────────────────
        "cover_title": ParagraphStyle(
            "cover_title",
            fontName="Helvetica-Bold",
            fontSize=28,
            textColor=C_WHITE,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),

        # ── Cover subtitle ────────────────────────────────────
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontName="Helvetica",
            fontSize=13,
            textColor=colors.HexColor("#C0DD97"),
            alignment=TA_CENTER,
            spaceAfter=6,
        ),

        # ── Section heading (H1) ─────────────────────────────
        # Used at the top of each module section
        "h1": ParagraphStyle(
            "h1",
            fontName="Helvetica-Bold",
            fontSize=16,
            textColor=C_PRIMARY,
            spaceBefore=16,
            spaceAfter=8,
            borderPad=4,
        ),

        # ── Sub-section heading (H2) ─────────────────────────
        "h2": ParagraphStyle(
            "h2",
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=C_SECONDARY,
            spaceBefore=10,
            spaceAfter=4,
        ),

        # ── Normal body text ──────────────────────────────────
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=10,
            textColor=C_BLACK,
            leading=16,        # line height = 16 points
            spaceAfter=4,
        ),

        # ── Small muted text ─────────────────────────────────
        "small": ParagraphStyle(
            "small",
            fontName="Helvetica",
            fontSize=8,
            textColor=C_MUTED,
            leading=12,
        ),

        # ── Warning / alert text ─────────────────────────────
        "warning": ParagraphStyle(
            "warning",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=C_DANGER,
            leading=14,
            spaceAfter=4,
        ),

        # ── Success / found text ─────────────────────────────
        "success": ParagraphStyle(
            "success",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=C_SUCCESS,
            leading=14,
        ),

        # ── Monospace (for hashes, URLs, IPs) ────────────────
        "mono": ParagraphStyle(
            "mono",
            fontName="Courier",
            fontSize=9,
            textColor=C_BLACK,
            leading=13,
            spaceAfter=2,
        ),

        # ── Footer text ───────────────────────────────────────
        "footer": ParagraphStyle(
            "footer",
            fontName="Helvetica",
            fontSize=7,
            textColor=C_MUTED,
            alignment=TA_CENTER,
        ),

        # ── Table of contents entry ───────────────────────────
        "toc": ParagraphStyle(
            "toc",
            fontName="Helvetica",
            fontSize=10,
            textColor=C_BLACK,
            leading=18,
        ),
    }

    return styles


# ════════════════════════════════════════════════════════════
#  HELPER: kv_table()
#  Creates a two-column label/value table from a list of
#  (label, value) tuples. Used for displaying OSINT data.
# ════════════════════════════════════════════════════════════

def kv_table(rows: list, styles: dict) -> Table:
    """
    Builds a styled key-value table.

    Parameters:
        rows   → list of (label, value) tuples
                 Use ("", "") for blank separator rows
        styles → our styles dict

    Returns:
        A reportlab Table object ready to add to the document.
    """

    # Filter out double-empty rows (keep single empties as spacers)
    table_data = []
    for label, value in rows:
        if label == "" and value == "":
            table_data.append(["", ""])
        else:
            table_data.append([
                Paragraph(str(label), styles["h2"]),
                Paragraph(str(value)[:500], styles["body"]),
                # [:500] prevents extremely long values from
                # breaking the table layout
            ])

    # TableStyle defines colours, fonts, borders, padding
    # Each command is a tuple:
    # ("COMMAND", (col_start, row_start), (col_end, row_end), value)
    # (0,0) = top-left cell, (-1,-1) = bottom-right cell

    style = TableStyle([
        # Alternating row background colours
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [C_WHITE, C_BG_LIGHT]),

        # Cell padding (left, bottom, right, top)
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),

        # Outer border
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),

        # Inner horizontal lines (between rows)
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, C_BORDER),

        # Vertical alignment
        ("VALIGN", (0, 0), (-1, -1), "TOP"),

        # Label column width — 35% of table
        ("COLWIDTH", (0, 0), (0, -1), 0.35),
    ])

    t = Table(
        table_data,
        colWidths=[5.5 * cm, 11.5 * cm],  # label col, value col
        style=style,
        repeatRows=0,    # don't repeat header on new pages
    )
    return t


# ════════════════════════════════════════════════════════════
#  HELPER: section_header()
#  Creates a coloured section header bar
# ════════════════════════════════════════════════════════════

def section_header(title: str, styles: dict,
                   icon: str = "●") -> list:
    """
    Returns a list of flowable elements forming a section header:
    a coloured background bar with white title text.
    """
    # We use a Table with one cell to create the coloured bar
    header_table = Table(
        [[Paragraph(f"{icon}  {title}", ParagraphStyle(
            "sh",
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=C_WHITE,
        ))]],
        colWidths=[PAGE_W - 2 * MARGIN],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_PRIMARY),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_PRIMARY]),
        ]),
    )
    return [
        Spacer(1, 0.3 * cm),
        header_table,
        Spacer(1, 0.2 * cm),
    ]


# ════════════════════════════════════════════════════════════
#  LOAD SCAN FILES
#  Reads all JSON files from output/ folder and returns
#  them as a combined dict organised by module type.
# ════════════════════════════════════════════════════════════

def load_scan_files(output_dir: str = "output") -> dict:
    """
    Scans the output/ folder for all JSON scan files.
    Groups them by type (phone, ip, email, username, image).

    glob.glob() finds files matching a pattern.
    "output/scan_*.json" matches all our saved scan files.
    """

    if not os.path.exists(output_dir):
        log_error(f"output/ folder not found. Run some scans first.")
        return {}

    # Find all JSON files
    pattern = os.path.join(output_dir, "scan_*.json")
    files   = sorted(glob.glob(pattern))

    if not files:
        log_warning("No scan files found in output/ folder.")
        log_info("Run phone/ip/email/social scans first, then generate report.")
        return {}

    log_info(f"Found {len(files)} scan file(s):")

    # Organise by type
    scans = {
        "phone":    [],
        "ip":       [],
        "email":    [],
        "username": [],
        "image":    [],
        "combined": [],
        "other":    [],
    }

    for filepath in files:
        filename = os.path.basename(filepath)
        log_result("  Loading", filename)

        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            # Determine type from filename prefix
            if "phone_"    in filename: scans["phone"].append(data)
            elif "ip_"     in filename: scans["ip"].append(data)
            elif "email_"  in filename: scans["email"].append(data)
            elif "username_" in filename: scans["username"].append(data)
            elif "image_"  in filename: scans["image"].append(data)
            elif "combined" in filename: scans["combined"].append(data)
            else:                        scans["other"].append(data)

        except json.JSONDecodeError as e:
            log_warning(f"Could not parse {filename}: {e}")
        except Exception as e:
            log_warning(f"Error loading {filename}: {e}")

    # Count total loaded
    total = sum(len(v) for v in scans.values())
    log_success(f"Loaded {total} scan result(s) successfully")

    return scans


# ════════════════════════════════════════════════════════════
#  PAGE TEMPLATE: header + footer on every page
# ════════════════════════════════════════════════════════════

class ReportTemplate(SimpleDocTemplate):
    """
    Custom document template that adds a header and footer
    to every page automatically.

    SimpleDocTemplate manages page layout — we just override
    the onPage callback to draw our header/footer.
    """

    def __init__(self, filename: str, target: str, scan_date: str):
        self.target    = target
        self.scan_date = scan_date

        super().__init__(
            filename,
            pagesize=A4,
            rightMargin=MARGIN,
            leftMargin=MARGIN,
            topMargin=MARGIN + 0.8 * cm,    # extra space for header
            bottomMargin=MARGIN + 0.8 * cm, # extra space for footer
        )

    def handle_pageBegin(self):
        """Called at the start of each new page."""
        super().handle_pageBegin()
        self._draw_page_elements()

    def _draw_page_elements(self):
        """Draw header and footer on the current page."""
        canvas = self.canv
        w, h   = A4

        # ── Header bar ────────────────────────────────────────
        canvas.saveState()

        # Teal header background rectangle
        canvas.setFillColor(C_PRIMARY)
        canvas.rect(0, h - 1.2 * cm, w, 1.2 * cm, fill=1, stroke=0)

        # Header text — left: tool name, right: target
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(MARGIN, h - 0.75 * cm, "OSINT Intelligence Tool")

        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            w - MARGIN, h - 0.75 * cm,
            f"Target: {self.target}  |  {self.scan_date}"
        )

        # ── Footer bar ────────────────────────────────────────

        # Light gray footer line
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 1.2 * cm, w - MARGIN, 1.2 * cm)

        # Footer text — left: disclaimer, right: page number
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(
            MARGIN, 0.7 * cm,
            "CONFIDENTIAL — For ethical and educational use only. "
            "Unauthorised use may violate applicable laws."
        )
        canvas.drawRightString(
            w - MARGIN, 0.7 * cm,
            f"Page {canvas.getPageNumber()}"
        )

        canvas.restoreState()


# ════════════════════════════════════════════════════════════
#  SECTION BUILDERS
#  Each function builds a list of reportlab "flowables"
#  (Paragraph, Table, Spacer etc.) for one data section.
#  We collect all flowables in a big list and pass to build().
# ════════════════════════════════════════════════════════════

def build_cover_page(scans: dict, styles: dict,
                     target: str) -> list:
    """Builds the cover page elements."""

    elements = []

    # Big coloured cover block using a table
    scan_date = datetime.now().strftime("%d %B %Y  %H:%M:%S")

    # Count what we found
    totals = {
        "phone scans":    len(scans.get("phone",    [])),
        "IP scans":       len(scans.get("ip",       [])),
        "email scans":    len(scans.get("email",    [])),
        "username scans": len(scans.get("username", [])),
        "image scans":    len(scans.get("image",    [])),
    }
    summary_lines = "  |  ".join(
        f"{v} {k}" for k, v in totals.items() if v > 0
    ) or "No scans found"

    cover_data = [[
        Paragraph("OSINT INTELLIGENCE REPORT", styles["cover_title"]),
    ], [
        Paragraph(f"Target: {target}", styles["cover_sub"]),
    ], [
        Paragraph(f"Generated: {scan_date}", styles["cover_sub"]),
    ], [
        Paragraph(summary_lines, ParagraphStyle(
            "cov_sum",
            fontName="Helvetica",
            fontSize=10,
            textColor=colors.HexColor("#E1F5EE"),
            alignment=TA_CENTER,
            spaceAfter=0,
        )),
    ]]

    cover_table = Table(
        cover_data,
        colWidths=[PAGE_W - 2 * MARGIN],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_PRIMARY),
            ("TOPPADDING",    (0, 0), (-1, -1), 18),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
            ("LEFTPADDING",   (0, 0), (-1, -1), 20),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 20),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_PRIMARY]),
            ("BOX",           (0, 0), (-1, -1), 1, C_SECONDARY),
        ]),
    )

    elements.append(Spacer(1, 1.5 * cm))
    elements.append(cover_table)
    elements.append(Spacer(1, 0.8 * cm))

    # Ethical disclaimer box
    disclaimer_data = [[
        Paragraph(
            "⚠  ETHICAL USE DISCLAIMER",
            ParagraphStyle("dh", fontName="Helvetica-Bold",
                           fontSize=11, textColor=C_DANGER)
        ),
    ], [
        Paragraph(
            "This report was generated by the OSINT Intelligence Tool for "
            "educational and ethical research purposes only. All data was "
            "collected from publicly available sources or with explicit "
            "written consent. Unauthorized use of this tool or its output "
            "may violate the IT Act 2000 (India) and similar cybercrime "
            "laws in other jurisdictions. The authors accept no liability "
            "for misuse.",
            styles["body"]
        ),
    ]]

    disclaimer_table = Table(
        disclaimer_data,
        colWidths=[PAGE_W - 2 * MARGIN],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FEF3EE")),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
            ("BOX",           (0, 0), (-1, -1), 1,
             colors.HexColor("#F09595")),
            ("LINEABOVE",     (0, 0), (-1, 0), 3, C_DANGER),
        ]),
    )

    elements.append(disclaimer_table)
    elements.append(Spacer(1, 0.5 * cm))

    # Scan summary table
    elements.append(
        Paragraph("Scan Summary", styles["h1"])
    )

    summary_data = [
        [Paragraph("Module", ParagraphStyle(
            "sh", fontName="Helvetica-Bold",
            fontSize=10, textColor=C_WHITE)),
         Paragraph("Scans", ParagraphStyle(
             "sh2", fontName="Helvetica-Bold",
             fontSize=10, textColor=C_WHITE)),
         Paragraph("Status", ParagraphStyle(
             "sh3", fontName="Helvetica-Bold",
             fontSize=10, textColor=C_WHITE))],
    ]
    for module, count in totals.items():
        status = "✔ Complete" if count > 0 else "— Not run"
        color  = C_SUCCESS if count > 0 else C_MUTED
        summary_data.append([
            Paragraph(module.title(), styles["body"]),
            Paragraph(str(count), styles["body"]),
            Paragraph(status, ParagraphStyle(
                "st", fontName="Helvetica-Bold" if count > 0
                else "Helvetica",
                fontSize=10, textColor=color)),
        ])

    summary_table = Table(
        summary_data,
        colWidths=[8 * cm, 3 * cm, 6 * cm],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1),
             [C_WHITE, C_BG_LIGHT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C_BORDER),
        ]),
    )
    elements.append(summary_table)
    elements.append(PageBreak())  # new page after cover

    return elements


def build_phone_section(phone_list: list, styles: dict) -> list:
    """Builds the Phone Intel section from saved scan data."""
    if not phone_list:
        return []

    elements = []
    elements += section_header("Phone Number Intelligence", styles, "☎")

    for i, data in enumerate(phone_list, 1):
        if len(phone_list) > 1:
            elements.append(
                Paragraph(f"Scan #{i}", styles["h2"])
            )

        rows = [
            ("Input number",     data.get("input",         "N/A")),
            ("E164 format",      data.get("e164",          "N/A")),
            ("International",    data.get("international", "N/A")),
            ("National format",  data.get("national",      "N/A")),
            ("", ""),
            ("Country / Region", data.get("geo_area",      "N/A") +
             f" ({data.get('region_code','')})"),
            ("Country dial code",f"+{data.get('country_code','')}"),
            ("Carrier",          data.get("carrier",       "N/A")),
            ("Line type",        data.get("line_type",     "N/A")),
            ("Timezone(s)",      ", ".join(data.get("timezones", []))),
            ("", ""),
            ("WhatsApp likely",  "Yes" if data.get("whatsapp_likely")
             else "No"),
        ]

        # Add API enrichment if available
        if data.get("api_carrier"):
            rows += [
                ("", ""),
                ("Carrier (API)",    data.get("api_carrier",   "")),
                ("Location (API)",   data.get("api_location",  "")),
                ("Line type (API)",  data.get("api_line_type", "")),
            ]

        # Search links
        links = data.get("search_links", {})
        if links:
            rows += [("", "")]
            for name, url in links.items():
                if url and not url.startswith("http"):
                    continue
                rows.append((
                    name.replace("_", " ").title(),
                    url[:80] + "..." if len(url) > 80 else url
                ))

        elements.append(kv_table(rows, styles))
        elements.append(Spacer(1, 0.4 * cm))

    return elements


def build_ip_section(ip_list: list, styles: dict) -> list:
    """Builds the IP Intel section."""
    if not ip_list:
        return []

    elements = []
    elements += section_header("IP Address Intelligence", styles, "◉")

    for i, data in enumerate(ip_list, 1):
        if len(ip_list) > 1:
            elements.append(Paragraph(f"Scan #{i}", styles["h2"]))

        rows = [
            ("IP Address",      data.get("ip",          "N/A")),
            ("Hostname",        data.get("hostname",     "N/A")),
            ("", ""),
            ("City",            data.get("city",         "N/A")),
            ("Region / State",  data.get("region",       "N/A")),
            ("Country",         data.get("country",      "N/A")),
            ("Postal code",     data.get("postal",       "N/A")),
            ("Timezone",        data.get("timezone",     "N/A")),
            ("Coordinates",     data.get("coordinates",  "N/A")),
            ("", ""),
            ("ISP",             data.get("isp",          "N/A")),
            ("Organisation",    data.get("org",          "N/A")),
            ("ASN",             data.get("asn",          "N/A")),
            ("", ""),
            ("Proxy / VPN",     "YES ⚠" if data.get("is_proxy")
             else "No"),
            ("Hosting / DC",    "YES ⚠" if data.get("is_hosting")
             else "No"),
            ("Mobile network",  "Yes"   if data.get("is_mobile")
             else "No"),
        ]

        links = data.get("links", {})
        if links:
            rows += [("", "")]
            for name, url in links.items():
                if url and url.startswith("http"):
                    rows.append((
                        name.replace("_", " ").title(),
                        url[:80]
                    ))

        elements.append(kv_table(rows, styles))
        elements.append(Spacer(1, 0.4 * cm))

    return elements


def build_email_section(email_list: list, styles: dict) -> list:
    """Builds the Email Intel section."""
    if not email_list:
        return []

    elements = []
    elements += section_header("Email Intelligence", styles, "✉")

    for i, data in enumerate(email_list, 1):
        if len(email_list) > 1:
            elements.append(Paragraph(f"Scan #{i}", styles["h2"]))

        rows = [
            ("Email",           data.get("input",          "N/A")),
            ("Username part",   data.get("username",        "N/A")),
            ("Domain",          data.get("domain",          "N/A")),
            ("Provider type",   data.get("provider_type",   "N/A")),
            ("Disposable",      "YES ⚠ FAKE"
             if data.get("is_disposable") else "No"),
            ("", ""),
        ]

        # DNS info
        dns = data.get("dns", {})
        if dns:
            rows += [
                ("Domain exists",    "Yes" if dns.get("domain_exists")
                 else "No ✖"),
                ("Can receive mail", "Yes" if dns.get("has_mx")
                 else "No ✖"),
                ("Mail servers",     ", ".join(
                    dns.get("mail_servers", [])[:2]) or "None"),
                ("", ""),
            ]

        # Abstract API
        ab = data.get("abstract", {})
        if ab:
            rows += [
                ("Deliverability",   ab.get("deliverability", "N/A")),
                ("Quality score",    f"{ab.get('quality_score',0):.2f}/1.0"),
                ("SMTP valid",       "Yes" if ab.get("is_smtp_valid")
                 else "No"),
                ("Catchall domain",  "Yes" if ab.get("is_catchall")
                 else "No"),
                ("", ""),
            ]

        # HIBP breaches
        hibp = data.get("hibp", {})
        if hibp:
            if hibp.get("found_in_breaches"):
                rows.append((
                    "Data breaches",
                    f"FOUND IN {hibp['breach_count']} BREACH(ES) ⚠"
                ))
                for b in hibp.get("breaches", [])[:5]:
                    rows.append((
                        f"  {b['name']}",
                        f"{b['date']} — "
                        f"{', '.join(b.get('data_classes',[])[:3])}"
                    ))
            else:
                rows.append((
                    "Data breaches",
                    "Not found in any known breaches ✔"
                ))

        elements.append(kv_table(rows, styles))
        elements.append(Spacer(1, 0.4 * cm))

    return elements


def build_social_section(username_list: list,
                         styles: dict) -> list:
    """Builds the Social Media Mapper section."""
    if not username_list:
        return []

    elements = []
    elements += section_header("Social Media Intelligence",
                               styles, "◈")

    for i, data in enumerate(username_list, 1):
        if len(username_list) > 1:
            elements.append(Paragraph(f"Scan #{i}", styles["h2"]))

        username = data.get("username", "Unknown")
        found    = data.get("found",    [])
        total    = data.get("total_checked", 0)

        elements.append(Paragraph(
            f"Username: <b>{username}</b>  —  "
            f"Found on {len(found)} of {total} platforms",
            styles["body"]
        ))
        elements.append(Spacer(1, 0.2 * cm))

        if found:
            # Build a table of found profiles
            profile_data = [[
                Paragraph("Platform", ParagraphStyle(
                    "ph", fontName="Helvetica-Bold",
                    fontSize=10, textColor=C_WHITE)),
                Paragraph("Profile URL", ParagraphStyle(
                    "ph2", fontName="Helvetica-Bold",
                    fontSize=10, textColor=C_WHITE)),
                Paragraph("Status", ParagraphStyle(
                    "ph3", fontName="Helvetica-Bold",
                    fontSize=10, textColor=C_WHITE)),
            ]]

            for profile in found:
                url = profile.get("url", "")
                note = profile.get("note", "")
                profile_data.append([
                    Paragraph(profile.get("platform", ""),
                              styles["body"]),
                    Paragraph(
                        url[:60] + "..." if len(url) > 60 else url,
                        styles["mono"]
                    ),
                    Paragraph(
                        note or f"HTTP {profile.get('status',200)}",
                        styles["small"]
                    ),
                ])

            profile_table = Table(
                profile_data,
                colWidths=[3.5 * cm, 10.5 * cm, 3 * cm],
                style=TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
                    ("ROWBACKGROUNDS",(0, 1), (-1, -1),
                     [C_WHITE, C_BG_LIGHT]),
                    ("TOPPADDING",    (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
                    ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C_BORDER),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ]),
            )
            elements.append(profile_table)
        else:
            elements.append(Paragraph(
                "No profiles found for this username.",
                styles["small"]
            ))

        elements.append(Spacer(1, 0.4 * cm))

    return elements


def build_image_section(image_list: list, styles: dict) -> list:
    """Builds the Image OSINT section."""
    if not image_list:
        return []

    elements = []
    elements += section_header("Image OSINT Analysis", styles, "◎")

    for i, data in enumerate(image_list, 1):
        if len(image_list) > 1:
            elements.append(Paragraph(f"Scan #{i}", styles["h2"]))

        fi   = data.get("file_info",      {})
        exif = data.get("exif",           {})
        hsh  = data.get("hashes",         {})
        steg = data.get("steganography",  {})

        # File info
        elements.append(Paragraph("File Information", styles["h2"]))
        rows = [
            ("Filename",     fi.get("filename",   "N/A")),
            ("Format",       fi.get("format",     "N/A")),
            ("Dimensions",   fi.get("dimensions", "N/A")),
            ("File size",    fi.get("file_size",  "N/A")),
            ("MD5 hash",     fi.get("md5",        "N/A")),
            ("SHA1 hash",    fi.get("sha1",       "N/A")),
        ]
        elements.append(kv_table(rows, styles))
        elements.append(Spacer(1, 0.2 * cm))

        # EXIF
        elements.append(Paragraph("EXIF Metadata", styles["h2"]))
        if exif.get("has_exif"):
            cam = exif.get("camera",   {})
            dt  = exif.get("datetime", {})
            gps = exif.get("gps",      {})
            s   = exif.get("settings", {})
            dev = exif.get("device",   {})
            exif_rows = [
                ("Camera make",   cam.get("make",  "N/A")),
                ("Camera model",  cam.get("model", "N/A")),
                ("Lens",          cam.get("lens_model", "N/A")),
                ("Date taken",    dt.get("taken_readable",
                                  dt.get("taken","N/A"))),
                ("Timezone",      dt.get("timezone","N/A")),
                ("GPS coords",    gps.get("coords_str","Not found")),
                ("Altitude",      f"{gps.get('altitude_m')}m"
                 if gps.get("altitude_m") else "N/A"),
                ("Google Maps",   gps.get("google_maps","N/A")),
                ("ISO",           s.get("iso","N/A")),
                ("Shutter speed", s.get("shutter_speed","N/A")),
                ("Aperture",      s.get("aperture","N/A")),
                ("Focal length",  s.get("focal_length","N/A")),
                ("Flash",         s.get("flash","N/A")),
                ("Software/OS",   dev.get("software","N/A")),
            ]
            elements.append(kv_table(exif_rows, styles))
        else:
            elements.append(Paragraph(
                "No EXIF data — web/screenshot image "
                "or EXIF was stripped by social media.",
                styles["small"]
            ))

        elements.append(Spacer(1, 0.2 * cm))

        # Steganography
        elements.append(Paragraph("Steganography Analysis",
                                  styles["h2"]))
        steg_rows = [
            ("Detected",    "YES ⚠" if steg.get("steg_detected")
             else "No"),
            ("Confidence",  steg.get("confidence", "N/A")),
        ]
        if steg.get("checks"):
            steg_rows.append(("Notes", "; ".join(steg["checks"][:3])))
        elements.append(kv_table(steg_rows, styles))
        elements.append(Spacer(1, 0.2 * cm))

        # Hashes
        elements.append(Paragraph("Perceptual Hashes (pHash)",
                                  styles["h2"]))
        hash_rows = [
            ("pHash", hsh.get("phash", "N/A")),
            ("aHash", hsh.get("ahash", "N/A")),
            ("dHash", hsh.get("dhash", "N/A")),
        ]
        elements.append(kv_table(hash_rows, styles))
        elements.append(Spacer(1, 0.4 * cm))

    return elements


# ════════════════════════════════════════════════════════════
#  MAIN FUNCTION
# ════════════════════════════════════════════════════════════

def generate_report(target: str = "Unknown Target",
                    output_dir: str = "output") -> str | None:
    """
    Master function — loads all scans and builds the PDF.

    Parameters:
        target     → label for the report (e.g. target name/number)
        output_dir → folder where JSON scans are saved

    Returns:
        Path to the generated PDF, or None if failed.
    """

    log_module("Report Generator")
    log_info(f"Building PDF report for target: {target}")

    # Step 1: Load all scan files
    scans = load_scan_files(output_dir)

    total_scans = sum(len(v) for v in scans.values())
    if total_scans == 0:
        log_error("No scan data found. Run some scans first.")
        log_info("Run phone/ip/email/social/image scans, then come back here.")
        return None

    # Step 2: Set up PDF file path
    os.makedirs(output_dir, exist_ok=True)
    timestamp  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_target = (
        target
        .replace(" ", "_")
        .replace("/", "_")
        .replace("\\","_")
        .replace("+", "")
        [:30]    # max 30 chars in filename
    )
    pdf_path = os.path.join(
        output_dir, f"OSINT_Report_{safe_target}_{timestamp}.pdf"
    )

    log_info(f"Output file: {pdf_path}")

    # Step 3: Build styles
    styles    = build_styles()
    scan_date = datetime.now().strftime("%d %B %Y  %H:%M")

    # Step 4: Create the document
    # ReportTemplate is our custom class with header/footer
    doc = ReportTemplate(pdf_path, target, scan_date)

    # Step 5: Build all content elements
    # Each build_*() function returns a list of flowables.
    # We concatenate them all into one big list.

    elements = []

    # Cover page
    elements += build_cover_page(scans, styles, target)

    # Phone section
    elements += build_phone_section(
        scans.get("phone", []), styles
    )

    # IP section
    if scans.get("phone") and scans.get("ip"):
        elements.append(PageBreak())
    elements += build_ip_section(
        scans.get("ip", []), styles
    )

    # Email section
    if scans.get("ip") or scans.get("phone"):
        elements.append(PageBreak())
    elements += build_email_section(
        scans.get("email", []), styles
    )

    # Social mapper section
    if any([scans.get("phone"), scans.get("ip"),
            scans.get("email")]):
        elements.append(PageBreak())
    elements += build_social_section(
        scans.get("username", []), styles
    )

    # Image section
    elements += build_image_section(
        scans.get("image", []), styles
    )

    # Final page — raw data note
    elements.append(PageBreak())
    elements += section_header("Raw Data Files", styles, "◇")
    elements.append(Paragraph(
        "All raw scan data is saved as JSON files in the "
        f"<b>{output_dir}/</b> folder. "
        "These files can be imported into other tools for "
        "further analysis.",
        styles["body"]
    ))
    elements.append(Spacer(1, 0.3 * cm))

    # List all JSON files
    json_files = sorted(glob.glob(
        os.path.join(output_dir, "scan_*.json")
    ))
    file_rows = [
        [Paragraph("File", ParagraphStyle(
            "fh", fontName="Helvetica-Bold",
            fontSize=10, textColor=C_WHITE)),
         Paragraph("Size", ParagraphStyle(
             "fh2", fontName="Helvetica-Bold",
             fontSize=10, textColor=C_WHITE))],
    ]
    for fp in json_files:
        size = os.path.getsize(fp)
        file_rows.append([
            Paragraph(os.path.basename(fp), styles["mono"]),
            Paragraph(f"{size:,} bytes", styles["small"]),
        ])

    file_table = Table(
        file_rows,
        colWidths=[13 * cm, 4 * cm],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1),
             [C_WHITE, C_BG_LIGHT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ]),
    )
    elements.append(file_table)

    # Step 6: Build the PDF
    # doc.build() renders all elements into the actual PDF file.
    # It calls our header/footer on every page automatically.
    try:
        log_info("Rendering PDF...")
        doc.build(elements)
        log_success(f"PDF report generated: {pdf_path}")
        return pdf_path

    except Exception as e:
        log_error(f"PDF generation failed: {e}")
        import traceback; traceback.print_exc()
        return None
