"""
reports/pdf_report.py

Generates a professional PDF report using ReportLab.

Report sections:
  1. Title page with project name, target, and scan metadata.
  2. Disclaimer and scope limitations.
  3. Executive summary with severity distribution table.
  4. Detailed findings (one section per finding).
  5. Footer with page numbers.

Long text, page breaks, empty finding lists, and encoding edge cases
are handled gracefully.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Flowable,
    HRFlowable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

if TYPE_CHECKING:
    from scanner.engine import ScanResult


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

COLOUR_TITLE_BG = colors.HexColor("#1a1a2e")
COLOUR_HEADING = colors.HexColor("#1a1a2e")
COLOUR_ACCENT = colors.HexColor("#3b82d4")
COLOUR_BORDER = colors.HexColor("#e5e7eb")

SEVERITY_COLOURS = {
    "Critical": colors.HexColor("#dc2626"),
    "High":     colors.HexColor("#ea580c"),
    "Medium":   colors.HexColor("#ca8a04"),
    "Low":      colors.HexColor("#2563eb"),
    "Informational": colors.HexColor("#6b7280"),
}

STATUS_COLOURS = {
    "confirmed":    colors.HexColor("#dc2626"),
    "potential":    colors.HexColor("#ea580c"),
    "informational": colors.HexColor("#2563eb"),
    "inconclusive": colors.HexColor("#6b7280"),
    "error":        colors.HexColor("#9333ea"),
}


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=26,
        textColor=colors.white,
        spaceAfter=8,
        alignment=TA_CENTER,
    ))

    styles.add(ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=13,
        textColor=colors.HexColor("#cbd5e1"),
        spaceAfter=4,
        alignment=TA_CENTER,
    ))

    styles.add(ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading1"],
        fontSize=14,
        textColor=COLOUR_HEADING,
        spaceBefore=14,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        "FindingTitle",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=COLOUR_HEADING,
        spaceBefore=10,
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        "BodyText2",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        spaceAfter=4,
        alignment=TA_JUSTIFY,
    ))

    styles.add(ParagraphStyle(
        "Label",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#57606a"),
        spaceAfter=2,
    ))

    styles.add(ParagraphStyle(
        "CodeBlock",
        parent=styles["Code"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1f2328"),
        backColor=colors.HexColor("#f6f8fa"),
        spaceAfter=4,
        leftIndent=8,
        rightIndent=8,
        borderPad=4,
    ))

    styles.add(ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#57606a"),
        leading=12,
        alignment=TA_JUSTIFY,
    ))

    return styles


# ---------------------------------------------------------------------------
# Page template with footer
# ---------------------------------------------------------------------------

class _FooterCanvas(BaseDocTemplate):
    """BaseDocTemplate subclass that draws a page footer."""

    def __init__(self, filename_or_buffer, target_url: str, **kwargs):
        self._target_url = target_url
        super().__init__(filename_or_buffer, **kwargs)

    def handle_pageBegin(self):
        super().handle_pageBegin()

    def afterPage(self):
        canvas = self.canv
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#57606a"))
        width, height = A4
        y = 1.2 * cm
        canvas.drawString(2 * cm, y,
                          f"Automated Web Security Scanner  |  Target: {self._target_url}")
        canvas.drawRightString(width - 2 * cm, y,
                               f"Page {self.page}")
        canvas.setStrokeColor(colors.HexColor("#e5e7eb"))
        canvas.line(2 * cm, y + 0.35 * cm, width - 2 * cm, y + 0.35 * cm)
        canvas.restoreState()


# ---------------------------------------------------------------------------
# Content builders
# ---------------------------------------------------------------------------

def _title_block(styles, target_url: str, timestamp: str,
                  scan_status: str) -> list:
    """Return flowables for the cover-page header band."""
    # Use a coloured table as a banner
    banner_data = [[
        Paragraph("Automated Web Security Scanner", styles["ReportTitle"]),
    ]]
    banner = Table(banner_data, colWidths=[17 * cm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOUR_TITLE_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 20),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
        ("LEFTPADDING",   (0, 0), (-1, -1), 20),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 20),
    ]))

    subtitle = Paragraph("Security Audit Report", styles["ReportSubtitle"])
    subtitle_table = Table([[subtitle]], colWidths=[17 * cm])
    subtitle_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#16213e")),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))

    meta_rows = [
        ["Target URL:", _truncate(target_url, 70)],
        ["Scan Date:", timestamp[:19].replace("T", " ") + " UTC"],
        ["Scan Status:", scan_status.title()],
    ]
    meta_table = Table(meta_rows, colWidths=[4 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",  (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#f7f8fa"), colors.white]),
        ("GRID",    (0, 0), (-1, -1), 0.5, COLOUR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))

    return [banner, subtitle_table, Spacer(1, 0.5 * cm), meta_table,
            Spacer(1, 0.5 * cm)]


def _disclaimer_block(styles) -> list:
    disclaimer_text = (
        "<b>Disclaimer and Scope Limitations</b><br/><br/>"
        "This report was produced by the Automated Web Security Scanner for "
        "educational and authorised security assessment purposes. Findings "
        "represent observations and potential risks identified through safe, "
        "non-intrusive HTTP header analysis. They do <b>not</b> constitute "
        "confirmed exploitable vulnerabilities and have not been verified "
        "through active exploitation.<br/><br/>"
        "<b>Limitations:</b> Analysis is confined to HTTP response headers. "
        "Application logic, authentication flows, TLS cipher suites, "
        "server-side code, and authenticated resources are outside scope. "
        "Results reflect a single point-in-time snapshot and may not capture "
        "dynamically changing configurations.<br/><br/>"
        "<b>Authorised use only.</b> Use this tool only against systems you "
        "are authorised to test."
    )
    return [
        Paragraph("Disclaimer", styles["SectionHeading"]),
        HRFlowable(width="100%", thickness=1, color=COLOUR_BORDER),
        Spacer(1, 0.2 * cm),
        Paragraph(disclaimer_text, styles["Disclaimer"]),
        Spacer(1, 0.4 * cm),
    ]


def _summary_block(styles, summary: dict) -> list:
    total = summary.get("total", 0)
    rows = [
        ["Severity", "Count", "Description"],
        ["Critical", str(summary.get("critical", 0)),
         "Immediate action required"],
        ["High", str(summary.get("high", 0)),
         "Address as a priority"],
        ["Medium", str(summary.get("medium", 0)),
         "Should be remediated"],
        ["Low", str(summary.get("low", 0)),
         "Consider remediating"],
        ["Informational", str(summary.get("informational", 0)),
         "Awareness only"],
        ["TOTAL", str(total), ""],
    ]

    tbl = Table(rows, colWidths=[4 * cm, 3 * cm, 10 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), COLOUR_HEADING),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2),
         [colors.HexColor("#f7f8fa"), colors.white]),
        ("BACKGROUND",  (0, -1), (-1, -1), colors.HexColor("#f0f4ff")),
        ("FONTNAME",    (0, -1), (-1, -1), "Helvetica-Bold"),
        ("GRID",   (0, 0), (-1, -1), 0.5, COLOUR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))

    # Colour severity labels
    severity_row_map = {
        1: "Critical", 2: "High", 3: "Medium",
        4: "Low", 5: "Informational",
    }
    for row_idx, sev in severity_row_map.items():
        c = SEVERITY_COLOURS.get(sev, colors.black)
        tbl.setStyle(TableStyle([
            ("TEXTCOLOR", (0, row_idx), (0, row_idx), c),
            ("FONTNAME",  (0, row_idx), (0, row_idx), "Helvetica-Bold"),
        ]))

    return [
        Paragraph("Executive Summary", styles["SectionHeading"]),
        HRFlowable(width="100%", thickness=1, color=COLOUR_BORDER),
        Spacer(1, 0.2 * cm),
        tbl,
        Spacer(1, 0.4 * cm),
    ]


def _findings_block(styles, findings: list) -> list:
    if not findings:
        return [
            Paragraph("Findings", styles["SectionHeading"]),
            HRFlowable(width="100%", thickness=1, color=COLOUR_BORDER),
            Spacer(1, 0.2 * cm),
            Paragraph("No findings were generated for this scan.", styles["BodyText2"]),
        ]

    flowables: list = [
        Paragraph("Detailed Findings", styles["SectionHeading"]),
        HRFlowable(width="100%", thickness=1, color=COLOUR_BORDER),
        Spacer(1, 0.2 * cm),
    ]

    # Sort: Critical → High → Medium → Low → Informational
    severity_order = {"Critical": 0, "High": 1, "Medium": 2,
                      "Low": 3, "Informational": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity, 9), f.rule_id)
    )

    for idx, finding in enumerate(sorted_findings, 1):
        sev_colour = SEVERITY_COLOURS.get(finding.severity, colors.black)

        # Finding header table
        header_data = [[
            Paragraph(
                f'<font color="#{_hex(sev_colour)}">[{finding.severity}]</font>  '
                f'{idx}. {_escape(finding.title)}',
                styles["FindingTitle"]
            ),
        ]]
        hdr_tbl = Table(header_data, colWidths=[17 * cm])
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f8fa")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.5, sev_colour),
        ]))
        flowables.append(hdr_tbl)

        # Meta row
        meta_data = [
            ["Rule ID:", finding.rule_id,
             "Category:", finding.category,
             "Confidence:", finding.confidence,
             "Status:", finding.status.title()],
        ]
        meta_tbl = Table(meta_data,
                         colWidths=[2.2*cm, 3.2*cm, 2*cm, 3*cm,
                                    2.4*cm, 2.3*cm, 1.8*cm, 2.1*cm])
        meta_tbl.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",  (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTNAME",  (4, 0), (4, -1), "Helvetica-Bold"),
            ("FONTNAME",  (6, 0), (6, -1), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 8),
            ("BACKGROUND",(0, 0), (-1, -1), colors.HexColor("#fafafa")),
            ("GRID", (0, 0), (-1, -1), 0.3, COLOUR_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        flowables.append(meta_tbl)
        flowables.append(Spacer(1, 0.15 * cm))

        # Detail fields
        fields = [
            ("Explanation",     finding.explanation),
            ("Potential Impact", finding.potential_impact),
            ("Remediation",     finding.remediation),
            ("Evidence",        finding.evidence),
        ]
        for label, value in fields:
            flowables.append(
                Paragraph(f"<b>{label}</b>", styles["Label"])
            )
            flowables.append(
                Paragraph(_escape(value or "N/A"), styles["BodyText2"])
            )

        flowables.append(Spacer(1, 0.4 * cm))

    return flowables


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _escape(text: str) -> str:
    """Escape XML special chars for ReportLab Paragraph."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 1] + "…"


def _hex(colour) -> str:
    """Convert a ReportLab colour to a 6-digit hex string (no #)."""
    try:
        r = int(colour.red * 255)
        g = int(colour.green * 255)
        b = int(colour.blue * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except Exception:
        return "000000"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_pdf_report(scan_result: "ScanResult") -> bytes:
    """
    Generate a PDF report for *scan_result* and return raw bytes.

    Uses ReportLab Platypus.  Safe for use with an in-memory buffer.
    """
    styles = _build_styles()
    buffer = io.BytesIO()

    doc = _FooterCanvas(
        buffer,
        target_url=scan_result.target_url,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2.5 * cm,
    )

    frame = Frame(
        doc.leftMargin, doc.bottomMargin,
        doc.width, doc.height,
        id="normal",
    )
    template = PageTemplate(id="main", frames=[frame])
    doc.addPageTemplates([template])

    story: list = []

    # Title block
    story += _title_block(
        styles,
        target_url=scan_result.target_url,
        timestamp=scan_result.timestamp,
        scan_status=scan_result.status,
    )

    story.append(PageBreak())

    # Disclaimer
    story += _disclaimer_block(styles)

    # Summary
    story += _summary_block(styles, scan_result.summary)

    story.append(PageBreak())

    # Findings
    story += _findings_block(styles, scan_result.findings)

    # Errors / scan issues
    if scan_result.errors:
        story.append(Paragraph("Scan Errors / Warnings", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_BORDER))
        story.append(Spacer(1, 0.2 * cm))
        for err in scan_result.errors:
            story.append(Paragraph(f"• {_escape(err)}", styles["BodyText2"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()


def safe_filename(scan_id: str) -> str:
    """Return a safe download filename for the PDF report."""
    clean_id = "".join(c for c in scan_id if c.isalnum() or c in "-_")
    return f"scan_report_{clean_id[:36]}.pdf"
