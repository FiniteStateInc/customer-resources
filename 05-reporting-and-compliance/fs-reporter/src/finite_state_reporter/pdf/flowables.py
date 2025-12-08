"""
Custom flowables for professional PDF reports.
Includes StatsBox, SectionHeading, and other enhanced components.
"""

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Flowable, Paragraph, Spacer, Table
from reportlab.platypus.tables import TableStyle

from . import colors
from .styles import get_stylesheet

_stylesheet = get_stylesheet()


class SectionHeading(Paragraph):
    """Professional section heading with colored styling."""

    def __init__(self, text, style=None, **kwargs):
        """
        Create a section heading with professional styling.

        :param text: Heading text
        :param style: Optional custom style (defaults to SectionHeading)
        """
        if style is None:
            style = _stylesheet["SectionHeading"]

        # Format text with uppercase transformation
        formatted_text = f"{text.upper()}"
        super().__init__(formatted_text, style=style, **kwargs)


class StatsBox(Table):
    """Professional statistics box with background and styling."""

    def __init__(
        self,
        labels,
        data,
        orientation="horizontal",
        spaceBefore=None,
        spaceAfter=None,
        **kwargs,
    ):
        """
        Create a professional statistics box.

        :param labels: List of labels for each statistic
        :param data: List of data values for each statistic
        :param orientation: "horizontal" or "vertical" layout
        :param spaceBefore: Space before the box
        :param spaceAfter: Space after the box
        """
        if len(labels) != len(data):
            raise ValueError("Labels and data must have the same length")

        # Prepare data based on orientation
        if orientation == "horizontal":
            table_data = self._zip_horizontal(data, labels)
            style_name = "StatsBoxHorizontal"
        else:
            table_data = self._zip_vertical(data, labels)
            style_name = "StatsBoxVertical"

        # Get table style
        table_style = None
        for style in _stylesheet.byName.values():
            if hasattr(style, "name") and style.name == style_name:
                table_style = style
                break

        super().__init__(
            table_data,
            style=table_style,
            spaceBefore=spaceBefore,
            spaceAfter=spaceAfter,
            **kwargs,
        )

    @staticmethod
    def _zip_horizontal(data, labels):
        """Create horizontal layout data."""
        # Create header row with data values
        header_row = []
        for value in data:
            p = Paragraph(f"<b>{value}</b>", _stylesheet["StatTextHeading"])
            header_row.append(p)

        # Create label row
        label_row = []
        for label in labels:
            p = Paragraph(label, _stylesheet["StatText"])
            label_row.append(p)

        return [header_row, label_row]

    @staticmethod
    def _zip_vertical(data, labels):
        """Create vertical layout data."""
        table_data = []
        for label, value in zip(labels, data):
            value_p = Paragraph(f"<b>{value}</b>", _stylesheet["StatTextHeading"])
            label_p = Paragraph(label, _stylesheet["StatText"])
            table_data.append([value_p, label_p])

        return table_data


class BlockQuote(Flowable):
    """Professional block quote with background and border."""

    def __init__(self, text, fill_color=None, border_color=None):
        """
        Create a professional block quote.

        :param text: Quote text
        :param fill_color: Background fill color
        :param border_color: Left border color
        """
        if fill_color is None:
            fill_color = colors.whitesmoke
        if border_color is None:
            border_color = colors.charcoal

        indent = 3 / 16 * inch
        self.para = Paragraph(
            text,
            ParagraphStyle(
                name="BlockQuote",
                parent=_stylesheet["Normal"],
                fontSize=10,
                spaceBefore=0,
                spaceAfter=0,
                leftIndent=indent,
                rightIndent=indent,
            ),
        )
        self.fillColor = fill_color
        self.borderColor = border_color
        super().__init__()

    def wrap(self, *args):
        """Calculate dimensions."""
        w, h = self.para.wrap(*args)
        style = self.para.style
        self.width = w
        self.height = h + (style.leftIndent * 2)
        return self.width, self.height

    def draw(self):
        """Draw the block quote."""
        self.canv.saveState()

        # Draw background
        self.canv.setFillColor(self.fillColor)
        self.canv.rect(0, 0, self.width, self.height, stroke=0, fill=1)

        # Draw left border
        self.canv.setFillColor(self.borderColor)
        self.canv.rect(0, 0, 0.03125 * inch, self.height, stroke=0, fill=1)

        # Draw text
        self.para.drawOn(self.canv, 0, self.para.style.leftIndent)

        self.canv.restoreState()


class CircleBulletPara(Paragraph):
    """Paragraph with a colored circle bullet point."""

    def __init__(self, text, style=None, radius=None, fill_color=None):
        """
        Create a paragraph with circle bullet.

        :param text: Paragraph text
        :param style: Text style
        :param radius: Bullet circle radius
        :param fill_color: Bullet color
        """
        if style is None:
            style = _stylesheet["Normal"]
        if radius is None:
            radius = 0.05 * inch
        if fill_color is None:
            fill_color = colors.brightgray

        self.radius = radius
        self.fillColor = fill_color

        super().__init__(text, style)

    def draw(self):
        """Draw the paragraph with bullet."""
        # Draw the circle bullet
        self.canv.saveState()
        self.canv.setFillColor(self.fillColor)
        bullet_x = self.radius + 0.1 * inch
        bullet_y = self.height - self.radius - 0.1 * inch
        self.canv.circle(bullet_x, bullet_y, self.radius, fill=1, stroke=0)
        self.canv.restoreState()

        # Draw the text with left margin for bullet
        text_x = self.radius * 2 + 0.15 * inch
        self.canv.saveState()
        self.canv.translate(text_x, 0)
        super().draw()
        self.canv.restoreState()


class StyledTable(Table):
    """Enhanced table with professional styling."""

    def __init__(self, data, thStyle=None, tdStyle=None, **kwargs):
        """
        Create a professionally styled table.

        :param data: Table data
        :param thStyle: Header style
        :param tdStyle: Cell style
        """
        if thStyle is None:
            thStyle = _stylesheet["StyledTableHeading"]
        if tdStyle is None:
            tdStyle = _stylesheet["Normal"]

        def _new_para(text, style):
            if isinstance(text, str):
                return Paragraph(text, style)
            return text

        # Process table data to ensure proper styling
        styled_data = []
        for i, row in enumerate(data):
            if i == 0:  # Header row
                styled_row = [_new_para(cell, thStyle) for cell in row]
            else:  # Data rows
                styled_row = [_new_para(cell, tdStyle) for cell in row]
            styled_data.append(styled_row)

        # Get styled table style
        table_style = None
        for style in _stylesheet.byName.values():
            if hasattr(style, "name") and style.name == "StyledTable":
                table_style = style
                break

        super().__init__(styled_data, style=table_style, **kwargs)


class FlowableGroup(Flowable):
    """Group multiple flowables together as a single unit."""

    def __init__(self, flowables):
        """
        Create a group of flowables.

        :param flowables: List of flowables to group
        """
        self.flowables = flowables
        super().__init__()

    def wrap(self, aW, aH):
        """Calculate total dimensions."""
        total_height = 0
        max_width = 0

        for flowable in self.flowables:
            w, h = flowable.wrap(aW, aH)
            total_height += h
            max_width = max(max_width, w)

        self.width = max_width
        self.height = total_height
        return self.width, self.height

    def draw(self):
        """Draw all flowables in the group."""
        y_offset = self.height

        for flowable in self.flowables:
            flowable_height = flowable.height
            y_offset -= flowable_height

            self.canv.saveState()
            self.canv.translate(0, y_offset)
            flowable.drawOn(self.canv, 0, 0)
            self.canv.restoreState()


class TopPadder(Flowable):
    """Add padding to the top of the page."""

    def __init__(self, height):
        """
        Create top padding.

        :param height: Padding height
        """
        self.height = height
        self.width = 0
        super().__init__()

    def wrap(self, aW, aH):
        """Return padding dimensions."""
        return self.width, self.height

    def draw(self):
        """Nothing to draw for padding."""
        pass


def create_severity_legend():
    """Create a legend showing severity color coding."""
    legend_data = []

    for severity, color in colors.SEVERITY_COLORS.items():
        # Create colored circle
        circle = CircleBulletPara("", radius=0.05 * inch, fill_color=color)

        # Create text
        text = Paragraph(severity, _stylesheet["Normal"])

        legend_data.append([circle, text])

    return StyledTable(
        legend_data,
        colWidths=[0.3 * inch, 1.5 * inch],
        spaceBefore=0.1 * inch,
        spaceAfter=0.1 * inch,
    )


def create_summary_stats(
    total_components,
    total_findings,
    critical_count,
    high_count,
    medium_count,
    low_count,
):
    """Create a professional summary statistics box."""
    labels = ["Total Components", "Total Findings", "Critical", "High", "Medium", "Low"]
    data = [
        total_components,
        total_findings,
        critical_count,
        high_count,
        medium_count,
        low_count,
    ]

    return StatsBox(
        labels=labels,
        data=data,
        orientation="horizontal",
        spaceBefore=0.2 * inch,
        spaceAfter=0.2 * inch,
    )


def create_exploit_stats(exploit_summary: dict):
    """Create a professional exploit statistics box."""
    # Complete list of all possible exploit categories in risk order (highest to lowest risk)
    all_exploit_categories = [
        "Exploited By Botnet",
        "Exploited By Ransomware",
        "Exploited By Threat Actors",
        "In KEV",
        "Reported in the Wild",
        "Commercial Exploit",
        "Weaponized",
        "PoC",
    ]

    # Risk level mapping for heat map colors (1-9 scale, 1=highest risk)
    risk_levels = {
        "Exploited By Botnet": 1,
        "Exploited By Ransomware": 2,
        "Exploited By Threat Actors": 3,
        "In KEV": 4,
        "Reported in the Wild": 5,
        "Commercial Exploit": 6,
        "Weaponized": 7,
        "PoC": 8,
    }

    # Heat map colors
    heat_colors = {
        "red": HexColor(0xFFE6E6),  # Light red for exploited
        "orange": HexColor(0xFFF2E6),  # Light orange for 4-6
        "yellow": HexColor(0xFFFFF0),  # Light yellow for 7-9
    }

    # Build table data with labels first, then values
    table_data = []
    for category in all_exploit_categories:
        count = exploit_summary.get(category, 0)
        label_p = Paragraph(category, _stylesheet["StatText"])
        value_p = Paragraph(f"<b>{count}</b>", _stylesheet["StatTextHeading"])
        table_data.append([label_p, value_p])

    # Create custom table style with heat map colors and divider lines
    custom_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            (
                "LINEBELOW",
                (0, 0),
                (-1, -2),
                1,
                colors.midgray,
            ),  # Divider lines between rows (not after last row)
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
    )

    # Add heat map background colors for each row
    for i, category in enumerate(all_exploit_categories):
        risk_level = risk_levels[category]
        if risk_level <= 5:
            bg_color = heat_colors["red"]
        elif risk_level <= 7:
            bg_color = heat_colors["orange"]
        else:
            bg_color = heat_colors["yellow"]

        custom_style.add("BACKGROUND", (0, i), (-1, i), bg_color)

    # Create table with custom style
    table = Table(
        table_data, style=custom_style, spaceBefore=0.2 * inch, spaceAfter=0.2 * inch
    )

    return table


def create_comprehensive_appendix():
    """Create a comprehensive appendix with terms, definitions, and helpful information organized by categories."""

    # Core Security Terms
    core_security_data = [
        ["Term", "Definition"],
        [
            "Risk Score",
            "A composite risk score computed by Finite State based on multiple subcomponents and comparison to other binaries. Higher scores indicate greater risk.",
        ],
        [
            "Severity",
            "Qualitative risk levels: Critical, High, Medium, Low. Used to categorize the potential impact of security findings.",
        ],
        [
            "CVE",
            "Common Vulnerabilities and Exposures - publicly known security vulnerabilities documented in the National Vulnerability Database (NVD).",
        ],
        [
            "EPSS Percentile",
            "Exploit Prediction Scoring System percentile (0-100) indicating the likelihood of exploitation compared to all known vulnerabilities. Higher percentiles indicate greater exploitation probability.",
        ],
    ]

    # Component and Software Terms
    component_software_data = [
        ["Term", "Definition"],
        [
            "Software Bill of Materials (SBOM)",
            "A list of software components found within firmware, including open-source and proprietary components used to assemble the software.",
        ],
        [
            "Component",
            "A software component or library that is part of the analyzed firmware or software package.",
        ],
        [
            "License",
            "The software license under which a component is distributed, affecting legal and compliance considerations.",
        ],
    ]

    # Exploit and Threat Intelligence Terms
    exploit_threat_data = [
        ["Term", "Definition"],
        [
            "Exploited By Botnet",
            "Part of mass exploitation campaigns, indicating wide exposure risk.",
        ],
        [
            "Exploited By Ransomware",
            "Indicates active, high-impact exploitation often resulting in major business disruption.",
        ],
        [
            "Exploited By Threat Actors",
            "Known use by real adversaries; strong signal of risk.",
        ],
        [
            "In KEV",
            "Listed in CISA Known Exploited Vulnerabilities Catalog based on past exploitation; prioritization recommended by authoritative sources.",
        ],
        [
            "Reported in the Wild",
            "Observed being used in attacks, but attribution or scope may be less clear than above.",
        ],
        [
            "Commercial Exploit",
            "Available to buyers (e.g., via private brokers); implies advanced threat use.",
        ],
        [
            "Weaponized",
            "Packaged in a ready-to-use exploit format (e.g., part of exploit kits or frameworks).",
        ],
        [
            "PoC (Proof of Concept)",
            "A working exploit is available, but not necessarily used yet. Still high risk, especially if easy to use.",
        ],
    ]

    # Security Analysis Terms
    security_analysis_data = [
        ["Term", "Definition"],
        [
            "Credentials",
            "User accounts and credentials found in firmware that can indicate potential backdoors or unauthorized access points.",
        ],
        [
            "Crypto Material",
            "Private keys and authorized key files that can indicate backdoors allowing unintended device access.",
        ],
        [
            "Exploit Mitigations",
            "Modern software compiler safety features designed to prevent common exploit methods like buffer overflows.",
        ],
        [
            "Unsafe Function Calls",
            "Legacy functions (like strcpy) in C that are unsafe and expose binaries to risks like buffer overflow. The platform detects these calls and uses their ratio to total function calls to percentile rank firmware.",
        ],
        [
            "Potential Memory Corruptions",
            "Binaries with the highest potential for buffer overflows and other memory-related attacks.",
        ],
        [
            "Code Analysis",
            "Static analysis results of source code, identifying security issues like invoking shell commands or command injections. Currently analyzes Python source code.",
        ],
    ]

    # Project and Version Terms
    project_version_data = [
        ["Term", "Definition"],
        [
            "Project",
            "A software project or product being analyzed for security vulnerabilities.",
        ],
        ["Version", "A specific version or release of a project being analyzed."],
        [
            "Finding",
            "A security vulnerability or issue identified during the analysis process.",
        ],
        [
            "Violations",
            "Policy violations related to security findings that may require immediate attention.",
        ],
        [
            "Warnings",
            "Policy warnings associated with findings that should be reviewed and addressed.",
        ],
    ]

    # Helper function to create a category section
    def create_category_section(title, data):
        section_elements = []

        # Add category heading
        section_elements.append(SectionHeading(title))
        section_elements.append(Spacer(1, 0.1 * inch))  # Reduced from 0.2 to 0.1 inch

        # Convert data to Paragraph objects
        table_data = []
        for row in data:
            formatted_row = []
            for cell in row:
                if cell == "Term" or cell == "Definition":
                    # Header row
                    p = Paragraph(f"<b>{cell}</b>", _stylesheet["Heading3"])
                else:
                    # Data row
                    p = Paragraph(cell, _stylesheet["Normal"])
                formatted_row.append(p)
            table_data.append(formatted_row)

        # Create table style for category
        category_style = TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),  # Header background
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),  # Header text color
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, -1),
                    colors.whitesmoke,
                ),  # Data rows background
                ("GRID", (0, 0), (-1, -1), 1, colors.midgray),  # Grid lines
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )

        # Create table
        table = Table(
            table_data,
            style=category_style,
            spaceBefore=0.1 * inch,
            spaceAfter=0.2 * inch,
        )  # Reduced spacing
        section_elements.append(table)

        return section_elements

    # Return individual sections that can be added to the story separately
    return {
        "core_security": create_category_section(
            "Core Security Terms", core_security_data
        ),
        "component_software": create_category_section(
            "Component and Software Terms", component_software_data
        ),
        "exploit_threat": create_category_section(
            "Exploit and Threat Intelligence Terms", exploit_threat_data
        ),
        "security_analysis": create_category_section(
            "Security Analysis Terms", security_analysis_data
        ),
        "project_version": create_category_section(
            "Project and Version Terms", project_version_data
        ),
    }


def create_exploit_glossary():
    """Create a glossary page with exploit category descriptions."""
    # This function is kept for backward compatibility but now redirects to the comprehensive appendix
    # For backward compatibility, return just the exploit section
    appendix_sections = create_comprehensive_appendix()
    return appendix_sections.get("exploit_threat", [])
