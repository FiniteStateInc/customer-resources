"""
Professional typography and styling for Finite State PDF reports.
Includes custom fonts, paragraph styles, and table styles matching the platform design.
"""

import os
from functools import cache

import reportlab.rl_config
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import registerFont, registerFontFamily
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus.tables import TableStyle

from . import colors


def register_fonts():
    """Register custom fonts for the PDF generation."""
    # Set font search path
    font_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static/fonts")
    if font_path not in reportlab.rl_config.TTFSearchPath:
        reportlab.rl_config.TTFSearchPath.append(font_path)

    # Configure ReportLab defaults
    reportlab.rl_config.defaultGraphicsFontName = "OpenSans"
    reportlab.rl_config.canvas_basefontname = "OpenSans"
    reportlab.rl_config.platypus_link_underline = 1
    reportlab.rl_config.warnOnMissingFontGlyphs = 0

    # Register Poppins fonts
    registerFont(TTFont("Poppins", "Poppins/Poppins-Light.ttf"))
    registerFont(TTFont("Poppins-SemiBold", "Poppins/Poppins-SemiBold.ttf"))
    registerFont(TTFont("Poppins-Italic", "Poppins/Poppins-Italic.ttf"))
    registerFont(TTFont("Poppins-SemiBoldItalic", "Poppins/Poppins-SemiBoldItalic.ttf"))
    registerFont(TTFont("Poppins-Light", "Poppins/Poppins-Light.ttf"))
    registerFont(TTFont("Poppins-Regular", "Poppins/Poppins-Regular.ttf"))
    registerFont(TTFont("Poppins-Bold", "Poppins/Poppins-Bold.ttf"))
    registerFontFamily(
        "Poppins",
        bold="Poppins-SemiBold",
        italic="Poppins-Italic",
        boldItalic="Poppins-SemiBoldItalic",
    )

    # Register Open Sans fonts
    registerFont(TTFont("OpenSans", "Open_Sans/static/OpenSans-Regular.ttf"))
    registerFont(TTFont("OpenSans-Bold", "Open_Sans/static/OpenSans-Bold.ttf"))
    registerFont(TTFont("OpenSans-Italic", "Open_Sans/static/OpenSans-Italic.ttf"))
    registerFont(
        TTFont("OpenSans-BoldItalic", "Open_Sans/static/OpenSans-BoldItalic.ttf")
    )
    registerFontFamily(
        "OpenSans",
        bold="OpenSans-Bold",
        italic="OpenSans-Italic",
        boldItalic="OpenSans-BoldItalic",
    )


@cache
def get_stylesheet():
    """Get comprehensive stylesheet with professional typography."""
    stylesheet = getSampleStyleSheet()

    # Typography settings
    leading = 1.35
    hdr_space_after = 1 / 8 * inch

    # Update existing base styles
    style = stylesheet["Normal"]
    style.fontName = "OpenSans"
    style.leading = style.fontSize * leading
    style.textColor = colors.darkjunglegreen

    style = stylesheet["Heading1"]
    style.fontName = "Poppins-SemiBold"
    style.fontSize = 24
    style.leading = style.fontSize * leading
    style.spaceAfter = hdr_space_after
    style.spaceBefore = 0
    style.textColor = colors.darkjunglegreen

    style = stylesheet["Heading2"]
    style.fontName = "Poppins-SemiBold"
    style.fontSize = 18
    style.leading = style.fontSize * leading
    style.spaceAfter = hdr_space_after
    style.spaceBefore = 0
    style.textColor = colors.darkjunglegreen

    style = stylesheet["Heading3"]
    style.fontName = "Poppins-SemiBold"
    style.fontSize = 14
    style.leading = style.fontSize * leading
    style.textColor = colors.darkjunglegreen

    style = stylesheet["Heading4"]
    style.fontName = "Poppins-SemiBold"
    style.fontSize = 12
    style.leading = style.fontSize * leading
    # style.spaceAfter = hdr_space_after
    style.textColor = colors.darkjunglegreen

    style = stylesheet["Heading5"]
    style.fontName = "Poppins-SemiBold"
    style.fontSize = 10
    style.leading = style.fontSize * leading
    style.textColor = colors.darkjunglegreen

    # Add custom styles
    stylesheet.add(
        ParagraphStyle(
            name="CoverContentText",
            fontName="Poppins",
            fontSize=10,
            leading=17.5,
            textColor=colors.white,
        )
    )

    stylesheet.add(
        ParagraphStyle(
            name="FooterText", fontName="OpenSans", fontSize=9, textColor=colors.gray
        )
    )

    stylesheet.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=stylesheet["Heading3"],
            textColor=colors.lightblue,
            alignment=TA_LEFT,
            fontSize=12,
        )
    )

    stylesheet.add(
        ParagraphStyle(name="BulletPara", linkUnderline=0, alignment=TA_CENTER)
    )

    stylesheet.add(ParagraphStyle(name="TOCHeading", parent=stylesheet["Heading3"]))

    stylesheet.add(
        ParagraphStyle(
            name="TOCBulletPara",
            parent=stylesheet["TOCHeading"],
            linkUnderline=0,
            alignment=TA_CENTER,
        )
    )

    stylesheet.add(
        ParagraphStyle(
            name="CopyText",
            parent=stylesheet["Normal"],
            spaceBefore=0,
            spaceAfter=0,
        )
    )

    stylesheet.add(
        ParagraphStyle(
            name="CenterHeading",
            parent=stylesheet["Heading3"],
            alignment=TA_CENTER,
            fontSize=12,
            spaceBefore=0,
            spaceAfter=0,
        )
    )

    # Table styles
    table_style = TableStyle(cmds=[("LEFTPADDING", (1, 1), (-1, -1), 1 / 8 * inch)])
    table_style.name = "TOCTable"
    stylesheet.add(table_style)

    # Stats box styles
    table_padding = 5 / 16 * inch
    table_style = TableStyle(
        cmds=[
            ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
            ("TOPPADDING", (0, 0), (-1, -1), table_padding),
            ("BOTTOMPADDING", (0, 0), (-1, -1), table_padding),
            ("LEFTPADDING", (0, 0), (0, 0), table_padding),
            ("RIGHTPADDING", (-1, -1), (-1, -1), table_padding),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
    )
    table_style.name = "StatsBoxHorizontal"
    stylesheet.add(table_style)

    table_style = TableStyle(
        cmds=[
            ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
            ("LEFTPADDING", (0, 0), (-1, -1), table_padding),
            ("RIGHTPADDING", (0, 0), (-1, -1), table_padding),
            ("TOPPADDING", (0, 0), (0, 0), table_padding),
            ("BOTTOMPADDING", (-1, -1), (-1, -1), table_padding),
        ]
    )
    table_style.name = "StatsBoxVertical"
    stylesheet.add(table_style)

    stylesheet.add(
        ParagraphStyle(
            name="StatTextHeading",
            parent=stylesheet["Heading2"],
            alignment=TA_CENTER,
            textColor=colors.lightblue,
            spaceBefore=0,
        )
    )

    stylesheet.add(
        ParagraphStyle(
            name="StatText",
            parent=stylesheet["Normal"],
            alignment=TA_CENTER,
            spaceBefore=0,
            spaceAfter=0,
        )
    )

    # General table style
    table_padding = 1 / 16 * inch
    table_style = TableStyle(
        cmds=[
            ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEABOVE", (0, 1), (-1, -1), 1, colors.mystic),
            ("TOPPADDING", (0, 0), (-1, -1), table_padding),
            ("BOTTOMPADDING", (0, 0), (-1, -1), table_padding),
        ]
    )
    table_style.name = "StyledTable"
    stylesheet.add(table_style)

    stylesheet.add(
        ParagraphStyle(
            name="StyledTableHeading",
            parent=stylesheet["Normal"],
            alignment=TA_LEFT,
            spaceBefore=0,
            spaceAfter=0,
            fontName="OpenSans-Bold",
        )
    )

    return stylesheet
