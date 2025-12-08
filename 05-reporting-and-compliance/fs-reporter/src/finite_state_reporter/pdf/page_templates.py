"""
Professional page templates for Finite State PDF reports.
Includes cover page, headers/footers, and page layouts matching the platform design.
"""

import os
from datetime import datetime

from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph
from reportlab.rl_config import defaultPageSize

from . import colors
from .styles import get_stylesheet

_stylesheet = get_stylesheet()

# Path to static assets
_image_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static/images")
_logo_img = ImageReader(os.path.join(_image_path, "fs-logo.png"))

# Try to load cover image if it exists
try:
    _cover_img = ImageReader(os.path.join(_image_path, "cover.jpg"))
except:
    _cover_img = None

PADDING_N = 0.5 * inch


class CoverPage(PageTemplate):
    """Professional cover page with background image and branding."""

    def __init__(self, id=None, pagesize=defaultPageSize):
        if not isinstance(id, str) or len(id) == 0:
            raise ValueError("id must be a non-empty string")
        w, h = pagesize
        super().__init__(
            id=id,
            onPage=self.on_page,
            pagesize=pagesize,
            frames=[
                Frame(
                    0,
                    0,
                    w,
                    h,
                    id=f"{id}_F1",
                    leftPadding=0,
                    rightPadding=0,
                    topPadding=0,
                    bottomPadding=0,
                )
            ],
        )

    @staticmethod
    def draw_cover_img_on(canvas, doc):
        """Draw cover background image if available."""
        if _cover_img:
            img_w, img_h = _cover_img.getSize()
            scale = 1.85
            canvas.drawImage(
                _cover_img,
                -12 * inch,
                -15 / 64 * inch,
                width=img_w * scale,
                height=img_h * scale,
            )

    @staticmethod
    def draw_logo_img_on(canvas, doc):
        """Draw Finite State logo on cover."""
        canvas.drawImage(
            _logo_img,
            doc.width - (PADDING_N / 2),
            doc.height - (PADDING_N / 2),
            width=150,
            preserveAspectRatio=True,
            anchor="ne",
            anchorAtXY=False,
            mask="auto",
        )

    @staticmethod
    def on_page(canvas, doc):
        """Render the cover page."""
        canvas.saveState()

        # Draw cover background image
        CoverPage.draw_cover_img_on(canvas, doc)

        # Draw logo
        CoverPage.draw_logo_img_on(canvas, doc)

        padding = 7 / 16 * inch

        # Get report data
        title_txt = getattr(doc, "title", "Project Risk Summary")
        project_name = getattr(doc, "project_name", "Project")
        version_name = getattr(doc, "version_name", "Version")
        organization = getattr(doc, "organization", "Organization")
        created_date = getattr(doc, "created_date", datetime.now().strftime("%Y-%m-%d"))

        # Calculate title box dimensions
        font_size = 24
        font_name = "Poppins-SemiBold"
        title_txt_w = stringWidth(title_txt, font_name, font_size)

        rw = padding * 2 + title_txt_w
        rh = (
            3 + 3 / 4
        ) * inch  # Increased height to accommodate all project info including published date
        rx = PADDING_N
        ry = (doc.height / 2.0) - (rh / 2.0)

        # Draw title box background
        canvas.setFillColor(colors.midnightblue)
        canvas.rect(rx, ry, rw, rh, fill=1, stroke=0)

        # Set content color and position
        canvas.setFillColor(colors.white)
        x = PADDING_N + padding

        # Draw title text
        y = (ry + rh) - (3 / 8 * inch + font_size)
        canvas.setFont(font_name, font_size)
        canvas.drawString(x, y, title_txt)

        # Draw title underline
        margin = 5 / 16 * inch
        y -= margin
        canvas.rect(x, y, title_txt_w, 1 / 32 * inch, fill=1, stroke=0)
        y -= margin

        # Draw project information
        style = _stylesheet["CoverContentText"]
        margin = 1 / 8 * inch

        # Project name
        p = Paragraph(
            f"""
        <span>Project Name:</span><br />
        <span size="12"><b>{project_name}</b></span><br />
        """,
            style=style,
        )
        p.wrap(title_txt_w, rh)
        y -= p.height
        p.drawOn(canvas, x, y)
        y -= margin

        # Version
        p = Paragraph(
            f"""
        <span>Version:</span><br />
        <span size="12"><b>{version_name}</b></span><br />
        """,
            style=style,
        )
        p.wrap(title_txt_w, rh)
        y -= p.height
        p.drawOn(canvas, x, y)
        y -= margin

        # Organization
        p = Paragraph(
            f"""
        <span>Organization:</span><br />
        <span size="12"><b>{organization}</b></span><br />
        """,
            style=style,
        )
        p.wrap(title_txt_w, rh)
        y -= p.height
        p.drawOn(canvas, x, y)
        y -= margin

        # Created date
        p = Paragraph(f"""Published: <b>{created_date}</b>""", style=style)
        p.wrap(title_txt_w, rh)
        y -= p.height
        p.drawOn(canvas, x, y)

        canvas.restoreState()


class BasePageTemplate(PageTemplate):
    """Base page template with professional header and footer."""

    header_h = 11 / 16 * inch
    header_margin = 3 / 16 * inch

    def __init__(self, id, frames, pagesize=defaultPageSize):
        if not isinstance(id, str) or len(id) == 0:
            raise ValueError("id must be a non-empty string")
        super().__init__(
            id=id,
            onPage=self.on_page,
            onPageEnd=self.on_page_end,
            pagesize=pagesize,
            frames=frames,
        )

    @staticmethod
    def on_page(canvas, doc):
        """Draw header on each page."""
        canvas.saveState()

        # Get actual page dimensions
        page_width, page_height = doc.pagesize

        # Header should be at the very top of the page
        y = page_height - BasePageTemplate.header_h

        # Draw header background - full page width
        canvas.setFillColor(colors.midnightblue)
        canvas.rect(0, y, page_width, BasePageTemplate.header_h, fill=1)

        font_size = 10
        margin_top = page_height - (11 / 64 * inch + font_size)

        # Get document attributes
        title = getattr(doc, "title", "Project Risk Summary")
        created_date = getattr(doc, "created_date", datetime.now().strftime("%Y-%m-%d"))
        organization = getattr(doc, "organization", "Organization")
        project_name = getattr(doc, "project_name", "Project")
        version_name = getattr(doc, "version_name", "Version")

        # Draw title and published date
        txt = canvas.beginText(PADDING_N, margin_top)
        txt.setFont("Poppins-SemiBold", font_size)
        txt.setFillColor(colors.coral)
        txt.textLine(title)

        txt.setFont("OpenSans", 8)
        txt.setFillColor(colors.white)
        txt.textLine(f"Published: {created_date}")

        canvas.drawText(txt)

        # Draw organization and project info in center - use page width
        x_mid = page_width / 2.0
        canvas.setFont("OpenSans", font_size)
        canvas.setFillColor(colors.white)
        canvas.drawCentredString(x_mid, margin_top, organization)

        font_size = 11
        canvas.setFont("OpenSans-Bold", font_size)
        canvas.drawCentredString(
            x_mid, margin_top - (font_size * 1.25), f"{project_name} / {version_name}"
        )

        # Draw logo - use page width
        canvas.drawImage(
            _logo_img,
            page_width - PADDING_N,
            y + (BasePageTemplate.header_h / 2.0),
            width=80,
            preserveAspectRatio=True,
            anchor="e",
            anchorAtXY=True,
            mask="auto",
        )

        canvas.restoreState()

    @staticmethod
    def draw_footer_text_on(canvas, doc):
        """Draw footer with copyright and contact information."""
        style = _stylesheet["FooterText"]

        # Combine copyright and contact information into centered text
        footer_text = "© 2025 Finite State, Inc. All rights reserved. | www.finitestate.io | support@finitestate.io"

        # Calculate center position
        text_width = stringWidth(footer_text, style.fontName, style.fontSize)
        x_center = (doc.width - text_width) / 2 + PADDING_N

        # Draw centered footer text - lowered by 5/16" (0.3125 inches)
        footer_y = PADDING_N - (
            5 / 16 * inch
        )  # 0.5 - 0.3125 = 0.1875 inches from bottom
        p = Paragraph(footer_text, style=style)
        p.wrap(text_width, doc.height)
        p.drawOn(canvas, x_center, footer_y)

    @staticmethod
    def on_page_end(canvas, doc):
        """Draw footer on each page."""
        canvas.saveState()
        BasePageTemplate.draw_footer_text_on(canvas, doc)
        canvas.restoreState()


class StandardPage(BasePageTemplate):
    """Standard page template with single column layout."""

    def __init__(self, id, pagesize=defaultPageSize):
        w, h = pagesize
        super().__init__(
            id=id,
            pagesize=pagesize,
            frames=[
                Frame(
                    PADDING_N,
                    PADDING_N,
                    w - 2 * PADDING_N,
                    h - BasePageTemplate.header_h - 2 * PADDING_N,
                    id=f"{id}_F1",
                    leftPadding=0,
                    rightPadding=0,
                    topPadding=0,
                    bottomPadding=0,
                )
            ],
        )


class TwoColumnPage(BasePageTemplate):
    """Two-column page template for detailed layouts."""

    def __init__(self, id, pagesize=defaultPageSize):
        w, h = pagesize
        col_width = (w - 3 * PADDING_N) / 2
        super().__init__(
            id=id,
            pagesize=pagesize,
            frames=[
                Frame(
                    PADDING_N,
                    PADDING_N,
                    col_width,
                    h - BasePageTemplate.header_h - 2 * PADDING_N,
                    id=f"{id}_F1",
                    leftPadding=0,
                    rightPadding=0,
                    topPadding=0,
                    bottomPadding=0,
                ),
                Frame(
                    PADDING_N + col_width + PADDING_N,
                    PADDING_N,
                    col_width,
                    h - BasePageTemplate.header_h - 2 * PADDING_N,
                    id=f"{id}_F2",
                    leftPadding=0,
                    rightPadding=0,
                    topPadding=0,
                    bottomPadding=0,
                ),
            ],
        )


class ProfessionalDocTemplate(BaseDocTemplate):
    """Enhanced document template with professional page layouts."""

    def __init__(self, filename, pagesize=defaultPageSize, **kwargs):
        super().__init__(filename, pagesize=pagesize, **kwargs)

        # Add page templates
        cover_template = CoverPage(id="cover", pagesize=pagesize)
        standard_template = StandardPage(id="standard", pagesize=pagesize)
        twocol_template = TwoColumnPage(id="twocol", pagesize=pagesize)

        self.addPageTemplates(
            [
                cover_template,
                standard_template,
                twocol_template,
            ]
        )

        # Set the default page template to cover
        self.pageTemplates[0] = cover_template

        # Set document attributes that can be overridden
        self.title = "Project Risk Summary"
        self.project_name = "Project"
        self.version_name = "Version"
        self.organization = "Organization"
        self.created_date = datetime.now().strftime("%Y-%m-%d")

    def set_document_info(
        self,
        title=None,
        project_name=None,
        version_name=None,
        organization=None,
        created_date=None,
    ):
        """Set document information for headers and cover page."""
        if title:
            self.title = title
        if project_name:
            self.project_name = project_name
        if version_name:
            self.version_name = version_name
        if organization:
            self.organization = organization
        if created_date:
            self.created_date = created_date
