"""
Report Generator
Exports detection rules and threat intelligence to Word/PDF formats
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
import os
import io


# ── Brand ─────────────────────────────────────────────────────────────────────
# One palette, shared with the branded reports (reports/assessment_charts.py): the
# wordmark's ink and its K's gold and red, plus the bateleur's own chestnut, bark
# and wing grey. The title-page wordmark and bird come from the same source as the
# assessment and campaign reports, so every Shikari report reads as one family.
BRAND = {
    "ink": "1a2028", "gold": "f59e0b", "red": "df514e", "chestnut": "8f5742",
    "bark": "776458", "wing": "b3a29b", "mist": "f0edeb", "band": "f7f4f2", "rule": "d6ceca",
}
TAGLINE = "Automated multi-vendor threat hunting and detection"


def _rgb(name: str) -> tuple:
    """Brand colour as an (r, g, b) tuple, by name or raw hex."""
    h = BRAND.get(name, name).lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _esc(text) -> str:
    """Escape text for a reportlab Paragraph, which parses its own mini-XML — so an
    unescaped '&' (e.g. in 'MITRE ATT&CK') or '<' would otherwise be mangled."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _wordmark_png(height_px: int = 300, with_eagle: bool = True) -> Optional[bytes]:
    """The ™ wordmark as PNG bytes, from the branded reports' own renderer; None if unavailable."""
    try:
        from shikari.reports import assessment_charts as charts
        return charts.wordmark(with_eagle, height_px)
    except Exception:
        return None


def _apply_style(table, names):
    """Set the first of `names` that the template defines; leave the default if none exist."""
    for n in names:
        try:
            table.style = n
            return
        except (KeyError, ValueError):
            continue


def _shade(cell, hexfill, qn):
    """Fill a Word table cell with a brand colour (hex, no '#')."""
    tcpr = cell._tc.get_or_add_tcPr()
    tcpr.append(tcpr.makeelement(
        qn("w:shd"), {qn("w:val"): "clear", qn("w:color"): "auto", qn("w:fill"): hexfill}))


class ReportFormat(Enum):
    """Supported report formats"""
    WORD = "docx"
    PDF = "pdf"
    HTML = "html"


class ReportGenerator(ABC):
    """Abstract base class for report generators"""

    @abstractmethod
    def generate(
        self,
        group_name: str,
        detections: List[Dict[str, Any]],
        correlations: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """
        Generate report and return as bytes

        Args:
            group_name: Threat group/actor name
            detections: List of detection dictionaries
            correlations: Optional list of correlation dictionaries
            metadata: Optional metadata (generation date, user, etc.)

        Returns:
            bytes: Report file content
        """
        pass

    @abstractmethod
    def get_format(self) -> ReportFormat:
        """Return report format"""
        pass

    def _prepare_metadata(self, metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare metadata with defaults"""
        result = {
            "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tool_name": "Shikari",
            "tool_version": "2.0",
            "generator": "Shikari Detection Engine"
        }
        if metadata:
            result.update(metadata)
        from shikari.reports import tlp
        try:
            result["tlp"] = tlp.normalise(result.get("tlp"))
        except ValueError:
            result["tlp"] = tlp.DEFAULT
        return result


class WordReportGenerator(ReportGenerator):
    """Generate Word (.docx) reports"""

    def __init__(self):
        """Initialize Word generator"""
        try:
            from docx import Document
            from docx.shared import Inches, Pt, RGBColor
            from docx.enum.text import WD_ALIGN_PARAGRAPH
            from docx.oxml.ns import qn
            self.Document = Document
            self.Inches = Inches
            self.Pt = Pt
            self.RGBColor = RGBColor
            self.WD_ALIGN_PARAGRAPH = WD_ALIGN_PARAGRAPH
            self.qn = qn
        except ImportError:
            raise ImportError("python-docx package not installed. Install with: pip install python-docx")

        # Initialize response actions generator
        try:
            from shikari.reports.response_actions import ResponseActionsGenerator
            self.response_generator = ResponseActionsGenerator()
        except ImportError:
            self.response_generator = None

    def generate(
        self,
        group_name: str,
        detections: List[Dict[str, Any]],
        correlations: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Generate Word document report"""

        doc = self.Document()
        meta = self._prepare_metadata(metadata)

        # Calibri as the document default, matching the branded reports
        try:
            doc.styles['Normal'].font.name = 'Calibri'
        except Exception:
            pass

        # Branded header: the name in ink, the tagline in bark
        header = doc.sections[0].header
        header_para = header.paragraphs[0]
        header_run = header_para.add_run('SHIKARI™  ')
        header_run.font.name = 'Calibri'
        header_run.font.size = self.Pt(13)
        header_run.font.bold = True
        header_run.font.color.rgb = self.RGBColor(*_rgb("ink"))

        subtitle_run = header_para.add_run(TAGLINE)
        subtitle_run.font.name = 'Calibri'
        subtitle_run.font.size = self.Pt(9)
        subtitle_run.font.color.rgb = self.RGBColor(*_rgb("bark"))

        # Add footer with Shikari branding
        footer = doc.sections[0].footer
        footer_para = footer.paragraphs[0]
        footer_para.alignment = self.WD_ALIGN_PARAGRAPH.CENTER
        from shikari.reports import tlp
        badge = footer_para.add_run(f"\u00a0{meta['tlp']}\u00a0")
        badge.font.size, badge.font.bold = self.Pt(8), True
        badge.font.color.rgb = self.RGBColor(*tlp.colour(meta["tlp"]))
        shd = badge._r.get_or_add_rPr().makeelement(self.qn("w:shd"), {
            self.qn("w:val"): "clear", self.qn("w:color"): "auto", self.qn("w:fill"): "000000"})
        badge._r.get_or_add_rPr().append(shd)
        footer_para.add_run("  ")
        footer_text = footer_para.add_run('Generated by Shikari™  |  ')
        footer_text.font.name = 'Calibri'
        footer_text.font.size = self.Pt(8)
        footer_text.font.color.rgb = self.RGBColor(*_rgb("bark"))

        footer_date = footer_para.add_run(meta['generation_date'])
        footer_date.font.name = 'Calibri'
        footer_date.font.size = self.Pt(8)
        footer_date.font.color.rgb = self.RGBColor(*_rgb("ink"))

        # Set document properties
        core_props = doc.core_properties
        core_props.title = f"{group_name} Detection Report"
        core_props.author = meta.get("user", "Shikari")
        core_props.subject = "Threat Detection Rules"
        core_props.keywords = f"{group_name}, MITRE ATT&CK, Detection"

        # Branded title page: the ™ wordmark (with the bateleur), then the report kind and target
        doc.add_paragraph()
        wm = _wordmark_png(360, with_eagle=True)
        if wm:
            logo_p = doc.add_paragraph()
            logo_p.alignment = self.WD_ALIGN_PARAGRAPH.CENTER
            logo_p.add_run().add_picture(io.BytesIO(wm), width=self.Inches(4.6))
        else:
            shikari_title = doc.add_paragraph()
            shikari_title.alignment = self.WD_ALIGN_PARAGRAPH.CENTER
            shikari_run = shikari_title.add_run('SHIKARI™')
            shikari_run.font.name = 'Calibri'
            shikari_run.font.size = self.Pt(48)
            shikari_run.font.bold = True
            shikari_run.font.color.rgb = self.RGBColor(*_rgb("ink"))

        # Subtitle
        subtitle = doc.add_paragraph()
        subtitle.alignment = self.WD_ALIGN_PARAGRAPH.CENTER
        subtitle_run = subtitle.add_run('Detection Engineering Report')
        subtitle_run.font.name = 'Calibri'
        subtitle_run.font.size = self.Pt(18)
        subtitle_run.font.color.rgb = self.RGBColor(*_rgb("bark"))

        # Spacing
        doc.add_paragraph()

        # Main title: the hunted group or target
        title = doc.add_paragraph()
        title.alignment = self.WD_ALIGN_PARAGRAPH.CENTER
        title_run = title.add_run(f'{group_name}')
        title_run.font.name = 'Calibri'
        title_run.font.size = self.Pt(32)
        title_run.font.bold = True
        title_run.font.color.rgb = self.RGBColor(*_rgb("ink"))

        doc.add_paragraph()
        doc.add_paragraph()

        # Add metadata section
        doc.add_heading('Report Information', level=1)

        # Build info data based on what's included
        info_data = [
            ('Generated:', meta['generation_date']),
            ('Report Type:', group_name),
        ]

        if len(detections) > 0:
            info_data.append(('Total Detections:', str(len(detections))))
        if correlations and len(correlations) > 0:
            info_data.append(('Total Correlations:', str(len(correlations))))

        info_data.append(('Generator:', meta['generator']))

        # Create table with dynamic row count
        info_table = doc.add_table(rows=len(info_data), cols=2)
        _apply_style(info_table, ["Light Grid", "Light List", "Table Grid"])

        for i, (label, value) in enumerate(info_data):
            row = info_table.rows[i]
            row.cells[0].text = label
            row.cells[1].text = value
            # Bold, brand-shaded label column
            row.cells[0].paragraphs[0].runs[0].font.bold = True
            _shade(row.cells[0], BRAND["mist"], self.qn)

        # Add executive summary
        doc.add_heading('Executive Summary', level=1)

        if len(detections) > 0 and len(correlations or []) > 0:
            summary_text = f"""This report contains {len(detections)} detection rules generated for the {group_name} threat group.
The detections are based on MITRE ATT&CK techniques and are compatible with multiple SIEM platforms including Splunk,
Microsoft Defender for Endpoint (MDE), Google SecOps, and Elastic Security."""
            summary_text += f"\n\nAdditionally, {len(correlations)} correlation rules have been generated to detect "
            summary_text += "multi-technique attack patterns commonly used by this threat actor."
        elif len(detections) > 0:
            summary_text = f"""This report contains {len(detections)} detection rules generated for the {group_name} threat group.
The detections are based on MITRE ATT&CK techniques and are compatible with multiple SIEM platforms including Splunk,
Microsoft Defender for Endpoint (MDE), Google SecOps, and Elastic Security."""
        elif len(correlations or []) > 0:
            summary_text = f"""This report contains {len(correlations)} correlation rules for detecting multi-technique attack patterns.
These correlation rules analyze event sequences across time windows to identify sophisticated attack chains commonly used
by advanced threat actors."""
        else:
            summary_text = "This report contains threat detection and correlation rules."

        doc.add_paragraph(summary_text)

        # Add Actor/Target section
        doc.add_heading('Actor Profile', level=2)
        actor_para = doc.add_paragraph()
        actor_para.add_run('Threat Actor/Target: ').font.bold = True
        actor_run = actor_para.add_run(group_name)
        actor_run.font.color.rgb = self.RGBColor(139, 0, 0)  # Dark red
        actor_run.font.size = self.Pt(12)

        # Add Hypothesis if provided
        if meta.get('hypothesis'):
            doc.add_paragraph()
            hypothesis_para = doc.add_paragraph()
            hypothesis_para.add_run('Hunt Hypothesis: ').font.bold = True
            hypothesis_para.add_run(meta.get('hypothesis'))
            hypothesis_para.paragraph_format.left_indent = self.Inches(0.25)

        # Add Conclusion if provided
        if meta.get('conclusion'):
            doc.add_paragraph()
            conclusion_para = doc.add_paragraph()
            conclusion_para.add_run('Conclusion: ').font.bold = True
            conclusion_para.add_run(meta.get('conclusion'))
            conclusion_para.paragraph_format.left_indent = self.Inches(0.25)

        # Add Key Metrics section if metadata is available
        if meta.get('total_detections') or meta.get('technique_count'):
            doc.add_heading('Key Metrics', level=2)

            metrics_table = doc.add_table(rows=8, cols=2)
            _apply_style(metrics_table, ["Light Grid", "Light List", "Table Grid"])

            metrics_data = [
                ('Total Detections', str(meta.get('total_detections', 'N/A'))),
                ('MITRE ATT&CK Techniques', str(meta.get('technique_count', 'N/A'))),
                ('Tactics Covered', str(meta.get('tactic_count', 'N/A'))),
                ('Correlation Rules', str(meta.get('correlation_count', 'N/A'))),
                ('Manual Hours (Est.)', f"{meta.get('manual_hours', 'N/A')} hours"),
                ('Shikari Generation Time', f"{meta.get('shikari_hours', 'N/A')} hours"),
                ('Time Saved', f"{meta.get('hours_saved', 'N/A')} hours"),
                ('Cost Savings (Est.)', f"${meta.get('cost_savings', 'N/A'):,}" if meta.get('cost_savings') else 'N/A')
            ]

            for i, (label, value) in enumerate(metrics_data):
                row = metrics_table.rows[i]
                row.cells[0].text = label
                row.cells[1].text = value
                # Bold, brand-shaded labels
                row.cells[0].paragraphs[0].runs[0].font.bold = True
                _shade(row.cells[0], BRAND["mist"], self.qn)

                # Colour the values from the brand palette
                _value_colours = [_rgb("gold"), _rgb("ink"), _rgb("chestnut"), _rgb("red")]
                vc = _value_colours[i] if i < len(_value_colours) else _rgb("bark")
                run = row.cells[1].paragraphs[0].runs[0]
                run.font.color.rgb = self.RGBColor(*vc)
                run.font.bold = True

        # Skip individual detections section - only show correlations

        # Add correlations section
        if correlations and len(correlations) > 0:
            doc.add_page_break()
            doc.add_heading('Correlation Rules', level=1)

            for i, corr in enumerate(correlations, 1):
                doc.add_heading(f'{i}. {corr.get("name", "Multi-Technique Correlation")}', level=3)

                # Correlation details
                corr_table = doc.add_table(rows=4, cols=2)
                _apply_style(corr_table, ["Light List", "Table Grid"])

                techniques = corr.get('techniques', [])
                technique_str = ', '.join(t.get('id', 'Unknown') for t in techniques[:5])
                if len(techniques) > 5:
                    technique_str += f' ... and {len(techniques) - 5} more'

                corr_data = [
                    ('Techniques:', technique_str),
                    ('Severity:', corr.get('severity', 'High')),
                    ('Time Window:', corr.get('time_window', 'N/A')),
                    ('Vendor:', corr.get('vendor', 'Unknown'))
                ]

                for j, (label, value) in enumerate(corr_data):
                    row = corr_table.rows[j]
                    row.cells[0].text = label
                    row.cells[1].text = str(value)
                    row.cells[0].paragraphs[0].runs[0].font.bold = True
                    _shade(row.cells[0], BRAND["mist"], self.qn)

                # Correlation query
                if corr.get('combined_query'):
                    doc.add_paragraph('Correlation Query:', style='Heading 4')
                    query_para = doc.add_paragraph()
                    query_run = query_para.add_run(corr['combined_query'][:1000])
                    query_run.font.name = 'Courier New'
                    query_run.font.size = self.Pt(9)
                    query_para.paragraph_format.left_indent = self.Inches(0.25)

                # OSINT information for correlations
                if corr.get('osint_enriched'):
                    doc.add_paragraph('OSINT Enrichment:', style='Heading 4')

                    osint_para = doc.add_paragraph()
                    osint_run = osint_para.add_run(
                        f"✓ {corr.get('osint_enrichment_count', 0)} of {corr.get('query_count', 0)} "
                        f"detection queries were enriched with OSINT indicators"
                    )
                    osint_run.font.color.rgb = self.RGBColor(*_rgb("gold"))

                    if corr.get('osint_sources'):
                        sources_para = doc.add_paragraph()
                        sources_para.add_run("OSINT Sources: ").font.bold = True
                        sources_para.add_run(", ".join(corr['osint_sources']))
                        sources_para.paragraph_format.left_indent = self.Inches(0.25)

                    if corr.get('osint_indicators'):
                        indicators_para = doc.add_paragraph()
                        indicators_para.add_run("Aggregated OSINT Indicators: ").font.bold = True
                        # Show count by type
                        indicator_counts = [
                            f"{ind_type}: {len(values)}"
                            for ind_type, values in corr['osint_indicators'].items()
                        ]
                        indicators_para.add_run(", ".join(indicator_counts))
                        indicators_para.paragraph_format.left_indent = self.Inches(0.25)

                doc.add_paragraph('')

        # Add footer
        doc.add_page_break()
        doc.add_heading('Appendix', level=1)
        doc.add_paragraph('MITRE ATT&CK® Framework')
        doc.add_paragraph(
            'MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques '
            'based on real-world observations. Visit https://attack.mitre.org for more information.'
        )

        # Save to bytes
        output = io.BytesIO()
        doc.save(output)
        output.seek(0)
        return output.getvalue()

    def get_format(self) -> ReportFormat:
        return ReportFormat.WORD


class PDFReportGenerator(ReportGenerator):
    """Generate PDF reports"""

    def __init__(self):
        """Initialize PDF generator"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            from reportlab.pdfgen import canvas

            self.letter = letter
            self.A4 = A4
            self.getSampleStyleSheet = getSampleStyleSheet
            self.ParagraphStyle = ParagraphStyle
            self.inch = inch
            self.SimpleDocTemplate = SimpleDocTemplate
            self.Table = Table
            self.TableStyle = TableStyle
            self.Paragraph = Paragraph
            self.Spacer = Spacer
            self.PageBreak = PageBreak
            self.colors = colors
            self.TA_CENTER = TA_CENTER
            self.TA_LEFT = TA_LEFT
            self.canvas = canvas
        except ImportError:
            raise ImportError("reportlab package not installed. Install with: pip install reportlab")

    def generate(
        self,
        group_name: str,
        detections: List[Dict[str, Any]],
        correlations: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Generate PDF report"""

        output = io.BytesIO()
        doc = self.SimpleDocTemplate(output, pagesize=self.letter)
        meta = self._prepare_metadata(metadata)

        # Container for document elements
        story = []
        styles = self.getSampleStyleSheet()

        # Custom styles with Shikari branding colors
        shikari_brand_style = self.ParagraphStyle(
            'ShikariBrand',
            parent=styles['Heading1'],
            fontSize=40,
            textColor=self.colors.HexColor('#1a2028'),  # ink
            alignment=self.TA_CENTER,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        )

        subtitle_style = self.ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=self.colors.HexColor('#776458'),  # bark
            alignment=self.TA_CENTER,
            spaceAfter=20,
            fontName='Helvetica'
        )

        title_style = self.ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=self.colors.HexColor('#1a2028'),  # ink
            alignment=self.TA_CENTER,
            spaceAfter=30,
            fontName='Helvetica-Bold'
        )

        heading_style = self.ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=self.colors.HexColor('#1a2028'),  # ink
            spaceAfter=12,
            fontName='Helvetica-Bold'
        )

        code_style = self.ParagraphStyle(
            'Code',
            parent=styles['Code'],
            fontSize=8,
            leftIndent=20,
            rightIndent=20,
            textColor=self.colors.HexColor('#1a2028'),
            backColor=self.colors.HexColor('#f7f4f2')  # band
        )

        # Branded title page: the ™ wordmark (with the bateleur), then the kind and target
        wm = _wordmark_png(360, with_eagle=True)
        if wm:
            from reportlab.platypus import Image as RLImage
            logo = RLImage(io.BytesIO(wm))
            logo._restrictSize(4.6 * self.inch, 2.4 * self.inch)
            logo.hAlign = 'CENTER'
            story.append(self.Spacer(1, 0.3 * self.inch))
            story.append(logo)
            story.append(self.Spacer(1, 0.15 * self.inch))
        else:
            story.append(self.Paragraph('SHIKARI™', shikari_brand_style))
        story.append(self.Paragraph('Detection Engineering Report', subtitle_style))
        story.append(self.Spacer(1, 0.2 * self.inch))
        story.append(self.Paragraph(_esc(group_name), title_style))
        story.append(self.Spacer(1, 0.4 * self.inch))

        # Report information table
        story.append(self.Paragraph('Report Information', heading_style))

        info_data = [
            ['Generated:', meta['generation_date']],
            ['Threat Group:', group_name],
            ['Total Detections:', str(len(detections))],
            ['Generator:', meta['generator']]
        ]

        info_table = self.Table(info_data, colWidths=[2 * self.inch, 4 * self.inch])
        info_table.setStyle(self.TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.colors.HexColor('#f0edeb')),  # mist
            ('TEXTCOLOR', (0, 0), (-1, -1), self.colors.HexColor('#1a2028')),  # ink
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, self.colors.HexColor('#d6ceca')),  # rule
            ('BOX', (0, 0), (-1, -1), 2, self.colors.HexColor('#f59e0b'))  # gold frame
        ]))

        story.append(info_table)
        story.append(self.Spacer(1, 0.3 * self.inch))

        # Executive summary
        story.append(self.Paragraph('Executive Summary', heading_style))
        summary_text = f"""This report contains {len(detections)} detection rules generated for the {group_name} threat group.
        The detections are based on MITRE ATT&CK techniques and are compatible with multiple SIEM platforms."""

        if correlations and len(correlations) > 0:
            summary_text += f" Additionally, {len(correlations)} correlation rules have been generated."

        story.append(self.Paragraph(_esc(summary_text), styles['BodyText']))
        story.append(self.Spacer(1, 0.3 * self.inch))

        # Add Hypothesis if provided
        if metadata.get('hypothesis'):
            story.append(self.Paragraph('Hunt Hypothesis', heading_style))
            story.append(self.Paragraph(_esc(metadata.get('hypothesis')), styles['BodyText']))
            story.append(self.Spacer(1, 0.2 * self.inch))

        # Add Conclusion if provided
        if metadata.get('conclusion'):
            story.append(self.Paragraph('Conclusion', heading_style))
            story.append(self.Paragraph(_esc(metadata.get('conclusion')), styles['BodyText']))
            story.append(self.Spacer(1, 0.2 * self.inch))

        # Add Key Metrics section if metadata is available
        if metadata.get('total_detections') or metadata.get('technique_count'):
            story.append(self.Paragraph('Key Metrics', heading_style))

            metrics_data = [
                ['Total Detections', str(metadata.get('total_detections', 'N/A'))],
                ['MITRE ATT&CK Techniques', str(metadata.get('technique_count', 'N/A'))],
                ['Tactics Covered', str(metadata.get('tactic_count', 'N/A'))],
                ['Correlation Rules', str(metadata.get('correlation_count', 'N/A'))],
                ['Manual Hours (Est.)', f"{metadata.get('manual_hours', 'N/A')} hours"],
                ['Shikari Generation Time', f"{metadata.get('shikari_hours', 'N/A')} hours"],
                ['Time Saved', f"{metadata.get('hours_saved', 'N/A')} hours"],
                ['Cost Savings (Est.)', f"${metadata.get('cost_savings', 'N/A'):,}" if metadata.get('cost_savings') else 'N/A']
            ]

            metrics_table = self.Table(metrics_data, colWidths=[2.5 * self.inch, 3.5 * self.inch])
            metrics_table.setStyle(self.TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), self.colors.HexColor('#f0edeb')),  # mist
                ('TEXTCOLOR', (0, 0), (0, -1), self.colors.HexColor('#1a2028')),  # ink labels
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, self.colors.HexColor('#d6ceca')),  # rule
                ('BOX', (0, 0), (-1, -1), 2, self.colors.HexColor('#f59e0b')),  # gold frame
                ('PADDING', (0, 0), (-1, -1), 8),
                # Brand-coloured values
                ('TEXTCOLOR', (1, 0), (1, 0), self.colors.HexColor('#f59e0b')),  # gold: detections
                ('TEXTCOLOR', (1, 1), (1, 1), self.colors.HexColor('#1a2028')),  # ink: techniques
                ('TEXTCOLOR', (1, 2), (1, 2), self.colors.HexColor('#8f5742')),  # chestnut: tactics
                ('TEXTCOLOR', (1, 3), (1, 3), self.colors.HexColor('#df514e')),  # red: correlations
                ('TEXTCOLOR', (1, 4), (1, -1), self.colors.HexColor('#776458')),  # bark: time/cost
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),  # Bold values
            ]))

            story.append(metrics_table)
            story.append(self.Spacer(1, 0.3 * self.inch))

        # Skip individual detections section - only show correlations

        # Correlations
        if correlations and len(correlations) > 0:
            story.append(self.PageBreak())
            story.append(self.Paragraph('Correlation Rules', title_style))

            for i, corr in enumerate(correlations[:10], 1):  # Limit to 10
                corr_title = f'{i}. {corr.get("name", "Multi-Technique Correlation")}'
                story.append(self.Paragraph(_esc(corr_title), styles['Heading3']))

                techniques = corr.get('techniques', [])
                technique_str = ', '.join(t.get('id', 'Unknown') for t in techniques[:5])

                corr_data = [
                    ['Techniques:', technique_str],
                    ['Severity:', corr.get('severity', 'High')],
                    ['Vendor:', corr.get('vendor', 'Unknown')]
                ]

                corr_table = self.Table(corr_data, colWidths=[1.5 * self.inch, 4.5 * self.inch])
                corr_table.setStyle(self.TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), self.colors.HexColor('#f7f4f2')),  # band
                    ('TEXTCOLOR', (0, 0), (-1, -1), self.colors.HexColor('#1a2028')),  # ink
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.colors.HexColor('#d6ceca')),  # rule
                    ('PADDING', (0, 0), (-1, -1), 6)
                ]))

                story.append(corr_table)
                story.append(self.Spacer(1, 0.2 * self.inch))

        # Build PDF
        from reportlab.lib import colors as rl_colors
        from shikari.reports import tlp

        def tlp_footer(canvas, _doc):
            label = meta["tlp"]
            canvas.saveState()
            canvas.setFont("Helvetica-Bold", 8)
            w = canvas.stringWidth(label, "Helvetica-Bold", 8) + 8
            canvas.setFillColor(rl_colors.black)
            canvas.rect(36, 20, w, 12, stroke=0, fill=1)
            canvas.setFillColor(rl_colors.Color(*[v / 255 for v in tlp.colour(label)]))
            canvas.drawString(40, 23, label)
            canvas.restoreState()

        doc.build(story, onFirstPage=tlp_footer, onLaterPages=tlp_footer)
        output.seek(0)
        return output.getvalue()

    def get_format(self) -> ReportFormat:
        return ReportFormat.PDF


class HTMLReportGenerator(ReportGenerator):
    """Generate HTML reports (for preview/print)"""

    def __init__(self):
        """Initialize HTML generator"""
        # Initialize response actions generator
        try:
            from shikari.reports.response_actions import ResponseActionsGenerator
            self.response_generator = ResponseActionsGenerator()
        except ImportError:
            self.response_generator = None

    def _html_brand_header(self) -> str:
        """The ™ wordmark as an inline data URI, with the tagline; empty if unavailable."""
        wm = _wordmark_png(200, with_eagle=True)
        if not wm:
            return ""
        import base64
        uri = "data:image/png;base64," + base64.b64encode(wm).decode("ascii")
        return (f'<div class="brand"><img src="{uri}" alt="Shikari™">'
                f'<div class="tagline">{TAGLINE}</div></div>')

    def generate(
        self,
        group_name: str,
        detections: List[Dict[str, Any]],
        correlations: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """Generate HTML report"""

        meta = self._prepare_metadata(metadata)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{group_name} Detection Report</title>
    <style>
        body {{ font-family: 'Calibri', 'Carlito', 'Segoe UI', sans-serif; margin: 40px;
                line-height: 1.6; color: #1a2028; }}
        .brand {{ text-align: center; margin-bottom: 10px; }}
        .brand img {{ height: 72px; }}
        .brand .tagline {{ color: #776458; font-size: 13px; margin-top: 4px; }}
        h1 {{ color: #1a2028; border-bottom: 3px solid #f59e0b; padding-bottom: 10px; }}
        h2 {{ color: #1a2028; margin-top: 30px; }}
        h3 {{ color: #776458; }}
        .metadata {{ background: #f0edeb; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .metadata table {{ width: 100%; }}
        .metadata td {{ padding: 5px; }}
        .metadata td:first-child {{ font-weight: bold; width: 150px; }}
        .detection {{ border: 1px solid #d6ceca; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .query {{ background: #f7f4f2; padding: 10px; font-family: 'Courier New', monospace;
                  font-size: 12px; overflow-x: auto; border-left: 3px solid #f59e0b; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #d6ceca; padding: 8px; text-align: left; }}
        th {{ background-color: #1a2028; color: white; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #d6ceca;
                   color: #776458; font-size: 12px; }}
    </style>
</head>
<body>
    {self._html_brand_header()}
    <h1>{group_name} Detection Report</h1>

    <div class="metadata">
        <table>
            <tr><td>Generated:</td><td>{meta['generation_date']}</td></tr>
            <tr><td>Threat Group:</td><td>{group_name}</td></tr>
            <tr><td>Total Detections:</td><td>{len(detections)}</td></tr>
            <tr><td>Generator:</td><td>{meta['generator']}</td></tr>
        </table>
    </div>

    <h2>Executive Summary</h2>
    <p>This report contains {len(detections)} detection rules generated for the {group_name} threat group.</p>
"""

        # Group by vendor
        detections_by_vendor = {}
        for det in detections:
            vendor = det.get('vendor', 'Unknown')
            if vendor not in detections_by_vendor:
                detections_by_vendor[vendor] = []
            detections_by_vendor[vendor].append(det)

        html += "<h2>Detection Rules</h2>"

        for vendor, vendor_detections in detections_by_vendor.items():
            html += f"<h3>{vendor} ({len(vendor_detections)} rules)</h3>"

            for i, det in enumerate(vendor_detections, 1):
                html += f"""
    <div class="detection">
        <h4>{i}. {det.get('technique', 'Unknown')}</h4>
        <table>
            <tr><td><b>Technique ID:</b></td><td>{det.get('technique_id', 'N/A')}</td></tr>
            <tr><td><b>Tactic:</b></td><td>{det.get('tactic', 'N/A')}</td></tr>
            <tr><td><b>Data Source:</b></td><td>{det.get('data_source', 'N/A')}</td></tr>
        </table>
"""
                if det.get('queries'):
                    query = det['queries'][0][:800]
                    html += f'<p><b>Query:</b></p><div class="query">{query}...</div>'

                # OSINT enrichment
                if det.get('osint_enriched') or det.get('osint_sources'):
                    html += '<p><b>OSINT Enrichment:</b></p>'
                    if det.get('osint_enriched'):
                        html += '<p style="color: #f59e0b;">✓ Query enriched with OSINT indicators</p>'
                    else:
                        html += '<p style="color: #776458;">ℹ Query compared with OSINT sources</p>'
                    if det.get('osint_sources'):
                        html += f"<p style=\"margin-left: 20px;\">Sources: {', '.join(det['osint_sources'])}</p>"

                # Response actions
                if self.response_generator:
                    response_data = self.response_generator.generate_response_actions(
                        technique_name=det.get('technique', 'Unknown'),
                        technique_id=det.get('technique_id', 'N/A'),
                        tactic=det.get('tactic', 'Unknown'),
                        description=det.get('description_html', ''),
                        indicators=det.get('indicators'),
                        threat_actor=group_name if '(' not in group_name else None,
                        threat_actor_context=None,
                    )

                    html += '<p><b>Response Actions:</b></p>'
                    priority_color = {'CRITICAL': '#df514e', 'HIGH': '#f59e0b', 'MEDIUM': '#8f5742', 'LOW': '#b3a29b'}
                    html += f'<p style="font-weight: bold; color: {priority_color.get(response_data["priority"], "#000")}">Priority: {response_data["priority"]}</p>'

                    for action_type, action_data in response_data['response_actions'].items():
                        html += f'<p><b>{action_type.title()}:</b> <i>{action_data["description"]}</i></p>'
                        html += '<ol style="margin-left: 20px;">'
                        for step in action_data['steps'][:3]:  # Limit to 3 steps for HTML
                            html += f'<li>{step}</li>'
                        if len(action_data['steps']) > 3:
                            html += f'<li><i>... and {len(action_data["steps"]) - 3} more steps</i></li>'
                        html += '</ol>'

                html += "</div>"

        from shikari.reports import tlp
        html += f"""
    <div class="footer">
        <p><span style="background:#000;color:{tlp.LEVELS[meta['tlp']]['hex']};font-weight:bold;padding:2px 6px">{meta['tlp']}</span></p>
        <p>Generated by Shikari - MITRE ATT&CK Detection Rule Generator</p>
        <p>MITRE ATT&CK® is a registered trademark of The MITRE Corporation.</p>
    </div>
</body>
</html>
"""

        return html.encode('utf-8')

    def get_format(self) -> ReportFormat:
        return ReportFormat.HTML
