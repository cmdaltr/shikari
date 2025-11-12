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
            "tool_name": "Archer",
            "tool_version": "2.0",
            "generator": "Archer Detection Engine"
        }
        if metadata:
            result.update(metadata)
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

        # Set document properties
        core_props = doc.core_properties
        core_props.title = f"{group_name} Detection Report"
        core_props.author = meta.get("user", "Archer")
        core_props.subject = "Threat Detection Rules"
        core_props.keywords = f"{group_name}, MITRE ATT&CK, Detection"

        # Add title
        title = doc.add_heading(f'{group_name} Detection Report', 0)
        title.alignment = self.WD_ALIGN_PARAGRAPH.CENTER

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
        info_table.style = 'Light Grid Accent 1'

        for i, (label, value) in enumerate(info_data):
            row = info_table.rows[i]
            row.cells[0].text = label
            row.cells[1].text = value
            # Make label bold
            row.cells[0].paragraphs[0].runs[0].font.bold = True

        # Add executive summary
        doc.add_heading('Executive Summary', level=1)

        if len(detections) > 0 and len(correlations or []) > 0:
            summary_text = f"""This report contains {len(detections)} detection rules generated for the {group_name} threat group.
The detections are based on MITRE ATT&CK techniques and include queries for multiple SIEM platforms including Splunk,
Microsoft Defender for Endpoint (MDE), Google Chronicle, and Elastic Security."""
            summary_text += f"\n\nAdditionally, {len(correlations)} correlation rules have been generated to detect "
            summary_text += "multi-technique attack patterns commonly used by this threat actor."
        elif len(detections) > 0:
            summary_text = f"""This report contains {len(detections)} detection rules generated for the {group_name} threat group.
The detections are based on MITRE ATT&CK techniques and include queries for multiple SIEM platforms including Splunk,
Microsoft Defender for Endpoint (MDE), Google Chronicle, and Elastic Security."""
        elif len(correlations or []) > 0:
            summary_text = f"""This report contains {len(correlations)} correlation rules for detecting multi-technique attack patterns.
These correlation rules analyze event sequences across time windows to identify sophisticated attack chains commonly used
by advanced threat actors."""
        else:
            summary_text = "This report contains threat detection and correlation rules."

        doc.add_paragraph(summary_text)

        # Group detections by vendor
        detections_by_vendor = {}
        for det in detections:
            vendor = det.get('vendor', 'Unknown')
            if vendor not in detections_by_vendor:
                detections_by_vendor[vendor] = []
            detections_by_vendor[vendor].append(det)

        # Add detection rules section (only if there are detections)
        if len(detections) > 0:
            doc.add_page_break()
            doc.add_heading('Detection Rules', level=1)

        for vendor, vendor_detections in detections_by_vendor.items():
            doc.add_heading(f'{vendor} ({len(vendor_detections)} rules)', level=2)

            for i, det in enumerate(vendor_detections, 1):
                # Detection header
                heading = doc.add_heading(f'{i}. {det.get("technique", "Unknown Technique")}', level=3)

                # Technique details
                details_table = doc.add_table(rows=5, cols=2)
                details_table.style = 'Light List Accent 1'

                details_data = [
                    ('Technique ID:', det.get('technique_id', 'N/A')),
                    ('Tactic:', det.get('tactic', 'N/A')),
                    ('Data Source:', det.get('data_source', 'N/A')),
                    ('Severity:', det.get('severity', 'Medium')),
                    ('Detection Likelihood:', f"{det.get('detection_likelihood', 75)}%")
                ]

                for j, (label, value) in enumerate(details_data):
                    row = details_table.rows[j]
                    row.cells[0].text = label
                    row.cells[1].text = str(value)
                    row.cells[0].paragraphs[0].runs[0].font.bold = True

                # Description
                if det.get('description_html'):
                    doc.add_paragraph('Description:', style='Heading 4')
                    # Strip HTML tags for Word
                    import re
                    desc_text = re.sub('<[^<]+?>', '', det['description_html'])
                    doc.add_paragraph(desc_text[:500] + ('...' if len(desc_text) > 500 else ''))

                # Query
                if det.get('queries') and len(det['queries']) > 0:
                    doc.add_paragraph('Detection Query:', style='Heading 4')
                    for query in det['queries']:
                        # Add query in code style
                        query_para = doc.add_paragraph()
                        query_run = query_para.add_run(query[:1000] + ('...' if len(query) > 1000 else ''))
                        query_run.font.name = 'Courier New'
                        query_run.font.size = self.Pt(9)
                        # Gray background
                        query_para.paragraph_format.left_indent = self.Inches(0.25)
                        query_para.paragraph_format.right_indent = self.Inches(0.25)

                # Indicators
                if det.get('indicators') and len(det['indicators']) > 0:
                    doc.add_paragraph('Threat Indicators:', style='Heading 4')
                    indicators_text = ', '.join(str(ind) for ind in det['indicators'][:20])
                    if len(det['indicators']) > 20:
                        indicators_text += f" ... and {len(det['indicators']) - 20} more"
                    doc.add_paragraph(indicators_text)

                # Add spacing
                doc.add_paragraph('')

        # Add correlations section
        if correlations and len(correlations) > 0:
            doc.add_page_break()
            doc.add_heading('Correlation Rules', level=1)

            for i, corr in enumerate(correlations, 1):
                doc.add_heading(f'{i}. {corr.get("name", "Multi-Technique Correlation")}', level=3)

                # Correlation details
                corr_table = doc.add_table(rows=4, cols=2)
                corr_table.style = 'Light List Accent 1'

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

                # Correlation query
                if corr.get('combined_query'):
                    doc.add_paragraph('Correlation Query:', style='Heading 4')
                    query_para = doc.add_paragraph()
                    query_run = query_para.add_run(corr['combined_query'][:1000])
                    query_run.font.name = 'Courier New'
                    query_run.font.size = self.Pt(9)
                    query_para.paragraph_format.left_indent = self.Inches(0.25)

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

        # Custom styles
        title_style = self.ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=self.colors.HexColor('#1a1a1a'),
            alignment=self.TA_CENTER,
            spaceAfter=30
        )

        heading_style = self.ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=self.colors.HexColor('#2c3e50'),
            spaceAfter=12
        )

        code_style = self.ParagraphStyle(
            'Code',
            parent=styles['Code'],
            fontSize=8,
            leftIndent=20,
            rightIndent=20,
            textColor=self.colors.HexColor('#000000'),
            backColor=self.colors.HexColor('#f5f5f5')
        )

        # Title
        story.append(self.Paragraph(f'{group_name} Detection Report', title_style))
        story.append(self.Spacer(1, 0.3 * self.inch))

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
            ('BACKGROUND', (0, 0), (0, -1), self.colors.HexColor('#e8e8e8')),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors.grey)
        ]))

        story.append(info_table)
        story.append(self.Spacer(1, 0.3 * self.inch))

        # Executive summary
        story.append(self.Paragraph('Executive Summary', heading_style))
        summary_text = f"""This report contains {len(detections)} detection rules generated for the {group_name} threat group.
        The detections are based on MITRE ATT&CK techniques and include queries for multiple SIEM platforms."""

        if correlations and len(correlations) > 0:
            summary_text += f" Additionally, {len(correlations)} correlation rules have been generated."

        story.append(self.Paragraph(summary_text, styles['BodyText']))
        story.append(self.Spacer(1, 0.3 * self.inch))

        # Group detections by vendor
        detections_by_vendor = {}
        for det in detections:
            vendor = det.get('vendor', 'Unknown')
            if vendor not in detections_by_vendor:
                detections_by_vendor[vendor] = []
            detections_by_vendor[vendor].append(det)

        # Detection rules
        story.append(self.PageBreak())
        story.append(self.Paragraph('Detection Rules', title_style))

        for vendor, vendor_detections in detections_by_vendor.items():
            story.append(self.Paragraph(f'{vendor} ({len(vendor_detections)} rules)', heading_style))

            for i, det in enumerate(vendor_detections[:20], 1):  # Limit to 20 per vendor to avoid huge PDFs
                # Detection header
                det_title = f'{i}. {det.get("technique", "Unknown Technique")}'
                story.append(self.Paragraph(det_title, styles['Heading3']))

                # Details table
                details_data = [
                    ['Technique ID:', det.get('technique_id', 'N/A')],
                    ['Tactic:', det.get('tactic', 'N/A')],
                    ['Data Source:', det.get('data_source', 'N/A')],
                    ['Severity:', det.get('severity', 'Medium')]
                ]

                details_table = self.Table(details_data, colWidths=[1.5 * self.inch, 4.5 * self.inch])
                details_table.setStyle(self.TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), self.colors.HexColor('#f0f0f0')),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.colors.grey),
                    ('PADDING', (0, 0), (-1, -1), 6)
                ]))

                story.append(details_table)
                story.append(self.Spacer(1, 0.1 * self.inch))

                # Query (truncated)
                if det.get('queries') and len(det['queries']) > 0:
                    query_text = det['queries'][0][:500]
                    if len(det['queries'][0]) > 500:
                        query_text += '...'

                    story.append(self.Paragraph('<b>Detection Query:</b>', styles['BodyText']))
                    story.append(self.Paragraph(f'<font face="Courier" size="8">{query_text}</font>', code_style))

                story.append(self.Spacer(1, 0.2 * self.inch))

            if len(vendor_detections) > 20:
                story.append(self.Paragraph(
                    f'<i>Note: Showing first 20 of {len(vendor_detections)} {vendor} detections</i>',
                    styles['Italic']
                ))

        # Correlations
        if correlations and len(correlations) > 0:
            story.append(self.PageBreak())
            story.append(self.Paragraph('Correlation Rules', title_style))

            for i, corr in enumerate(correlations[:10], 1):  # Limit to 10
                corr_title = f'{i}. {corr.get("name", "Multi-Technique Correlation")}'
                story.append(self.Paragraph(corr_title, styles['Heading3']))

                techniques = corr.get('techniques', [])
                technique_str = ', '.join(t.get('id', 'Unknown') for t in techniques[:5])

                corr_data = [
                    ['Techniques:', technique_str],
                    ['Severity:', corr.get('severity', 'High')],
                    ['Vendor:', corr.get('vendor', 'Unknown')]
                ]

                corr_table = self.Table(corr_data, colWidths=[1.5 * self.inch, 4.5 * self.inch])
                corr_table.setStyle(self.TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), self.colors.HexColor('#f0f0f0')),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.colors.grey),
                    ('PADDING', (0, 0), (-1, -1), 6)
                ]))

                story.append(corr_table)
                story.append(self.Spacer(1, 0.2 * self.inch))

        # Build PDF
        doc.build(story)
        output.seek(0)
        return output.getvalue()

    def get_format(self) -> ReportFormat:
        return ReportFormat.PDF


class HTMLReportGenerator(ReportGenerator):
    """Generate HTML reports (for preview/print)"""

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
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #7f8c8d; }}
        .metadata {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .metadata table {{ width: 100%; }}
        .metadata td {{ padding: 5px; }}
        .metadata td:first-child {{ font-weight: bold; width: 150px; }}
        .detection {{ border: 1px solid #ddd; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .query {{ background: #f5f5f5; padding: 10px; font-family: 'Courier New', monospace;
                  font-size: 12px; overflow-x: auto; border-left: 3px solid #3498db; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd;
                   color: #7f8c8d; font-size: 12px; }}
    </style>
</head>
<body>
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

                html += "</div>"

        html += """
    <div class="footer">
        <p>Generated by Archer - MITRE ATT&CK Detection Rule Generator</p>
        <p>MITRE ATT&CK® is a registered trademark of The MITRE Corporation.</p>
    </div>
</body>
</html>
"""

        return html.encode('utf-8')

    def get_format(self) -> ReportFormat:
        return ReportFormat.HTML
