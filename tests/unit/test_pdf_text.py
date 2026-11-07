"""A PDF report's text reaches Analyse (PyPDF2 was never installed, so it came back empty)."""
from io import BytesIO

from reportlab.pdfgen import canvas

from shikari.parsers.file_intelligence import FileIntelligenceParser


def _pdf(*lines):
    buf = BytesIO()
    c = canvas.Canvas(buf)
    for i, line in enumerate(lines):
        c.drawString(72, 760 - 18 * i, line)
    c.showPage()
    c.save()
    return buf.getvalue()


def test_text_comes_out_of_a_pdf(tmp_path):
    content = _pdf("The actor ran powershell.exe -enc (T1059.001)", "C2 at evil[.]example")
    parser = FileIntelligenceParser()
    text = parser._extract_pdf_bytes(content)
    assert "T1059.001" in text and "evil[.]example" in text
    path = tmp_path / "report.pdf"
    path.write_bytes(content)
    assert "T1059.001" in parser._extract_pdf_text(str(path))
