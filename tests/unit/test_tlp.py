"""TLP 2.0 labels on reports."""

import io

import pytest

from shikari.reports import tlp
from shikari.reports.generator import HTMLReportGenerator, PDFReportGenerator, WordReportGenerator


@pytest.mark.unit
@pytest.mark.parametrize("given,label", [
    ("", "TLP:AMBER"), (None, "TLP:AMBER"), ("amber", "TLP:AMBER"), ("TLP:RED", "TLP:RED"),
    ("tlp:white", "TLP:CLEAR"), ("amber+strict", "TLP:AMBER+STRICT"), ("TLP:AMBER STRICT", "TLP:AMBER+STRICT"),
])
def test_labels_normalise_to_tlp_2(given, label):
    assert tlp.normalise(given) == label


@pytest.mark.unit
def test_anything_else_is_refused():
    with pytest.raises(ValueError):
        tlp.normalise("SECRET")


@pytest.mark.unit
def test_hunt_reports_carry_the_label():
    from docx import Document

    meta = {"tlp": "green"}
    word = WordReportGenerator().generate("APT29", [], metadata=meta)
    footer = Document(io.BytesIO(word)).sections[0].footer.paragraphs[0].text
    assert "TLP:GREEN" in footer
    assert "TLP:GREEN" in HTMLReportGenerator().generate("APT29", [], metadata=meta).decode()
    assert PDFReportGenerator().generate("APT29", [], metadata=meta).startswith(b"%PDF")
    # An unknown label falls back to the default rather than failing the report
    assert "TLP:AMBER" in HTMLReportGenerator().generate("APT29", [], metadata={"tlp": "SECRET"}).decode()
