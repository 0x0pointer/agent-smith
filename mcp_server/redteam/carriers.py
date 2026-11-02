"""Document CARRIER builders for indirect prompt injection (issues #258 / #260).

A structured-extraction, OCR/vision, or RAG pipeline ingests a FILE submitted by
an external party — not a JSON text field. The realistic threat is an attacker who
controls the SOURCE DOCUMENT and hides an instruction in it (white / 0pt / invisible
text, metadata, a tEXt chunk, invisible Unicode). `redteam_tools._http_send_fn` can
only POST application/json, so that file pipeline is never exercised — which is why
the current skill would miss a crafted-PDF indirect-injection finding.

These builders generate such a carrier with ONLY the Python stdlib (no reportlab /
python-docx / Pillow) so they can't break like a scanner. Each returns
(bytes, filename, content_type). The hidden instruction is placed where a parser /
OCR / text extractor still reads it but a human reviewer does not.
"""
from __future__ import annotations

import io
import struct
import zlib
import zipfile
from html import escape

from mcp_server.transforms.invisible import tags_encode

CARRIERS = ("svg", "html", "docx", "xlsx", "pdf", "png")


# ── text formats ────────────────────────────────────────────────────────────────

def build_svg(visible: str, hidden: str) -> tuple[bytes, str, str]:
    """SVG with the instruction in an invisible <text> (opacity 0, 1px) + a comment."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="480" height="120">\n'
        f'  <text x="12" y="40" font-size="16">{escape(visible)}</text>\n'
        f'  <text x="12" y="60" fill="#ffffff" fill-opacity="0" font-size="1">{escape(hidden)}</text>\n'
        f'  <!-- {escape(hidden)} -->\n'
        '</svg>\n'
    )
    return svg.encode("utf-8"), "carrier.svg", "image/svg+xml"


def build_html(visible: str, hidden: str) -> tuple[bytes, str, str]:
    """HTML with the instruction hidden (display:none + 0px white + invisible-Unicode)."""
    html = (
        "<!doctype html><html><head><meta charset=\"utf-8\"></head><body>\n"
        f"<p>{escape(visible)}</p>\n"
        f"<div style=\"display:none\">{escape(hidden)}</div>\n"
        f"<span style=\"color:#fff;font-size:0px\">{escape(hidden)}</span>\n"
        f"<span>{tags_encode(hidden)}</span>\n"
        "</body></html>\n"
    )
    return html.encode("utf-8"), "carrier.html", "text/html"


# ── OOXML (zip + XML) ───────────────────────────────────────────────────────────

_CT_DOCX = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '</Types>')
_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
         '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
         '</Relationships>')


def build_docx(visible: str, hidden: str) -> tuple[bytes, str, str]:
    """Minimal DOCX; the instruction is a white 1pt run AND the core-properties
    description metadata (both are read by text extractors, invisible on screen)."""
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
        f'<w:p><w:r><w:t xml:space="preserve">{escape(visible)}</w:t></w:r></w:p>'
        f'<w:p><w:r><w:rPr><w:color w:val="FFFFFF"/><w:sz w:val="2"/></w:rPr>'
        f'<w:t xml:space="preserve">{escape(hidden)}</w:t></w:r></w:p>'
        '</w:body></w:document>'
    )
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f'<dc:description>{escape(hidden)}</dc:description></cp:coreProperties>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CT_DOCX)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", document)
        z.writestr("docProps/core.xml", core)
    return buf.getvalue(), "carrier.docx", \
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


_CT_XLSX = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '</Types>')
_XLSX_WB_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                 '</Relationships>')
_XLSX_ROOT_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   '</Relationships>')


def build_xlsx(visible: str, hidden: str) -> tuple[bytes, str, str]:
    """Minimal XLSX with the instruction as an inline-string cell (text extractors
    and LLM spreadsheet readers pick it up)."""
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')
    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
             f'<row r="1"><c r="A1" t="inlineStr"><is><t xml:space="preserve">{escape(visible)}</t></is></c></row>'
             f'<row r="2"><c r="A2" t="inlineStr"><is><t xml:space="preserve">{escape(hidden)}</t></is></c></row>'
             '</sheetData></worksheet>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CT_XLSX)
        z.writestr("_rels/.rels", _XLSX_ROOT_RELS)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", _XLSX_WB_RELS)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue(), "carrier.xlsx", \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


# ── PDF (hand-written, minimal, valid xref) ─────────────────────────────────────

def _pdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(visible: str, hidden: str) -> tuple[bytes, str, str]:
    """Minimal single-page PDF. `visible` is drawn normally; `hidden` is drawn with
    text render mode 3 (invisible) — present to any text extractor, unseen on screen."""
    content = (
        "BT /F1 18 Tf 1 0 0 1 60 700 Tm "
        f"({_pdf_escape(visible)}) Tj ET\n"
        "BT 3 Tr /F1 10 Tf 1 0 0 1 60 680 Tm "
        f"({_pdf_escape(hidden)}) Tj ET\n"
    ).encode("latin-1", "replace")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objs)+1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n").encode()
    return bytes(out), "carrier.pdf", "application/pdf"


# ── PNG with a tEXt chunk (for an OCR/vision ingest path) ───────────────────────

def _png_chunk(typ: bytes, data: bytes) -> bytes:
    body = typ + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)


def build_png(visible: str, hidden: str) -> tuple[bytes, str, str]:
    """A 1x1 PNG carrying the instruction in a tEXt metadata chunk (read by EXIF/
    metadata extractors and some vision pre-processors). `visible` is unused on a
    1x1 pixel — it rides along in a second tEXt chunk for completeness."""
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)          # 1x1, 8-bit RGB
    idat = zlib.compress(b"\x00\xff\xff\xff")                     # one white pixel
    text = _png_chunk(b"tEXt", b"Comment\x00" + hidden.encode("latin-1", "replace"))
    desc = _png_chunk(b"tEXt", b"Description\x00" + visible.encode("latin-1", "replace"))
    png = sig + _png_chunk(b"IHDR", ihdr) + text + desc + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")
    return png, "carrier.png", "image/png"


_BUILDERS = {"svg": build_svg, "html": build_html, "docx": build_docx,
             "xlsx": build_xlsx, "pdf": build_pdf, "png": build_png}


def build(kind: str, visible: str, hidden: str) -> tuple[bytes, str, str]:
    """Build a carrier of `kind` embedding `hidden` behind `visible`."""
    fn = _BUILDERS.get(kind)
    if fn is None:
        raise ValueError(f"unknown carrier '{kind}'; use one of {CARRIERS}")
    return fn(visible or "", hidden or "")
