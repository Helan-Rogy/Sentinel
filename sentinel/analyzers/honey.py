"""Honey files: realistic multi-format decoy canary files with embedded tripwire tokens.

Any modify, rename, or delete on these files immediately indicates suspicious behavior.
Files use high-priority alphabetical prefixing ('!00_', '_') to ensure early discovery by
ransomware directory enumeration routines (e.g. FindFirstFileW / readdir).
"""
from __future__ import annotations

import io
import os
import random
import uuid
import zipfile
from typing import List

# Alphabetically prioritized decoys spanning Office, PDF, CSV, and TXT formats
DECOYS = [
    "!00_Executive_Payroll_2024.docx",
    "!01_Financial_Audit_Report.pdf",
    "!02_Corporate_Strategy_Confidential.docx",
    "_budget_2024.csv",
    "_passwords_backup.txt",
    "_tax_records.txt",
    "_client_list.csv",
]


def norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _pdf_content(title: str, token: str) -> bytes:
    """Generate a fully valid, parseable binary PDF document."""
    stream_content = f"BT /F1 12 Tf 72 712 Td ({title} - CONFIDENTIAL INTERNAL USE ONLY) Tj ET"
    stream_len = len(stream_content)
    pdf = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << >> >> endobj
4 0 obj << /Length {stream_len} >>
stream
{stream_content}
endstream
endobj
5 0 obj << /Title ({title}) /Author (Sentinel Canary Engine) /Subject (Canary Tripwire Token: {token}) >> endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000216 00000 n 
0000000330 00000 n 
trailer << /Size 6 /Root 1 0 R /Info 5 0 R >>
startxref
440
%%EOF
"""
    return pdf.encode("latin-1")


def _docx_content(title: str, token: str) -> bytes:
    """Generate a fully valid OpenXML binary DOCX document with PK header."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>',
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>',
        )
        zf.writestr(
            "word/document.xml",
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f'<w:body><w:p><w:r><w:t>STRICTLY CONFIDENTIAL: {title}. '
            f'Canary Security Token: {token}</w:t></w:r></w:p></w:body></w:document>',
        )
        zf.writestr(
            "docProps/core.xml",
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            f'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f'<dc:title>{title}</dc:title><cp:keywords>{token}</cp:keywords></cp:coreProperties>',
        )
    return buf.getvalue()


def _tabular_content(name: str, seed: int, token: str) -> bytes:
    """Generate structured CSV / text financial ledger records."""
    rnd = random.Random(seed)
    lines = [
        f"# CONFIDENTIAL DATA EXPORT: {name}",
        f"# SYSTEM_CANARY_TOKEN={token}",
        "record_id,employee_id,department,salary_usd,auth_hash",
    ]
    depts = ["Executive", "Finance", "Treasury", "Legal", "Engineering"]
    for i in range(120):
        lines.append(
            f"REC-{i:04d},EMP-{rnd.randint(1000, 9999)},{rnd.choice(depts)},{rnd.randint(65000, 240000)},{rnd.hexdigest(16)}"
        )
    return "\n".join(lines).encode("utf-8")


def _generate_canary(name: str, seed: int) -> bytes:
    token = f"CANARY-{uuid.uuid4().hex[:12].upper()}"
    base_name = os.path.splitext(name)[0].lstrip("!_0123456789")
    if name.endswith(".docx"):
        return _docx_content(base_name.replace("_", " "), token)
    elif name.endswith(".pdf"):
        return _pdf_content(base_name.replace("_", " "), token)
    else:
        return _tabular_content(name, seed, token)


class HoneyRegistry:
    def __init__(self) -> None:
        self._paths: set[str] = set()

    def deploy(self, directory: str, count: int = 4) -> List[str]:
        os.makedirs(directory, exist_ok=True)
        made = []
        for i, name in enumerate(DECOYS[: max(1, count)]):
            p = os.path.join(directory, name)
            with open(p, "wb") as f:
                f.write(_generate_canary(name, i))
            self._paths.add(norm(p))
            made.append(p)
        return made

    def is_honey(self, path: str | None) -> bool:
        return bool(path) and norm(path) in self._paths

    def rename(self, src: str, dst: str) -> None:
        if norm(src) in self._paths:
            self._paths.discard(norm(src))
            self._paths.add(norm(dst))

    @property
    def paths(self) -> List[str]:
        return sorted(self._paths)
