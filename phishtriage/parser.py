"""EML / MSG dosyalarini okuyup yapisal parcalarina ayirir."""
from __future__ import annotations

import email
import email.policy
import hashlib
import html as html_mod
import os
import re
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from typing import Dict, List, Tuple

from .models import AttachmentInfo

_RECEIVED_IP = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
_RECEIVED_FROM = re.compile(r"from\s+([^\s;()]+)", re.IGNORECASE)
_RECEIVED_BY = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)


def read_message(path: str) -> EmailMessage:
    """EML dosyasini okur. .msg icin basit bir metin cikarma denemesi yapar."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if path.lower().endswith(".msg") and raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        raise ValueError(
            "Outlook .msg (OLE) formati desteklenmiyor. "
            "Once .eml olarak disari aktarin (Outlook: Farkli Kaydet > .eml)."
        )
    return email.message_from_bytes(raw, policy=email.policy.default)


# --------------------------------------------------------------------------- #
def header(msg: EmailMessage, name: str) -> str:
    try:
        value = msg.get(name, "")
    except Exception:
        return ""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def split_address(value: str) -> Tuple[str, str]:
    """'Ad Soyad <a@b.com>' -> ('Ad Soyad', 'a@b.com')"""
    display, addr = parseaddr(value)
    return display.strip(), addr.strip().lower()


def all_addresses(value: str) -> List[str]:
    return [a.lower() for _n, a in getaddresses([value or ""]) if a]


# --------------------------------------------------------------------------- #
def parse_received_chain(msg: EmailMessage) -> List[Dict[str, str]]:
    """Received basliklarini en eskiden yeniye siralayarak hop listesi uretir."""
    received = msg.get_all("Received") or []
    hops: List[Dict[str, str]] = []
    for idx, raw in enumerate(reversed(received)):
        text = " ".join(str(raw).split())
        ips = _RECEIVED_IP.findall(text)
        from_match = _RECEIVED_FROM.search(text)
        by_match = _RECEIVED_BY.search(text)
        hops.append({
            "hop": str(idx + 1),
            "from": from_match.group(1) if from_match else "",
            "by": by_match.group(1) if by_match else "",
            "ip": ips[0] if ips else "",
            "raw": text[:300],
        })
    return hops


def parse_authentication(msg: EmailMessage) -> Dict[str, str]:
    """Authentication-Results / Received-SPF basliklarindan SPF-DKIM-DMARC durumu."""
    result = {"spf": "yok", "dkim": "yok", "dmarc": "yok", "compauth": "yok"}
    blob = " ".join(
        str(v) for name in ("Authentication-Results", "ARC-Authentication-Results",
                            "Received-SPF", "Authentication-Results-Original")
        for v in (msg.get_all(name) or [])
    ).lower()
    if not blob:
        return result
    for mech in ("spf", "dkim", "dmarc", "compauth"):
        match = re.search(rf"\b{mech}=(\w+)", blob)
        if match:
            result[mech] = match.group(1)
    if result["spf"] == "yok":
        spf_header = str(msg.get("Received-SPF", "")).strip().lower()
        if spf_header:
            result["spf"] = spf_header.split()[0]
    if msg.get("DKIM-Signature") and result["dkim"] == "yok":
        result["dkim"] = "imzali (dogrulanmadi)"
    return result


# --------------------------------------------------------------------------- #
def _decode(part: EmailMessage) -> str:
    try:
        payload = part.get_content()
        if isinstance(payload, bytes):
            return payload.decode("utf-8", "replace")
        return str(payload)
    except Exception:
        raw = part.get_payload(decode=True)
        if isinstance(raw, bytes):
            charset = part.get_content_charset() or "utf-8"
            return raw.decode(charset, "replace")
        return str(raw or "")


def extract_bodies(msg: EmailMessage) -> Tuple[str, str]:
    """(duz_metin, html) doner."""
    text_parts, html_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition.lower():
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain":
                text_parts.append(_decode(part))
            elif ctype == "text/html":
                html_parts.append(_decode(part))
    else:
        content = _decode(msg)
        (html_parts if msg.get_content_type() == "text/html" else text_parts).append(content)
    return "\n".join(text_parts), "\n".join(html_parts)


def html_to_text(html_body: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html_body)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html_mod.unescape(text)).strip()


# --------------------------------------------------------------------------- #
_MACRO_MARKERS = (b"vbaProject.bin", b"macros/vba", b"word/vbaData.xml")
_RISKY_EXT = {
    ".exe": "calistirilabilir dosya", ".scr": "ekran koruyucu (calistirilabilir)",
    ".js": "JavaScript", ".jse": "kodlanmis JavaScript", ".vbs": "VBScript",
    ".vbe": "kodlanmis VBScript", ".wsf": "Windows Script File", ".hta": "HTML Application",
    ".jar": "Java arsivi", ".ps1": "PowerShell script", ".bat": "toplu is dosyasi",
    ".cmd": "toplu is dosyasi", ".com": "DOS calistirilabilir", ".pif": "program bilgi dosyasi",
    ".lnk": "kisayol (komut calistirabilir)", ".iso": "disk imaji (MOTW atlatma)",
    ".img": "disk imaji (MOTW atlatma)", ".msi": "yukleyici", ".dll": "kutuphane",
    ".chm": "derlenmis yardim dosyasi", ".reg": "kayit defteri dosyasi",
    ".ace": "eski arsiv formati", ".cpl": "denetim masasi ogesi",
}
_ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab"}
_MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam"}


def extract_attachments(msg: EmailMessage) -> List[AttachmentInfo]:
    out: List[AttachmentInfo] = []
    if not msg.is_multipart():
        return out
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = str(part.get("Content-Disposition") or "")
        filename = part.get_filename()
        if "attachment" not in disposition.lower() and not filename:
            continue
        filename = filename or "adsiz"
        data = part.get_payload(decode=True) or b""
        info = AttachmentInfo(
            filename=filename,
            content_type=part.get_content_type(),
            size=len(data),
            md5=hashlib.md5(data).hexdigest() if data else "",
            sha256=hashlib.sha256(data).hexdigest() if data else "",
        )
        info.notes.extend(inspect_attachment(filename, data))
        out.append(info)
    return out


def inspect_attachment(filename: str, data: bytes) -> List[str]:
    """Dosya adi ve icerigine bakarak risk notlari uretir."""
    notes: List[str] = []
    name = filename.lower()
    ext = os.path.splitext(name)[1]

    if ext in _RISKY_EXT:
        notes.append(f"riskli uzanti: {ext} ({_RISKY_EXT[ext]})")
    if ext in _MACRO_EXT:
        notes.append(f"makro icerebilen Office formati: {ext}")
    if ext in _ARCHIVE_EXT:
        notes.append("arsiv dosyasi - icerigi ayrica incelenmeli")

    # cift uzanti / RTLO
    base = os.path.splitext(name)[0]
    inner_ext = os.path.splitext(base)[1]
    if inner_ext and inner_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
        notes.append(f"cift uzanti gizlemesi: '{inner_ext}{ext}'")
    if "‮" in filename or "‫" in filename:
        notes.append("RTLO (sagdan sola yazim) karakteri ile uzanti gizleme")

    if data[:2] == b"MZ":
        notes.append("PE (Windows calistirilabilir) imzasi tespit edildi")
    if data[:4] == b"%PDF":
        lowered = data.lower()
        for marker, label in ((b"/javascript", "JavaScript"), (b"/js", "JS objesi"),
                              (b"/openaction", "OpenAction (otomatik calisma)"),
                              (b"/launch", "Launch eylemi"),
                              (b"/embeddedfile", "gomulu dosya")):
            if marker in lowered:
                notes.append(f"PDF icinde {label}")
    if data[:2] == b"PK" and any(m in data for m in _MACRO_MARKERS):
        notes.append("Office belgesinde VBA makro projesi bulundu")
    return notes
