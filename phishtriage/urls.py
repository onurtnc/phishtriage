"""URL cikarma ve supheli baglanti analizi."""
from __future__ import annotations

import difflib
import ipaddress
import re
import urllib.parse
from typing import Dict, List, Tuple

from .models import UrlInfo

_URL_RE = re.compile(r"""(?i)\b((?:https?://|ftp://|www\.)[^\s<>"'\)\]]+)""")
_ANCHOR_RE = re.compile(
    r"""(?is)<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>"""
)

# Kisaltma servisleri - hedef gizler
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
    "bl.ink", "lnkd.in", "t.ly", "shorte.st", "adf.ly",
}

# Ucretsiz barindirma / sik kotuye kullanilan platformlar
ABUSED_HOSTS = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "glitch.me", "repl.co",
    "web.app", "firebaseapp.com", "blogspot.com", "r2.dev", "workers.dev",
    "pages.dev", "duckdns.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "sharepoint-cdn.com", "backblazeb2.com", "storage.googleapis.com",
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click",
    ".link", ".work", ".fit", ".rest", ".country", ".kim", ".loan", ".men",
    ".date", ".stream", ".download", ".review", ".icu", ".cyou", ".sbs", ".buzz",
}

# Taklit edilen populer markalar
BRANDS = [
    "microsoft", "office365", "outlook", "onedrive", "sharepoint", "google",
    "gmail", "apple", "icloud", "amazon", "paypal", "netflix", "facebook",
    "instagram", "linkedin", "dropbox", "adobe", "docusign", "dhl", "fedex",
    "ups", "chase", "wellsfargo", "hsbc", "garanti", "isbank", "akbank",
    "yapikredi", "ziraat", "turkiye", "eDevlet", "edevlet", "ptt", "trendyol",
    "hepsiburada", "vakifbank", "denizbank", "qnb", "teb",
]

# Latin harflerine benzeyen Kiril/Yunan karakterleri
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ν": "v", "ο": "o", "α": "a",
    "ρ": "p", "ι": "i", "κ": "k", "μ": "m", "τ": "t",
}


def defang(url: str) -> str:
    """Tiklanamaz hale getirir: http://a.com -> hxxp://a[.]com"""
    return (url.replace("http://", "hxxp://")
               .replace("https://", "hxxps://")
               .replace(".", "[.]"))


def registered_domain(host: str) -> str:
    """Kaba bir eTLD+1 cikarimi (harici bagimlilik olmadan)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_level = {"co.uk", "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr",
                 "co.jp", "com.au", "com.br", "co.in", "com.mx", "gov.uk", "ac.uk"}
    if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(url: str, anchor_text: str = "") -> UrlInfo:
    raw = url.strip().rstrip(".,;:!?)")
    if raw.lower().startswith("www."):
        raw = "http://" + raw
    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or "").lower()
    info = UrlInfo(url=raw, domain=host, scheme=parsed.scheme,
                   anchor_text=anchor_text.strip(), defanged=defang(raw))
    notes = info.notes
    reg = registered_domain(host)

    if _is_ip(host):
        notes.append("alan adi yerine dogrudan IP adresi kullanilmis")
        try:
            if ipaddress.ip_address(host).is_private:
                notes.append("ozel (internal) IP araligi")
        except ValueError:
            pass
    if reg in SHORTENERS:
        notes.append(f"URL kisaltma servisi ({reg}) - gercek hedef gizli")
    if any(host.endswith(h) or reg == h for h in ABUSED_HOSTS):
        notes.append("kotuye kullanimi sik goruklen ucretsiz barindirma platformu")
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            notes.append(f"riskli ust seviye alan adi ({tld})")
            break
    if parsed.scheme == "http":
        notes.append("sifrelenmemis HTTP baglantisi")
    if "@" in (parsed.netloc or ""):
        notes.append("URL'de '@' ile kullanici bilgisi gizlemesi")
    if host.startswith("xn--") or ".xn--" in host:
        notes.append("punycode (IDN) alan adi - homograf saldirisi olabilir")
    if any(ch in host for ch in HOMOGLYPHS):
        notes.append("alan adinda Latin harfine benzeyen Kiril/Yunan karakter")
    if host.count(".") >= 4:
        notes.append(f"asiri alt alan adi derinligi ({host.count('.') + 1} seviye)")
    if len(raw) > 160:
        notes.append("asiri uzun URL")
    if re.search(r"(?i)(login|signin|verify|secure|account|update|confirm|billing|"
                 r"password|unlock|validate|recover)", parsed.path or ""):
        notes.append("kimlik dogrulama temali yol (login/verify/secure...)")
    if re.search(r"(?i)\.(exe|scr|js|hta|vbs|jar|msi|iso|zip|rar|ps1)$", parsed.path or ""):
        notes.append("dogrudan calistirilabilir/arsiv dosyasina isaret ediyor")

    brand = brand_lookalike(host)
    if brand:
        notes.append(f"'{brand}' markasini taklit eden alan adi")

    if anchor_text:
        mismatch = anchor_mismatch(anchor_text, host)
        if mismatch:
            notes.append(mismatch)
    return info


def brand_lookalike(host: str) -> str:
    """Marka adi barindiran ama resmi olmayan alan adlarini yakalar."""
    reg = registered_domain(host)
    label = reg.split(".")[0]
    for brand in BRANDS:
        brand_low = brand.lower()
        if brand_low in host and not reg.startswith(brand_low + "."):
            # microsoft.com mesru, microsoft-login.xyz degil
            if reg not in (f"{brand_low}.com", f"{brand_low}.com.tr", f"{brand_low}.net"):
                return brand
        ratio = difflib.SequenceMatcher(None, label, brand_low).ratio()
        if 0.75 <= ratio < 1.0 and abs(len(label) - len(brand_low)) <= 3:
            return brand
    return ""


def anchor_mismatch(anchor_text: str, real_host: str) -> str:
    """Gorunen metin bir URL/alan adi ise ve gercek hedefle uyusmuyorsa uyarir."""
    text = anchor_text.strip()
    match = re.search(r"(?i)(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", text)
    if not match:
        return ""
    shown = registered_domain(match.group(1))
    real = registered_domain(real_host)
    if shown and real and shown != real:
        return f"gorunen adres '{shown}' ama gercek hedef '{real}'"
    return ""


def extract_urls(text_body: str, html_body: str) -> List[UrlInfo]:
    """Duz metin ve HTML govdesinden benzersiz URL listesi cikarir."""
    seen: Dict[str, UrlInfo] = {}
    anchors: List[Tuple[str, str]] = _ANCHOR_RE.findall(html_body or "")
    for href, inner in anchors:
        if href.lower().startswith(("mailto:", "tel:", "#")):
            continue
        anchor_text = re.sub(r"(?s)<[^>]+>", " ", inner)
        anchor_text = re.sub(r"\s+", " ", anchor_text).strip()
        info = analyze_url(href, anchor_text)
        seen.setdefault(info.url, info)

    for blob in (text_body or "", re.sub(r"(?s)<[^>]+>", " ", html_body or "")):
        for match in _URL_RE.findall(blob):
            info = analyze_url(match)
            seen.setdefault(info.url, info)
    return list(seen.values())
