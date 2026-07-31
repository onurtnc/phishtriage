"""Gostergeleri toplayip phishing skorunu uretir."""
from __future__ import annotations

import re
from typing import List

from .models import Analysis, Indicator
from .urls import BRANDS, registered_domain

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yandex.com", "yandex.ru", "mail.ru", "proton.me",
    "protonmail.com", "aol.com", "gmx.com", "zoho.com", "icloud.com",
    "mynet.com", "hotmail.com.tr",
}

URGENCY = [
    "acil", "acilen", "hemen", "derhal", "son uyari", "son gun", "24 saat icinde",
    "gecikmeden", "askiya alin", "askiya alindi", "kapatilacak", "silinecek",
    "dogrulayin", "dogrulama gerekli", "onaylayin", "sifrenizi", "hesabiniz",
    "urgent", "immediately", "act now", "final notice", "last warning",
    "within 24 hours", "will be suspended", "will be deleted", "verify your",
    "confirm your", "your account", "action required", "password expire",
    "unusual activity", "unauthorized login", "click here", "update payment",
]

CREDENTIAL_BAIT = [
    "sifre", "parola", "kullanici adi", "oturum ac", "giris yap", "kimlik dogrula",
    "kredi karti", "iban", "tc kimlik", "guvenlik kodu", "cvv", "otp", "sms kodu",
    "password", "username", "sign in", "log in", "credentials", "credit card",
    "social security", "one-time code", "mfa code", "wire transfer",
    "gift card", "bitcoin", "invoice attached", "payment details",
]

_TAG_RE = re.compile(r"(?s)<[^>]+>")


def _norm(text: str) -> str:
    table = str.maketrans("ıİşŞğĞüÜöÖçÇ", "iisSgGuUoOcC")
    return text.lower().translate(table)


# --------------------------------------------------------------------------- #
def score_headers(analysis: Analysis) -> List[Indicator]:
    out: List[Indicator] = []
    from_addr = analysis.from_address
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    from_reg = registered_domain(from_domain) if from_domain else ""
    display = analysis.from_display

    if not from_addr:
        out.append(Indicator("HDR001", "Gonderen adresi yok",
                             "From basligi bos veya cozulemedi.", 15, "header"))

    # Display name icinde farkli bir e-posta adresi
    display_mail = re.search(r"[\w.+-]+@[\w.-]+\.\w+", display or "")
    if display_mail and display_mail.group(0).lower() != from_addr:
        out.append(Indicator(
            "HDR002", "Gorunen ad sahte adres iceriyor",
            f"Gorunen ad '{display_mail.group(0)}' gosteriyor ama gercek gonderen "
            f"'{from_addr}'.", 30, "header"))

    # Marka taklidi + freemail
    norm_display = _norm(display or "")
    impersonated = next((b for b in BRANDS if b.lower() in norm_display), "")
    if impersonated and from_reg in FREEMAIL:
        out.append(Indicator(
            "HDR003", "Kurumsal marka taklidi + ucretsiz e-posta",
            f"Gorunen ad '{display}' ile '{impersonated}' taklit ediliyor ama adres "
            f"ucretsiz bir saglayicida ({from_reg}).", 35, "header"))
    elif impersonated and from_reg and not any(
            from_reg.startswith(b.lower()) for b in BRANDS):
        out.append(Indicator(
            "HDR004", "Gorunen ad ile gonderen alan adi uyusmuyor",
            f"'{impersonated}' adina gonderilmis gibi gorunuyor, gercek alan adi "
            f"'{from_reg}'.", 20, "header"))

    # Reply-To farkli alan adi
    if analysis.reply_to:
        reply_domain = registered_domain(analysis.reply_to.split("@")[-1])
        if reply_domain and from_reg and reply_domain != from_reg:
            out.append(Indicator(
                "HDR005", "Reply-To farkli bir alan adina yonlendiriyor",
                f"From: {from_reg} / Reply-To: {reply_domain}. Cevaplar saldirgana gider.",
                25, "header"))

    # Return-Path farkli (zarf gondereni)
    if analysis.return_path and "@" in analysis.return_path:
        rp_domain = registered_domain(analysis.return_path.split("@")[-1])
        if rp_domain and from_reg and rp_domain != from_reg:
            out.append(Indicator(
                "HDR006", "Return-Path ile From alan adi uyusmuyor",
                f"Zarf gondereni '{rp_domain}', baslikta yazan '{from_reg}'. "
                "Klasik sahtecilik gostergesi.", 20, "header"))

    if not analysis.message_id:
        out.append(Indicator("HDR007", "Message-ID basligi yok",
                             "Mesru posta sunuculari her zaman Message-ID ekler.",
                             10, "header"))
    elif from_reg and "@" in analysis.message_id:
        mid_domain = registered_domain(analysis.message_id.split("@")[-1].strip("<> "))
        if mid_domain and mid_domain != from_reg:
            out.append(Indicator(
                "HDR008", "Message-ID alan adi gonderenle uyusmuyor",
                f"Message-ID '{mid_domain}' uzerinden uretilmis.", 8, "header"))

    if re.match(r"(?i)^\s*(re|fw|fwd|yan|ilt)\s*:", analysis.subject or "") and \
            not analysis.hops[:1]:
        out.append(Indicator(
            "HDR009", "Sahte yanit konusu",
            "Konu 'Re:/Fwd:' ile basliyor ama mesajda onceki yazisma izi yok.",
            10, "header"))
    return out


def score_authentication(analysis: Analysis) -> List[Indicator]:
    out: List[Indicator] = []
    auth = analysis.auth
    fail_values = {"fail", "softfail", "permerror", "temperror", "none", "neutral"}

    if auth.get("spf", "yok").lower() in ("fail", "softfail"):
        out.append(Indicator("AUT001", f"SPF dogrulamasi basarisiz ({auth['spf']})",
                             "Gonderen sunucu bu alan adi adina posta gondermeye yetkili degil.",
                             25, "auth"))
    if auth.get("dkim", "yok").lower() in fail_values and auth.get("dkim") != "yok":
        out.append(Indicator("AUT002", f"DKIM dogrulamasi basarisiz ({auth['dkim']})",
                             "Mesaj icerigi imzali degil veya imza gecersiz.", 20, "auth"))
    if auth.get("dmarc", "yok").lower() in ("fail", "quarantine", "reject"):
        out.append(Indicator("AUT003", f"DMARC politikasi ihlal edildi ({auth['dmarc']})",
                             "Alan adi sahibinin politikasina gore bu mesaj sahte.", 30, "auth"))
    if all(v == "yok" for k, v in auth.items() if k != "compauth"):
        out.append(Indicator("AUT004", "Kimlik dogrulama basligi hic yok",
                             "SPF/DKIM/DMARC sonucu bulunamadi; mesaj dogrulanmamis "
                             "bir yoldan gelmis olabilir.", 12, "auth"))
    return out


def score_urls(analysis: Analysis) -> List[Indicator]:
    out: List[Indicator] = []
    weights = {
        "gorunen adres": 30, "markasini taklit": 30, "punycode": 28,
        "Kiril/Yunan": 28, "'@' ile": 25, "kisaltma servisi": 15,
        "dogrudan IP": 22, "calistirilabilir/arsiv": 25,
        "riskli ust seviye": 12, "ucretsiz barindirma": 15,
        "kimlik dogrulama temali": 10, "asiri alt alan": 10,
        "sifrelenmemis HTTP": 5, "asiri uzun": 5,
    }
    seen_codes = set()
    for url_info in analysis.urls:
        for note in url_info.notes:
            weight = next((w for key, w in weights.items() if key in note), 5)
            code = f"URL-{abs(hash(note)) % 9973:04d}"
            if note in seen_codes:
                continue
            seen_codes.add(note)
            out.append(Indicator(
                code, note.capitalize(),
                f"{url_info.defanged}" + (f"  (metin: '{url_info.anchor_text}')"
                                          if url_info.anchor_text else ""),
                weight, "url"))
    if len(analysis.urls) > 25:
        out.append(Indicator("URL999", "Cok fazla baglanti",
                             f"{len(analysis.urls)} farkli URL bulundu.", 5, "url"))
    return out


def score_attachments(analysis: Analysis) -> List[Indicator]:
    out: List[Indicator] = []
    weights = {
        "riskli uzanti": 35, "PE (Windows": 40, "VBA makro": 35,
        "cift uzanti": 35, "RTLO": 40, "makro icerebilen": 25,
        "PDF icinde": 20, "arsiv dosyasi": 10,
    }
    for att in analysis.attachments:
        for note in att.notes:
            weight = next((w for key, w in weights.items() if key in note), 8)
            out.append(Indicator(
                f"ATT-{abs(hash(note + att.filename)) % 9973:04d}",
                note.capitalize(), f"{att.filename} ({att.size} bayt)",
                weight, "attachment"))
    return out


def score_body(analysis: Analysis, text_body: str, html_body: str) -> List[Indicator]:
    out: List[Indicator] = []
    combined = _norm(f"{analysis.subject}\n{text_body}\n{_TAG_RE.sub(' ', html_body)}")

    urgency_hits = sorted({k for k in URGENCY if _norm(k) in combined})
    if urgency_hits:
        out.append(Indicator(
            "BDY001", "Aciliyet / korku dili",
            "Gecen ifadeler: " + ", ".join(urgency_hits[:6]),
            min(20, 5 + 4 * len(urgency_hits)), "body"))

    bait_hits = sorted({k for k in CREDENTIAL_BAIT if _norm(k) in combined})
    if bait_hits:
        out.append(Indicator(
            "BDY002", "Kimlik bilgisi / odeme talebi",
            "Gecen ifadeler: " + ", ".join(bait_hits[:6]),
            min(25, 8 + 4 * len(bait_hits)), "body"))

    if re.search(r"(?i)(sayin (musteri|kullanici|yetkili)|dear (customer|user|sir|madam)|"
                 r"valued customer|account holder)", combined):
        out.append(Indicator("BDY003", "Kisisellestirilmemis hitap",
                             "Mesru kurumlar genellikle adinizla hitap eder.", 8, "body"))

    if html_body and not text_body.strip():
        out.append(Indicator("BDY004", "Sadece HTML govde",
                             "Duz metin alternatifi yok; icerik gizleme icin kullanilabilir.",
                             5, "body"))

    if re.search(r"(?i)<img[^>]+width\s*=\s*[\"']?1[\"']?[^>]*height\s*=\s*[\"']?1", html_body or ""):
        out.append(Indicator("BDY005", "Takip pikseli (1x1 gorsel)",
                             "Mesajin okunup okunmadigini izleyen gizli gorsel.", 10, "body"))

    if re.search(r"(?i)<form\b", html_body or ""):
        out.append(Indicator("BDY006", "E-posta icinde HTML form",
                             "Kimlik bilgisi toplamak icin kullanilan klasik yontem.",
                             25, "body"))

    if re.search(r"(?i)style\s*=\s*[\"'][^\"']*(display\s*:\s*none|font-size\s*:\s*0)", html_body or ""):
        out.append(Indicator("BDY007", "Gizlenmis metin",
                             "display:none / font-size:0 ile spam filtresi atlatma denemesi.",
                             12, "body"))
    return out


def build_indicators(analysis: Analysis, text_body: str, html_body: str) -> List[Indicator]:
    indicators: List[Indicator] = []
    indicators += score_headers(analysis)
    indicators += score_authentication(analysis)
    indicators += score_urls(analysis)
    indicators += score_attachments(analysis)
    indicators += score_body(analysis, text_body, html_body)
    indicators.sort(key=lambda i: -i.weight)
    return indicators
