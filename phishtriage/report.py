"""Analiz ciktilarini konsol / JSON / HTML olarak sunar."""
from __future__ import annotations

import html
import json
from typing import List

from .models import Analysis

COLORS = {
    "PHISHING": "\033[97;41m", "SUPHELI": "\033[91m",
    "DUSUK RISK": "\033[93m", "TEMIZ": "\033[92m",
}
HEX = {
    "PHISHING": "#b3001b", "SUPHELI": "#e8590c",
    "DUSUK RISK": "#f08c00", "TEMIZ": "#2b8a3e",
}
RESET, BOLD = "\033[0m", "\033[1m"

CATEGORY_TR = {
    "header": "Baslik", "auth": "Kimlik dogrulama", "url": "Baglanti",
    "attachment": "Ek dosya", "body": "Icerik", "general": "Genel",
}


def _c(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{RESET}" if use_color else text


def to_console(analyses: List[Analysis], use_color: bool = True, verbose: bool = False) -> str:
    lines: List[str] = []
    for analysis in analyses:
        lines.append(_c("=" * 78, BOLD, use_color))
        lines.append(_c(f"  PhishTriage  -  {analysis.path}", BOLD, use_color))
        lines.append(_c("=" * 78, BOLD, use_color))

        if analysis.error:
            lines.append(f"  HATA: {analysis.error}\n")
            continue

        verdict = analysis.verdict
        bar = "#" * (analysis.score // 5) + "." * (20 - analysis.score // 5)
        lines.append("  Karar: " + _c(f" {verdict} ", COLORS.get(verdict, ""), use_color)
                     + f"   Skor: [{bar}] {analysis.score}/100")
        lines.append("-" * 78)
        lines.append(f"  Konu       : {analysis.subject or '-'}")
        sender = f"{analysis.from_display} <{analysis.from_address}>" \
            if analysis.from_display else analysis.from_address
        lines.append(f"  Gonderen   : {sender or '-'}")
        if analysis.reply_to:
            lines.append(f"  Reply-To   : {analysis.reply_to}")
        if analysis.return_path:
            lines.append(f"  Return-Path: {analysis.return_path}")
        lines.append(f"  Alici      : {analysis.to or '-'}")
        lines.append(f"  Tarih      : {analysis.date or '-'}")
        auth = analysis.auth
        lines.append(f"  Dogrulama  : SPF={auth.get('spf')}  DKIM={auth.get('dkim')}  "
                     f"DMARC={auth.get('dmarc')}")
        lines.append("")

        if analysis.indicators:
            lines.append(_c(f"  BULGULAR ({len(analysis.indicators)})", BOLD, use_color))
            for ind in analysis.indicators:
                tag = f"[+{ind.weight:>2}]"
                cat = CATEGORY_TR.get(ind.category, ind.category)
                lines.append(_c(f"   {tag} {ind.title}", COLORS.get(verdict, ""), use_color)
                             + f"  ({cat})")
                lines.append(f"          {ind.detail}")
            lines.append("")
        else:
            lines.append("  Supheli bulgu yok.\n")

        if analysis.urls:
            lines.append(_c(f"  BAGLANTILAR ({len(analysis.urls)})", BOLD, use_color))
            for url in analysis.urls[:15]:
                lines.append(f"   - {url.defanged}")
                if url.anchor_text:
                    lines.append(f"     gorunen metin: {url.anchor_text[:80]}")
                for note in url.notes:
                    lines.append(f"     ! {note}")
            if len(analysis.urls) > 15:
                lines.append(f"   ... {len(analysis.urls) - 15} baglanti daha")
            lines.append("")

        if analysis.attachments:
            lines.append(_c(f"  EKLER ({len(analysis.attachments)})", BOLD, use_color))
            for att in analysis.attachments:
                lines.append(f"   - {att.filename}  [{att.content_type}, {att.size} bayt]")
                lines.append(f"     sha256: {att.sha256}")
                for note in att.notes:
                    lines.append(f"     ! {note}")
            lines.append("")

        if verbose and analysis.hops:
            lines.append(_c("  TESLIM ZINCIRI", BOLD, use_color))
            for hop in analysis.hops:
                lines.append(f"   {hop['hop']}. {hop['from'] or '?'} -> {hop['by'] or '?'}"
                             f"  {('[' + hop['ip'] + ']') if hop['ip'] else ''}")
            lines.append("")

        if verbose and analysis.body_preview:
            lines.append(_c("  ICERIK ONIZLEME", BOLD, use_color))
            lines.append(f"   {analysis.body_preview[:400]}")
            lines.append("")

        iocs = analysis.iocs
        flat = [i for values in iocs.values() for i in values]
        if flat:
            lines.append(_c("  IOC OZETI", BOLD, use_color))
            for key, values in iocs.items():
                if values:
                    lines.append(f"   {key}: {', '.join(values[:6])}")
            lines.append("")
    return "\n".join(lines)


def to_json(analyses: List[Analysis]) -> str:
    return json.dumps([a.to_dict() for a in analyses], indent=2, ensure_ascii=False)


def to_html(analyses: List[Analysis]) -> str:
    blocks = []
    for a in analyses:
        color = HEX.get(a.verdict, "#868e96")
        indicators = "".join(
            f"<li><span class='w'>+{i.weight}</span><b>{html.escape(i.title)}</b>"
            f"<span class='cat'>{html.escape(CATEGORY_TR.get(i.category, i.category))}</span>"
            f"<div class='d'>{html.escape(i.detail)}</div></li>"
            for i in a.indicators) or "<li>Supheli bulgu yok.</li>"
        urls = "".join(
            f"<li><code>{html.escape(u.defanged)}</code>"
            + (f"<div class='d'>gorunen metin: {html.escape(u.anchor_text[:100])}</div>"
               if u.anchor_text else "")
            + "".join(f"<div class='n'>! {html.escape(n)}</div>" for n in u.notes)
            + "</li>" for u in a.urls) or "<li>Baglanti yok.</li>"
        atts = "".join(
            f"<li><b>{html.escape(x.filename)}</b> <span class='d'>{x.size} bayt "
            f"&middot; {html.escape(x.content_type)}</span>"
            f"<div class='d'><code>{x.sha256}</code></div>"
            + "".join(f"<div class='n'>! {html.escape(n)}</div>" for n in x.notes)
            + "</li>" for x in a.attachments) or "<li>Ek yok.</li>"

        blocks.append(f"""
<section class="mail">
  <div class="head">
    <span class="verdict" style="background:{color}">{html.escape(a.verdict)}</span>
    <span class="score">{a.score}/100</span>
    <h2>{html.escape(a.subject or '(konu yok)')}</h2>
    <div class="d">{html.escape(a.path)}</div>
  </div>
  <table class="hdr">
    <tr><th>Gonderen</th><td>{html.escape(a.from_display)} &lt;{html.escape(a.from_address)}&gt;</td></tr>
    <tr><th>Reply-To</th><td>{html.escape(a.reply_to or '-')}</td></tr>
    <tr><th>Return-Path</th><td>{html.escape(a.return_path or '-')}</td></tr>
    <tr><th>Alici</th><td>{html.escape(a.to or '-')}</td></tr>
    <tr><th>Tarih</th><td>{html.escape(a.date or '-')}</td></tr>
    <tr><th>SPF / DKIM / DMARC</th><td>{html.escape(a.auth.get('spf','?'))} /
        {html.escape(a.auth.get('dkim','?'))} / {html.escape(a.auth.get('dmarc','?'))}</td></tr>
  </table>
  <h3>Bulgular</h3><ul class="ind">{indicators}</ul>
  <h3>Baglantilar</h3><ul class="url">{urls}</ul>
  <h3>Ekler</h3><ul class="url">{atts}</ul>
</section>""")

    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishTriage Raporu</title><style>
 body {{ font-family:-apple-system,Segoe UI,Roboto,sans-serif; background:#0f1115;
        color:#e6e6e6; margin:0; padding:24px; }}
 h1 {{ font-size:22px; margin:0 0 18px; }}
 .mail {{ background:#171a21; border:1px solid #262b36; border-radius:12px;
          padding:18px 22px; margin-bottom:22px; }}
 .head h2 {{ margin:8px 0 2px; font-size:17px; }}
 .verdict {{ padding:4px 12px; border-radius:20px; color:#fff; font-weight:700; font-size:12px; }}
 .score {{ margin-left:10px; color:#9aa0a6; font-size:13px; }}
 .d {{ color:#9aa0a6; font-size:12px; }}
 .n {{ color:#ffa94d; font-size:12px; }}
 h3 {{ font-size:13px; text-transform:uppercase; color:#9aa0a6;
       border-bottom:1px solid #262b36; padding-bottom:6px; margin:18px 0 8px; }}
 table.hdr {{ width:100%; border-collapse:collapse; margin-top:12px; }}
 table.hdr th {{ text-align:left; color:#9aa0a6; font-weight:500; font-size:12px;
                 width:170px; padding:3px 0; vertical-align:top; }}
 table.hdr td {{ font-size:13px; padding:3px 0; word-break:break-all; }}
 ul {{ list-style:none; padding:0; margin:0; }}
 ul li {{ padding:8px 0; border-bottom:1px solid #21262f; font-size:13px; }}
 .w {{ display:inline-block; min-width:38px; color:#ff6b6b; font-weight:700; }}
 .cat {{ margin-left:8px; color:#5c9ded; font-size:11px; }}
 code {{ font-family:ui-monospace,Menlo,Consolas,monospace; word-break:break-all; }}
</style></head><body>
<h1>PhishTriage - E-posta Triyaj Raporu</h1>
{''.join(blocks)}
</body></html>"""
