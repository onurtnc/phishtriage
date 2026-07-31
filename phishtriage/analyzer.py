"""Tum parcalari birlestiren ana analiz akisi."""
from __future__ import annotations

import os
from typing import List

from .models import Analysis
from .parser import (all_addresses, extract_attachments, extract_bodies, header,
                     html_to_text, parse_authentication, parse_received_chain,
                     read_message, split_address)
from .scoring import build_indicators
from .urls import extract_urls


def analyze_file(path: str) -> Analysis:
    analysis = Analysis(path=os.path.basename(path))
    try:
        msg = read_message(path)
    except Exception as exc:
        analysis.error = str(exc)
        return analysis

    display, address = split_address(header(msg, "From"))
    analysis.subject = header(msg, "Subject")
    analysis.from_display = display
    analysis.from_address = address
    analysis.to = header(msg, "To")
    analysis.date = header(msg, "Date")
    analysis.message_id = header(msg, "Message-ID")
    reply_to = all_addresses(header(msg, "Reply-To"))
    analysis.reply_to = reply_to[0] if reply_to else ""
    return_path = all_addresses(header(msg, "Return-Path"))
    analysis.return_path = return_path[0] if return_path else ""
    analysis.hops = parse_received_chain(msg)
    analysis.auth = parse_authentication(msg)

    text_body, html_body = extract_bodies(msg)
    analysis.urls = extract_urls(text_body, html_body)
    analysis.attachments = extract_attachments(msg)

    preview_source = text_body.strip() or html_to_text(html_body)
    analysis.body_preview = " ".join(preview_source.split())[:600]

    analysis.indicators = build_indicators(analysis, text_body, html_body)
    return analysis


def analyze_paths(paths: List[str]) -> List[Analysis]:
    files: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, names in os.walk(path):
                files.extend(
                    os.path.join(root, n) for n in sorted(names)
                    if n.lower().endswith((".eml", ".msg", ".txt"))
                )
        else:
            files.append(path)
    return [analyze_file(f) for f in files]
