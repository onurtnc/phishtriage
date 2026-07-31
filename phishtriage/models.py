"""Ortak veri modelleri."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Indicator:
    """Tek bir supheli bulgu."""
    code: str
    title: str
    detail: str
    weight: int              # 0-40 arasi puan katkisi
    category: str = "general"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code, "title": self.title, "detail": self.detail,
            "weight": self.weight, "category": self.category,
        }


@dataclass
class UrlInfo:
    url: str
    domain: str = ""
    scheme: str = ""
    anchor_text: str = ""
    defanged: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url, "defanged": self.defanged, "domain": self.domain,
            "scheme": self.scheme, "anchor_text": self.anchor_text, "notes": self.notes,
        }


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    md5: str = ""
    sha256: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename, "content_type": self.content_type,
            "size": self.size, "md5": self.md5, "sha256": self.sha256,
            "notes": self.notes,
        }


@dataclass
class Analysis:
    path: str
    subject: str = ""
    from_display: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    hops: List[Dict[str, str]] = field(default_factory=list)
    auth: Dict[str, str] = field(default_factory=dict)
    urls: List[UrlInfo] = field(default_factory=list)
    attachments: List[AttachmentInfo] = field(default_factory=list)
    indicators: List[Indicator] = field(default_factory=list)
    body_preview: str = ""
    error: Optional[str] = None

    # ------------------------------------------------------------------ #
    @property
    def score(self) -> int:
        return min(100, sum(i.weight for i in self.indicators))

    @property
    def verdict(self) -> str:
        score = self.score
        if score >= 70:
            return "PHISHING"
        if score >= 40:
            return "SUPHELI"
        if score >= 15:
            return "DUSUK RISK"
        return "TEMIZ"

    @property
    def iocs(self) -> Dict[str, List[str]]:
        domains = sorted({u.domain for u in self.urls if u.domain})
        return {
            "urls": sorted({u.url for u in self.urls}),
            "domains": domains,
            "sender_domain": [self.from_address.split("@")[-1]] if "@" in self.from_address else [],
            "attachment_sha256": [a.sha256 for a in self.attachments if a.sha256],
            "source_ips": sorted({h["ip"] for h in self.hops if h.get("ip")}),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.path,
            "verdict": self.verdict,
            "score": self.score,
            "headers": {
                "subject": self.subject, "from_display": self.from_display,
                "from_address": self.from_address, "reply_to": self.reply_to,
                "return_path": self.return_path, "to": self.to,
                "date": self.date, "message_id": self.message_id,
            },
            "authentication": self.auth,
            "hops": self.hops,
            "urls": [u.to_dict() for u in self.urls],
            "attachments": [a.to_dict() for a in self.attachments],
            "indicators": [i.to_dict() for i in self.indicators],
            "iocs": self.iocs,
            "body_preview": self.body_preview,
            "error": self.error,
        }
