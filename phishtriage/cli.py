"""PhishTriage komut satiri arayuzu."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from . import __version__
from .analyzer import analyze_paths
from .report import to_console, to_html, to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishtriage",
        description="Supheli e-postalari (.eml) analiz edip phishing skoru uretir.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""ornekler:
  phishtriage samples/                        # tum ornekleri analiz et
  phishtriage mail.eml -v                     # teslim zinciri + icerik onizleme
  phishtriage kutu/ --html rapor.html
  phishtriage mail.eml --iocs                 # sadece IOC listesi (SIEM'e beslemek icin)
  phishtriage kutu/ --min-score 40 --quiet --json bulgular.json
""")
    parser.add_argument("inputs", nargs="+", help=".eml dosyasi veya dizin")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="teslim zinciri ve icerik onizlemesini de goster")
    parser.add_argument("--json", metavar="PATH", help="JSON raporu yaz")
    parser.add_argument("--html", metavar="PATH", help="HTML raporu yaz")
    parser.add_argument("--iocs", action="store_true",
                        help="sadece IOC listesini yazdir (satir satir)")
    parser.add_argument("--min-score", type=int, default=0,
                        help="bu skorun altindaki mailleri gosterme")
    parser.add_argument("--no-color", action="store_true", help="ANSI renklerini kapat")
    parser.add_argument("--quiet", action="store_true", help="konsol ciktisini bastir")
    parser.add_argument("--fail-on", type=int, default=-1, metavar="SKOR",
                        help="bu skor ve uzeri mail varsa exit code 1 dondur")
    parser.add_argument("-V", "--version", action="version", version=f"phishtriage {__version__}")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        analyses = analyze_paths(args.inputs)
    except FileNotFoundError as exc:
        print(f"Bulunamadi: {exc}", file=sys.stderr)
        return 2
    if not analyses:
        print("Analiz edilecek e-posta bulunamadi.", file=sys.stderr)
        return 2

    shown = [a for a in analyses if a.score >= args.min_score or a.error]

    if args.iocs:
        seen = set()
        for analysis in shown:
            for kind, values in analysis.iocs.items():
                for value in values:
                    key = (kind, value)
                    if value and key not in seen:
                        seen.add(key)
                        print(f"{kind}\t{value}")
    elif not args.quiet:
        print(to_console(shown, use_color=not args.no_color, verbose=args.verbose))
        verdicts = {}
        for analysis in analyses:
            verdicts[analysis.verdict] = verdicts.get(analysis.verdict, 0) + 1
        summary = "  ".join(f"{k}: {v}" for k, v in verdicts.items())
        print(f"Toplam {len(analyses)} e-posta analiz edildi.  {summary}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(shown))
        print(f"JSON raporu -> {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(shown))
        print(f"HTML raporu -> {args.html}")

    if args.fail_on >= 0 and any(a.score >= args.fail_on for a in analyses):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
