"""PhishTriage birim testleri."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishtriage.analyzer import analyze_file, analyze_paths      # noqa: E402
from phishtriage.parser import inspect_attachment, split_address  # noqa: E402
from phishtriage.urls import (anchor_mismatch, analyze_url, brand_lookalike,  # noqa: E402
                              defang, extract_urls, registered_domain)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")


class TestUrlHelpers(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(defang("http://evil.com/a"), "hxxp://evil[.]com/a")

    def test_registered_domain(self):
        self.assertEqual(registered_domain("mail.google.com"), "google.com")
        self.assertEqual(registered_domain("a.b.sirket.com.tr"), "sirket.com.tr")
        self.assertEqual(registered_domain("evil.top"), "evil.top")

    def test_ip_url(self):
        info = analyze_url("http://194.87.144.9/x.php")
        self.assertTrue(any("IP adresi" in n for n in info.notes))

    def test_shortener(self):
        info = analyze_url("https://bit.ly/3xQzVn1")
        self.assertTrue(any("kisaltma" in n for n in info.notes))

    def test_brand_lookalike(self):
        self.assertEqual(brand_lookalike("microsoft-hesap-dogrulama.top"), "microsoft")
        self.assertEqual(brand_lookalike("www.microsoft.com"), "")
        self.assertEqual(brand_lookalike("paypa1.com"), "paypal")

    def test_anchor_mismatch(self):
        msg = anchor_mismatch("https://login.microsoftonline.com/verify",
                              "microsoft-hesap-dogrulama.top")
        self.assertIn("gercek hedef", msg)
        self.assertEqual(anchor_mismatch("Tum sayiyi oku", "python.org"), "")

    def test_punycode_and_at_trick(self):
        self.assertTrue(any("punycode" in n for n in analyze_url("http://xn--80ak6aa92e.com").notes))
        self.assertTrue(any("'@'" in n for n in
                            analyze_url("http://apple.com@evil.top/login").notes))

    def test_extract_urls_from_html(self):
        html = '<a href="http://evil.top/login">https://bank.com</a>'
        urls = extract_urls("", html)
        self.assertEqual(urls[0].domain, "evil.top")
        self.assertTrue(any("gercek hedef" in n for n in urls[0].notes))


class TestAttachments(unittest.TestCase):
    def test_double_extension(self):
        notes = inspect_attachment("Makbuz.pdf.exe", b"MZ\x90\x00")
        self.assertTrue(any("cift uzanti" in n for n in notes))
        self.assertTrue(any("PE (" in n for n in notes))

    def test_pdf_javascript(self):
        notes = inspect_attachment("a.pdf", b"%PDF-1.7 /OpenAction /JavaScript")
        self.assertTrue(any("JavaScript" in n for n in notes))

    def test_clean_file(self):
        self.assertEqual(inspect_attachment("rapor.txt", b"merhaba"), [])


class TestParserHelpers(unittest.TestCase):
    def test_split_address(self):
        self.assertEqual(split_address('"Ad Soyad" <A@B.com>'), ("Ad Soyad", "a@b.com"))


class TestEndToEnd(unittest.TestCase):
    def test_brand_impersonation_sample(self):
        a = analyze_file(os.path.join(SAMPLES, "01_marka_taklidi.eml"))
        self.assertEqual(a.verdict, "PHISHING")
        self.assertGreaterEqual(a.score, 70)
        codes = {i.code for i in a.indicators}
        self.assertIn("HDR003", codes)   # marka taklidi + freemail
        self.assertIn("HDR005", codes)   # reply-to farkli
        self.assertIn("AUT001", codes)   # spf fail
        self.assertIn("AUT003", codes)   # dmarc fail
        self.assertIn("BDY006", codes)   # html form
        self.assertIn("BDY005", codes)   # takip pikseli
        self.assertEqual(a.auth["spf"], "fail")

    def test_malicious_attachment_sample(self):
        a = analyze_file(os.path.join(SAMPLES, "02_zararli_ek.eml"))
        self.assertEqual(a.verdict, "PHISHING")
        self.assertEqual(len(a.attachments), 3)
        names = {x.filename for x in a.attachments}
        self.assertIn("Makbuz.pdf.exe", names)
        all_notes = " ".join(n for x in a.attachments for n in x.notes)
        self.assertIn("VBA makro", all_notes)
        self.assertIn("PE (", all_notes)
        for att in a.attachments:
            self.assertEqual(len(att.sha256), 64)

    def test_legitimate_sample_is_clean(self):
        a = analyze_file(os.path.join(SAMPLES, "03_mesru_bulten.eml"))
        self.assertEqual(a.verdict, "TEMIZ")
        self.assertEqual(a.score, 0)
        self.assertEqual(a.auth["dmarc"], "pass")

    def test_iocs_collected(self):
        a = analyze_file(os.path.join(SAMPLES, "02_zararli_ek.eml"))
        self.assertIn("194.87.144.9", a.iocs["domains"])
        self.assertEqual(len(a.iocs["attachment_sha256"]), 3)
        self.assertIn("185.244.25.171", a.iocs["source_ips"])

    def test_analyze_directory(self):
        results = analyze_paths([SAMPLES])
        self.assertEqual(len(results), 3)
        self.assertEqual(sum(1 for r in results if r.verdict == "PHISHING"), 2)

    def test_received_chain_order(self):
        a = analyze_file(os.path.join(SAMPLES, "01_marka_taklidi.eml"))
        self.assertEqual(len(a.hops), 2)
        self.assertEqual(a.hops[0]["hop"], "1")

    def test_missing_file_is_graceful(self):
        a = analyze_file(os.path.join(SAMPLES, "yok.eml"))
        self.assertIsNotNone(a.error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
