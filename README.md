# PhishTriage

**Supheli e-postalari saniyeler icinde triyaj eden, sifir bagimlilikli SOC araci.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-19%20passing-success)

Bir `.eml` dosyasi verin; PhishTriage baslik zincirini, SPF/DKIM/DMARC sonuclarini,
her baglantiyi ve her eki inceleyip **0-100 arasi bir phishing skoru** ve gerekce
listesi uretsin. Ciktiyi dogrudan ticket'a yapistirabilir, IOC'leri SIEM'e besleyebilirsiniz.

---

## Neden?

Tier-1 SOC'a gelen ticket'larin buyuk bolumu "bu mail sahte mi?" sorusudur. Elle
bakildiginda her biri 5-10 dakika alir: baslik oku, SPF kontrol et, linkleri defang
et, eki hash'le. PhishTriage bunu tek komuta indirir ve **neden** supheli oldugunu
madde madde soyler — yani analistin yerine karar vermez, ona gerekce sunar.

## Ozellikler

### Baslik analizi
- Gorunen ad ile gercek gonderen adresi uyusmazligi
- `Reply-To` ve `Return-Path` farkliligi (cevap saldirgana gidiyor mu)
- Marka taklidi + ucretsiz e-posta saglayicisi kombinasyonu
- Eksik/uyumsuz `Message-ID`, sahte `Re:` konu basligi
- `Received` zincirinin cozulmesi, kaynak IP'lerin cikarilmasi

### Kimlik dogrulama
- `Authentication-Results` ve `Received-SPF` basliklarindan SPF / DKIM / DMARC / compauth
- `fail`, `softfail`, `none` durumlarinin agirliklandirilmasi

### Baglanti analizi
- HTML `<a>` etiketlerinde **gorunen metin ile gercek hedef uyusmazligi**
- Marka taklidi alan adlari (`microsoft-hesap-dogrulama.top`) ve typo-squat tespiti
- Punycode / IDN homograf, Kiril-Latin karakter karisimi
- URL kisaltma servisleri, `@` ile kullanici gizleme, dogrudan IP kullanimi
- Riskli TLD'ler (`.zip`, `.top`, `.xyz`, `.tk`...), kotuye kullanilan barindirma platformlari
- Tum URL'ler otomatik **defang** edilir (`hxxp://evil[.]com`)

### Ek dosya analizi
- MD5 + SHA256 hash (dogrudan VirusTotal/IOCForge'a beslenebilir)
- Riskli uzantilar, cift uzanti gizlemesi (`Makbuz.pdf.exe`), RTLO karakteri
- Office dosyasinda **VBA makro projesi** tespiti (zip icerigi taranir)
- PDF icinde `/JavaScript`, `/OpenAction`, `/Launch`, gomulu dosya
- PE (`MZ`) imzasi kontrolu

### Icerik analizi
- Turkce + Ingilizce aciliyet/korku dili ve kimlik bilgisi talebi sozlugu
- E-posta govdesine gomulu HTML `<form>` (kimlik toplama)
- 1x1 takip pikseli, `display:none` ile gizlenmis metin
- Kisisellestirilmemis hitap ("Sayin Musteri")

## Kurulum

```bash
git clone https://github.com/<kullanici>/phishtriage.git
cd phishtriage
python -m phishtriage samples/     # kurulum gerekmiyor
```

Komut olarak eklemek icin: `pip install -e .`

## Kullanim

```bash
# Tum ornekleri analiz et
python -m phishtriage samples/

# Tek dosya, detayli (teslim zinciri + icerik onizleme)
python -m phishtriage supheli.eml -v

# HTML rapor uret (ticket'a eklemek icin)
python -m phishtriage karantina/ --html rapor.html

# Sadece IOC listesi - SIEM/TIP'e beslemek icin
python -m phishtriage supheli.eml --iocs

# Toplu tarama: sadece 40 puan uzeri olanlari goster
python -m phishtriage kutu/ --min-score 40 --json bulgular.json

# CI/otomasyon: 70+ skorlu mail varsa exit 1
python -m phishtriage kutu/ --fail-on 70 --quiet
```

### Ornek cikti

```
==============================================================================
  PhishTriage  -  01_marka_taklidi.eml
==============================================================================
  Karar:  PHISHING    Skor: [####################] 100/100
------------------------------------------------------------------------------
  Konu       : ACIL: Hesabiniz 24 saat icinde askiya alinacak
  Gonderen   : Microsoft Hesap Guvenligi <security-noreply2026@gmail.com>
  Reply-To   : destek@microsoft-hesap-dogrulama.top
  Dogrulama  : SPF=fail  DKIM=none  DMARC=fail

  BULGULAR (14)
   [+35] Kurumsal marka taklidi + ucretsiz e-posta  (Baslik)
          Gorunen ad 'Microsoft Hesap Guvenligi' ile 'microsoft' taklit ediliyor
          ama adres ucretsiz bir saglayicida (gmail.com).
   [+30] Gorunen adres 'microsoftonline.com' ama gercek hedef
         'microsoft-hesap-dogrulama.top'  (Baglanti)
   [+30] DMARC politikasi ihlal edildi (fail)  (Kimlik dogrulama)
   [+25] E-posta icinde HTML form  (Icerik)
   ...

  IOC OZETI
   urls: http://microsoft-hesap-dogrulama.top/login/verify?id=8812
   domains: microsoft-hesap-dogrulama.top, bit.ly
   source_ips: 193.176.79.204, 127.0.0.1
```

## Skorlama

Her bulgu bir agirlik tasir; toplam 100'de kesilir.

| Skor | Karar | Ne yapmali |
|---|---|---|
| 70-100 | **PHISHING** | Karantinaya al, gonderen/URL'leri blokla, alicilari uyar |
| 40-69 | **SUPHELI** | Analist incelemesi gerekli, kum havuzunda ac |
| 15-39 | **DUSUK RISK** | Muhtemelen pazarlama/spam, kaydet gec |
| 0-14 | **TEMIZ** | Islem gerekmiyor |

Agirliklar `phishtriage/scoring.py` icinde tek yerde tanimlidir; kurumunuzun
gercekligine gore rahatca ayarlayabilirsiniz.

## `.msg` dosyalari

Outlook'un OLE tabanli `.msg` formati desteklenmez (arac bilincli olarak sifir
bagimlilik tutar). Outlook'ta **Farkli Kaydet → .eml** ile disari aktarin, ya da:

```bash
pip install extract-msg
extract_msg --out-dir . mail.msg
```

## Mimari

```
phishtriage/
├── models.py     Indicator / UrlInfo / AttachmentInfo / Analysis veri siniflari
├── parser.py     EML okuma, Received zinciri, SPF-DKIM-DMARC, ek cikarma
├── urls.py       URL cikarma, defang, marka/homograf/anchor analizi
├── scoring.py    Tum gostergeler ve agirliklari (ayar noktasi burasi)
├── analyzer.py   Akisi birlestiren katman
├── report.py     Konsol / JSON / HTML ciktilari
└── cli.py        argparse arayuzu
```

## Testler

```bash
python -m unittest discover -s tests -v
```

`samples/` altinda uc gercekci ornek var: marka taklidi phishing, zararli ekli
sahte fatura ve temiz bir bulten. Testler her ucunun dogru siniflandirildigini
dogrular.

## Yol haritasi

- [ ] VirusTotal / URLhaus entegrasyonu (IOCForge ile ortak)
- [ ] IMAP kutusuna baglanip otomatik tarama
- [ ] QR kod (quishing) tespiti — gorsel eklerdeki QR'lari cozme
- [ ] MISP formatinda IOC disa aktarimi
- [ ] Yerlesik `.msg` cozucu

## Sorumluluk reddi

Savunma amacli bir aractir. Uretilen skor **otomatik karar degil**, analistin
inceleme baslangicidir. Zararli ekleri asla uretim makinesinde acmayin.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
