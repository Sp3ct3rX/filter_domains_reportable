     

<h1 align="center">🔍 WP Recon & Domain Intelligence Pipeline</h1>

<p align="center">
  <b>Developed by <span style="color:#00ffcc;">Sp3ct3r X</span></b><br>
  A scalable, resilient, high-speed framework for WordPress fingerprinting and domain intelligence filtering.
</p>

---

<p align="center">
<img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge">
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge">
<img src="https://img.shields.io/badge/Security-Pentesting%20Tool-orange?style=for-the-badge">
<img src="https://img.shields.io/badge/Maintainer-Sp3ct3r%20X-00ffcc?style=for-the-badge">
</p>

---

## 📌 Overview

This project automates **high-volume reconnaissance** for large domain lists (45k+), including:

✅ WordPress CMS detection  
✅ Verification by multiple WordPress indicators  
✅ Subdomain stripping & domain normalization  
✅ Smart error-handling & anti-block delay system  
✅ Multi-threaded workers (configurable)  
✅ API-based filtering (MajesticTF / MozSpam / MozDA) — optional module  

Suitable for:
- Red Team engagements
- Bug bounty recon automation
- Large-scale domain triage

---

## 🧠 WP Detection Logic

Detection is considered **valid** only if ≥ 2 indicators match:

| Indicator | Method |
|----------|--------|
| `wp-login.php` | Status 200/30x |
| `wp-json` REST API | 200 with valid JSON structure |
| `generator: WordPress` | HTML header meta |
| `/wp-content/` | presence in response code/static assets |
| `/wp-admin/` | restricted access (403/302 to login) |
| Powered by WordPress | manual fallback indicator |

> ⚠️ Redirects to domain-parking services / 404 / CDN placeholders **DO NOT** count as WordPress.

---

## 🚀 Performance

| Feature | Result |
|--------|-------|
| Concurrent Workers | 30–100 adjustable |
| Input Size | Tested up to 3+ GB raw files |
| Resume Support | ✅ continues from last processed record |
| Logging | detailed with timestamps |
| Verbose Mode | colored structured output |

> Timeouts & HTTP block → auto-backoff: **15 min cool-down** then resume from checkpoint.

---

## 🛠 Installation

```bash
git clone https://github.com/<YOUR-USERNAME>/wp-recon-pipeline.git
cd wp-recon-pipeline
pip install -r requirements.txt

▶️ Usage
1️⃣ Extract clean domains from credential data

python extract_clean_domains.py --input huge_input.txt --output clean_domains.txt

2️⃣ WordPress scanning

python wp_detect.py --input clean_domains.txt --output wp_targets.txt --workers 80 --verbose

Optional:

--resume true
--delay 0.5

📂 Output Structure

📁 output/

├── wp_valid.txt              # confirmed WordPress domains
├── wp_invalid.txt            # non-WordPress
├── errors.log                # errors & blocked cases
├── progress.state            # resume from last index
└── logs/
    ├── verbose.log
    └── workers/

All output logs use ✅🎨 color-coded categories:

    🟢 Success

    🟡 Retry

    🔴 Failed

    🔒 Blocked / IP Denied

🔐 Security & Ownership

This tool is proprietary.
Unauthorized copy, distribution, or resale is prohibited.

© 2025 — Sp3ct3r X — All Rights Reserved

✅ GPG Signature Verification

Every official release is signed by the author:

Author: Sp3ct3r X
Public Key Fingerprint: [REPLACE WITH YOURS]

Verify:

gpg --verify release.tar.gz.asc release.tar.gz

Public Key:

gpg --import sp3ct3r_pub.asc

📌 Roadmap
Feature	Status
Async scanning	✅
WP fingerprinting	✅
Auto-cooldown on block	✅
CMS classification (Joomla / Drupal / Shopify)	🔄
Dashboard with actionable insights	🔄
CI/CD Testing	🔲
🤝 Collaborators & Contact

For authorized use only.
شرایط همکاری تجاری از طریق درخواست رسمی:

📩 sp3ct3r@example.com


📌 Iran / EU — Available for cybersecurity consulting
<p align="center"> With 💀 & ⚡ by <b style="color:#00ffcc;">Sp3ct3r X</b> </p> ``` 
