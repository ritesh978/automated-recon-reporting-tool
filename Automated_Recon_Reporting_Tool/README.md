# 🕵️ Automated Recon & Reporting Tool

**Author:** Ritesh Jogdand  
**Category:** Cybersecurity / Passive Reconnaissance  
**Date:** October 2025  

---

## 🚀 Overview

A **Python-based command-line tool** that performs **automated, passive reconnaissance** on a target domain using publicly available data sources such as **WHOIS**, **DNS**, and **Certificate Transparency (crt.sh)**.  
It generates clean, professional **Markdown** or **HTML** reports — perfect for documentation, security demos, and ethical hacking assessments.

---

## ⚙️ Features

- WHOIS lookup (registrar, creation/expiry, contact info)  
- DNS enumeration (A, AAAA, MX, NS, TXT, SOA records)  
- Certificate Transparency (crt.sh) subdomain discovery  
- Optional subdomain brute-force (small local wordlist)  
- Template-based Markdown or HTML reporting (Jinja2)  
- Ethical, passive-only operation — safe and legal use  

---

## 🧠 Tech Stack

| Component | Technology |
|------------|-------------|
| **Language** | Python 3.x |
| **Libraries** | `requests`, `python-whois`, `dnspython`, `jinja2`, `argparse` |
| **Data Sources** | WHOIS, DNS, crt.sh JSON endpoint |
| **Output Formats** | Markdown (.md) or HTML (.html) |

---

## 🧩 Project Structure

```
automated-recon-tool/
│
├── recon.py                    # main CLI script
├── requirements.txt             # dependencies
├── README.md                    # project documentation
├── wordlists/
│   └── small-wordlist.txt       # optional subdomain list
├── example_report.md            # sample generated report (Markdown)
├── example_report.html          # sample generated report (HTML)
└── demo.gif                     # short CLI demo (optional)
```

---

## 🧰 Installation & Usage

### 1️⃣ Setup Virtual Environment (Recommended)

```bash
# Create and activate venv (Linux/macOS)
python3 -m venv venv
source venv/bin/activate

# or on Windows
python -m venv venv
venv\Scripts\activate
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

(If you don’t have `requirements.txt`, install manually:)
```bash
pip install requests python-whois dnspython jinja2
```

### 3️⃣ Run the Tool

```bash
# Generate Markdown report
python recon.py --domain example.com --format md --output report_example.md

# Generate HTML report
python recon.py -d example.com -f html -o report_example.html

# Include optional wordlist-based subdomain check
python recon.py -d example.com --wordlist wordlists/small-wordlist.txt
```

---

## 🧾 Sample CLI Output

```
$ python recon.py -d example.com -f html -o report.html
[+] Passive recon for example.com
[*] WHOIS lookup...
[*] DNS queries (A, AAAA, MX, NS, TXT, SOA)...
[*] Querying crt.sh for subdomains...
[*] Quick resolving 12 crt.sh names ...
[*] Rendering report...
[+] Report written to report.html (took 5.2s)
```

---

## 🧑‍💻 Sample Report (Excerpt)

```
# Recon Report: example.com

**Generated:** 2025-10-24T10:00:00Z

## Summary
- Domain: `example.com`
- WHOIS available: Yes
- Subdomains (crt.sh): 2
- Resolved subdomains: 2

## WHOIS
**domain_name:** `EXAMPLE.COM`  
**registrar:** `Reserved Domain Name`

## Certificate Transparency (crt.sh)
- `www.example.com` — resolved: True, A: ['93.184.216.34']
- `example.com` — resolved: True, A: ['93.184.216.34']
```

---

## ⚖️ Ethics & Legal Disclaimer

> This tool performs **passive reconnaissance only**.  
> It does **not** perform intrusive scans or exploitation.  
> Use it **only** on domains you **own** or have **explicit authorization** to test.  
> Respect rate limits, robots.txt, and API Terms of Service.

---

## 🎯 Skills Demonstrated

- Python scripting & CLI design  
- DNS & WHOIS automation  
- JSON API parsing (crt.sh)  
- Jinja2 templating for reports  
- Exception handling & timeout management  
- Ethical hacking methodology & passive recon concepts  

---

## 💡 Future Improvements

- Integrate VirusTotal & SecurityTrails APIs  
- Add Flask dashboard for visualization  
- Include Dockerfile & CI workflow  
- Support CSV/JSON report exports  

---

## 📤 Deployment (Upload to GitHub)

```bash
git init
git add .
git commit -m "Initial commit: Automated Recon & Reporting Tool"
git branch -M main
git remote add origin https://github.com/<your-username>/automated-recon-tool.git
git push -u origin main
```

---

## 🧩 Author

**Ritesh Jogdand**  
Cybersecurity Enthusiast | CEH v13 Trainee | Python Developer  
📧 [Add your email if desired]  
🌐 [Add your LinkedIn or GitHub profile link]

---

### ⭐ Don’t forget to Star the repo if you find it useful!
