#!/usr/bin/env python3
"""
recon.py - Passive Recon & Report CLI

Passive modules:
 - WHOIS (python-whois)
 - DNS records (dnspython)
 - Certificate Transparency lookup (crt.sh JSON)
 - Optional subdomain wordlist resolution (simple DNS resolves; still fairly innocuous)

Outputs:
 - Markdown (.md) or HTML (.html) report using Jinja2 templates.

Usage:
  python recon.py --domain example.com --format md --output report_example.md
  python recon.py -d example.com -f html -o report_example.html --no-bruteforce
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import List, Dict, Any, Set

import requests
import whois
import dns.resolver
import dns.exception

from jinja2 import Template

# -------------------------
# Config
# -------------------------
CRT_SH_URL = "https://crt.sh/?q=%25{domain}&output=json"
DEFAULT_TIMEOUT = 5.0

# -------------------------
# Helper functions
# -------------------------
def whois_lookup(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        # whois.whois returns an object that may have datetime/date/strings
        # Convert to dictionary-friendly types.
        data = {}
        for k, v in w.__dict__.items():
            try:
                json.dumps({k: v}, default=str)
                data[k] = v
            except Exception:
                data[k] = str(v)
        return data
    except Exception as e:
        return {"error": f"whois lookup failed: {e}"}


def dns_query(domain: str, record_type: str) -> List[str]:
    res = []
    r = dns.resolver.Resolver()
    r.lifetime = DEFAULT_TIMEOUT
    try:
        answers = r.resolve(domain, record_type, lifetime=DEFAULT_TIMEOUT)
        for a in answers:
            res.append(str(a).strip())
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except dns.exception.Timeout:
        pass
    except Exception as e:
        res.append(f"error: {e}")
    return res


def crtsh_subdomains(domain: str) -> List[str]:
    """Query crt.sh JSON output and extract DNS names."""
    try:
        url = CRT_SH_URL.format(domain=domain)
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []
        entries = resp.json()
        names = set()
        for e in entries:
            name = e.get("name_value")
            if not name:
                continue
            # `name_value` may contain newlines with multiple names.
            for n in str(name).splitlines():
                # Normalize wildcard and whitespace
                n = n.strip().lstrip("*.")
                if n.endswith(domain):
                    names.add(n)
        return sorted(names)
    except Exception:
        return []


def resolve_subdomains(subs: List[str], timeout: float = 2.0) -> Dict[str, Dict[str, Any]]:
    """Resolve a list of hostnames for A/AAAA records (lightweight)."""
    results = {}
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    for s in subs:
        if s in results:
            continue
        record = {"A": [], "AAAA": [], "resolved": False}
        try:
            a = r.resolve(s, "A", lifetime=timeout)
            record["A"] = [str(x) for x in a]
            record["resolved"] = True
        except Exception:
            pass
        try:
            a6 = r.resolve(s, "AAAA", lifetime=timeout)
            record["AAAA"] = [str(x) for x in a6]
            record["resolved"] = True if record["resolved"] else bool(record["AAAA"])
        except Exception:
            pass
        results[s] = record
    return results


def brute_subdomains(domain: str, wordlist_path: str, max_entries: int = 10000) -> List[str]:
    """Optional: read a small wordlist and try resolve <word>.<domain>. 
       This performs many DNS queries — keep small and optional.
    """
    names = []
    if not os.path.exists(wordlist_path):
        return names
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh):
            if i >= max_entries:
                break
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            names.append(f"{w}.{domain}")
    return names


# -------------------------
# Templates
# -------------------------
MD_TEMPLATE = """# Recon Report: {{ domain }}

**Generated:** {{ generated_at }}

## Summary
- Domain: `{{ domain }}`
- WHOIS available: {{ 'Yes' if whois_data and not whois_error else 'No' }}
- Subdomains (crt.sh): {{ subdomains|length }}
- Resolved subdomains (quick DNS test): {{ resolved_count }}

---

## WHOIS
{% if whois_error %}
WHOIS lookup failed: `{{ whois_error }}`
{% else %}
{% for k, v in whois_data.items() %}
**{{ k }}:** `{{ v }}`  
{% endfor %}
{% endif %}

---

## DNS records
{% for rtype, vals in dns_records.items() %}
### {{ rtype }}
{% if vals %}
{% for v in vals %}
- `{{ v }}`
{% endfor %}
{% else %}
_No records found_
{% endif %}
{% endfor %}

---

## Certificate Transparency (crt.sh) subdomains
Found {{ subdomains|length }} unique names.
{% for s in subdomains %}
- `{{ s }}`{% if resolved_map.get(s) %} — resolved: {{ resolved_map[s]['resolved'] }}, A: {{ resolved_map[s]['A'] }}, AAAA: {{ resolved_map[s]['AAAA'] }}{% endif %}
{% endfor %}

---

## Optional Brute-forced subdomains (wordlist)
{% if bruteforce_list %}
Tried {{ bruteforce_list|length }} candidates. (Note: this is a limited wordlist check.)
{% for s in bruteforce_list %}
- `{{ s }}`{% if bruteforce_resolved.get(s) %} — resolved: {{ bruteforce_resolved[s]['resolved'] }}, A: {{ bruteforce_resolved[s]['A'] }}, AAAA: {{ bruteforce_resolved[s]['AAAA'] }}{% endif %}
{% endfor %}
{% else %}
_No brute-force wordlist used._
{% endif %}

---

## Notes & next steps
- This report uses only passive / DNS-based lookups and public certificate transparency logs (crt.sh).
- Recommended next steps: manual inspection, more passive sources (SecurityTrails, PassiveTotal, VirusTotal, with API keys), link analysis, web crawling (be mindful of robots.txt and rate limits).
"""

HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Recon Report: {{ domain }}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial; margin: 24px; color: #111; }
    header { border-bottom: 1px solid #ddd; margin-bottom: 16px; padding-bottom: 8px; }
    pre { background:#f7f7f7; padding:8px; border-radius:6px; overflow:auto; }
    .section { margin-top: 16px; }
    .k { font-weight:600; }
    .small { color:#666; font-size:0.9em; }
    table { border-collapse: collapse; width:100%; }
    th, td { border: 1px solid #eee; padding:8px; text-align:left; }
  </style>
</head>
<body>
  <header>
    <h1>Recon Report: {{ domain }}</h1>
    <div class="small">Generated: {{ generated_at }}</div>
  </header>

  <div class="section">
    <h2>Summary</h2>
    <ul>
      <li><strong>Domain:</strong> {{ domain }}</li>
      <li><strong>WHOIS available:</strong> {{ 'Yes' if whois_data and not whois_error else 'No' }}</li>
      <li><strong>Subdomains (crt.sh):</strong> {{ subdomains|length }}</li>
      <li><strong>Resolved subdomains (quick DNS):</strong> {{ resolved_count }}</li>
    </ul>
  </div>

  <div class="section">
    <h2>WHOIS</h2>
    {% if whois_error %}
      <pre>{{ whois_error }}</pre>
    {% else %}
      <table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>
      {% for k, v in whois_data.items() %}
        <tr><td class="k">{{ k }}</td><td>{{ v }}</td></tr>
      {% endfor %}
      </tbody></table>
    {% endif %}
  </div>

  <div class="section">
    <h2>DNS records</h2>
    {% for rtype, vals in dns_records.items() %}
      <h3>{{ rtype }}</h3>
      {% if vals %}
        <ul>{% for v in vals %}<li><pre>{{ v }}</pre></li>{% endfor %}</ul>
      {% else %}
        <div class="small">No records found</div>
      {% endif %}
    {% endfor %}
  </div>

  <div class="section">
    <h2>Certificate Transparency (crt.sh)</h2>
    <p>Found {{ subdomains|length }} names.</p>
    <table><thead><tr><th>Name</th><th>Resolved</th><th>A</th><th>AAAA</th></tr></thead><tbody>
    {% for s in subdomains %}
      <tr>
        <td>{{ s }}</td>
        <td>{{ resolved_map.get(s, {}).get('resolved', False) }}</td>
        <td>{{ resolved_map.get(s, {}).get('A', []) }}</td>
        <td>{{ resolved_map.get(s, {}).get('AAAA', []) }}</td>
      </tr>
    {% endfor %}
    </tbody></table>
  </div>

  <div class="section">
    <h2>Brute candidates (wordlist)</h2>
    {% if bruteforce_list %}
      <p>Tried {{ bruteforce_list|length }} candidates.</p>
      <table><thead><tr><th>Name</th><th>Resolved</th><th>A</th><th>AAAA</th></tr></thead><tbody>
      {% for s in bruteforce_list %}
        <tr>
          <td>{{ s }}</td>
          <td>{{ bruteforce_resolved.get(s, {}).get('resolved', False) }}</td>
          <td>{{ bruteforce_resolved.get(s, {}).get('A', []) }}</td>
          <td>{{ bruteforce_resolved.get(s, {}).get('AAAA', []) }}</td>
        </tr>
      {% endfor %}
      </tbody></table>
    {% else %}
      <div class="small">No brute force wordlist used.</div>
    {% endif %}
  </div>

  <footer class="section small">
    <p>Passive-only recon. Respect robots.txt and rate limits for further enumeration.</p>
  </footer>
</body>
</html>
"""

# -------------------------
# Report generation
# -------------------------
def render_report(data: Dict[str, Any], fmt: str = "md") -> str:
    tpl = MD_TEMPLATE if fmt.lower() in ("md", "markdown") else HTML_TEMPLATE
    rendered = Template(tpl).render(**data)
    return rendered


# -------------------------
# CLI
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Passive Recon & Report generator")
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    p.add_argument("-o", "--output", default=None, help="Output file path (defaults to recon_<domain>.md)")
    p.add_argument("-f", "--format", choices=["md", "html"], default="md", help="Output format")
    p.add_argument("--no-bruteforce", dest="bruteforce", action="store_false", help="Disable wordlist-based bruteforce")
    p.add_argument("--wordlist", help="Optional wordlist for subdomain bruteforce (one entry per line)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="DNS timeout (seconds)")
    return p.parse_args()


def main():
    args = parse_args()
    domain = args.domain.strip()
    fmt = args.format.lower()
    out = args.output or f"recon_{domain.replace('.', '_')}.{fmt}"

    print(f"[+] Passive recon for {domain}")
    start = time.time()

    # WHOIS
    print("[*] WHOIS lookup...")
    whois_data = whois_lookup(domain)
    whois_error = None
    if "error" in whois_data:
        whois_error = whois_data.get("error")
        whois_data = {}

    # DNS records
    print("[*] DNS queries (A, AAAA, MX, NS, TXT, SOA)...")
    dns_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    dns_records = {}
    for t in dns_types:
        dns_records[t] = dns_query(domain, t)

    # crt.sh subdomains
    print("[*] Querying Certificate Transparency logs (crt.sh)...")
    subdomains = crtsh_subdomains(domain)
    subdomains_unique = sorted(set(subdomains))

    # quick resolution of subdomains (lightweight)
    print(f"[*] Quick resolving {len(subdomains_unique)} crt.sh names ...")
    resolved_map = resolve_subdomains(subdomains_unique, timeout=args.timeout)

    # optional bruteforce
    bruteforce_list = []
    bruteforce_resolved = {}
    if args.bruteforce and args.wordlist:
        print("[*] Loading wordlist and preparing bruteforce candidates...")
        bruteforce_list = brute_subdomains(domain, args.wordlist)
        print(f"[*] Attempting resolve of {len(bruteforce_list)} candidates...")
        bruteforce_resolved = resolve_subdomains(bruteforce_list, timeout=args.timeout)

    resolved_count = sum(1 for v in resolved_map.values() if v.get("resolved"))

    data = {
        "domain": domain,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "whois_data": whois_data,
        "whois_error": whois_error,
        "dns_records": dns_records,
        "subdomains": subdomains_unique,
        "resolved_map": resolved_map,
        "resolved_count": resolved_count,
        "bruteforce_list": bruteforce_list,
        "bruteforce_resolved": bruteforce_resolved,
    }

    print("[*] Rendering report...")
    report_text = render_report(data, fmt=fmt)

    with open(out, "w", encoding="utf-8") as fh:
        fh.write(report_text)
    elapsed = time.time() - start
    print(f"[+] Report written to {out} (took {elapsed:.1f}s)")

if __name__ == "__main__":
    main()

