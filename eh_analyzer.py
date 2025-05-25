#!/usr/bin/env python3
"""
EH Analyzer – Lightweight e‑mail forensics (single‑file)

Note: AI ChatGPT included to be used if system variable 'OPENAI_API_KEY' is in place and using param --ai
================================================================

Innovations baked in:
 • Colour‑coded authentication table (green / red / orange / grey) with raw info
 • Optional YARA autogenerator (`--yara`) → produces ready‑to‑use .yar

USAGE
-----
$ python eh_analyzer.py message.eml                        # analyse one .eml
$ python eh_analyzer.py inbox/ --export json               # folder → JSON
$ python eh_analyzer.py phish.eml --yara                   # generate yara file

DEPENDENCIES
------------
pip install rich pyfiglet beautifulsoup4 tldextract

pip install -r requirements.txt

__version__ = "1.0.1"

Author: Dagent-E –  2025
"""

import argparse
import hashlib
import json
import pathlib
import re
from urllib.parse import urlparse, parse_qs, unquote
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import List, Dict

from bs4 import BeautifulSoup  # type: ignore
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.panel import Panel
from pyfiglet import Figlet  # type: ignore
import tldextract  # type: ignore

import time

# ──────────────────────────────────────────────────────────────────────────────
# ChatGPT integration
# pip install openai>=1.14
# ──────────────────────────────────────────────────────────────────────────────

import os
import openai

def gpt_header_analyzer(all_gpt_data: str) -> str:
    """
    Send the raw email headers to the ChatGPT API and return the model's response.
    """
    openai.api_key = os.getenv("OPENAI_API_KEY")
    if not openai.api_key:
        raise ValueError("Please set the OPENAI_API_KEY environment variable.")

    chatgpt_input_data = all_gpt_data

    response = openai.ChatCompletion.create(
        model="gpt-4.1-nano",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert email forensics analyst.\n\n"
                    "1) Produce up to five bullet points, each starting with an emoji:\n"
                    "   ✔️ benign, ⚠️ suspicious, ❌ malicious.\n"
                    "   In your bullets, address:\n"
                    "     • SPF, DKIM & DMARC results (with special note that passes via public relays are expected but not conclusive)\n"
                    "     • Envelope From vs. Header From & Return-Path mismatches\n"
                    "     • Received-chain hops, HELO/EHLO name vs. PTR consistency\n"
                    "     • Message-ID formatting oddities\n"
                    "     • Any URLs or List-Unsubscribe links (hover-check text vs. actual href)\n"
                    "     • Header typos or formatting anomalies\n"
                    "     • MIME structure quirks and suspicious attachments (double extensions, macros, executables)\n"
                    "     • Content cues (urgency, poor grammar, unexpected requests)\n"
                    "     • Reputation signals (newly registered domains, blacklist hits)\n\n"
                    "2) Next, in 4–6 sentences, write a detailed analysis that:\n"
                    "     • Explains the likely *purpose* of this message (e.g., phishing, spam, legitimate notification, CV auto-reply, etc.)\n"
                    "     • Cites specific header or content clues (links, language, attachments) supporting that inference\n"
                    "     • Notes when public-relay passes (gmail/hotmail) don’t prove legitimacy\n"
                    "     • Recommends whether to trust, block, or investigate further\n\n"
                    "3) Finally, given all of the above, assign a risk score from 0.0 to 10.0 and provide a recommended action:\n"
                    "     • Be conservative—err on the side of higher risk for any uncertainty.\n"
                    "     • You dont have to always give an action, not all emails should be blocked. Maybe just double-checked by IT/sec team..\n"
                    "     • Output on its own line as: GPT Risk score: {chatgpt_score}\n\n"
                    "     • Output on its own line as: GPT Recommended Action: {chatgpt_recomm_action}\n\n"
                    "Use clear, professional language and keep your bullet points concise."
                )
            },
            {"role": "user", "content": chatgpt_input_data}
        ],
        temperature=0.3, # Defines the randomness of the output, meaning the more temperature the more creative GPT gets. Accurracy implies lower temp like 0.3.
                         # Range goes from 0.0 to 2.0 (if I remember correctly.)
        max_tokens=800   # Max Token Usage. Increase with caution not to use all your tokens too fast. I've found between 800-1200 it works really well.
                         # But you are all invited to try higher values. I didn't want to spend my 5$ so I didn't do it. :)
    )

    chatgpt_output_data = response.choices[0].message.content.strip()

    return chatgpt_output_data

# ──────────────────────────────────────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────────────────────────────────────

URL_RE = re.compile(r"https?://[\w\-./%?=&#+~:;,@!$()*]+", re.I)
console = Console(record=True)
figlet = Figlet(font="slant")

# ──────────────────────────────────────────────────────────────────────────────
# CONST
# ──────────────────────────────────────────────────────────────────────────────

DANGEROUS_TLDS = {
    "ru", "su", "top", "tk", "cc", "vip", "xyz", "loan", "xin", "gdn", "info", "bid", "pro",
    "sbs", "one", "icu", "cf", "ga", "gq", "ml", "pw", "zip", "cm", "pink", "pizza", "pictures", "cam",
    "ooo", "rest", "plus", "wiki", "wang", "skin", "support", "wiki", "world", "finance",
    "fyi", "zone", "ink", "mom", "click", "cyou", "today", "best"
}

DANGEROUS_FILE_EXTENSIONS = {
    # Executable and Script Files
    ".exe", ".com", ".bat", ".cmd", ".msi", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".jar",
    # Microsoft Office Documents with Macros
    ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".ppam", ".ppsm", ".sldm",
    # Compressed and Archive Files
    ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz", ".ace",
    # Disk Image Files
    ".iso", ".img",
    # PDF and Other Document Formats
    ".rtf", ".html", ".htm",
    # Shortcut and Link Files
    ".lnk", ".url", ".desktop", ".scf",
    # Other Potentially Dangerous Files
    ".dll", ".sys", ".cpl", ".msc", ".jar", ".apk", ".app", ".pif", ".scr", ".hta", ".sh", ".pl", ".rb", ".py", ".php", ".asp", ".aspx", ".jsp", ".cgi", ".shtml", ".cfm", ".swf", ".flv", ".fla", ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".svg", ".ico", ".psd", ".ai", ".eps", ".indd", ".eps", ".pdf", ".epub", ".mobi"
}

LEAST_DANGEROUS_FILE_EXTENSIONS = {
    # PDF and Other Document Formats
    ".pdf", ".xls", "xlsx", "doc", "docx"
}

#TODO: File Transfer sites like WeTransfer, Dropbox, GoFile and more domains commonly used by attackers.

# ---------------------------------------------------------------------------
# Banner helper
# ---------------------------------------------------------------------------

def print_banner() -> None:
    banner_big = figlet.renderText("EH Analyzer")
    console.print(banner_big, style="bold green")
    console.print("[dim]by Dagent-E[/dim]\n")

# ---------------------------------------------------------------------------
# File & hash helpers
# ---------------------------------------------------------------------------

def load_messages(target: pathlib.Path):
    """Return a list of tuples (filename, EmailMessage)."""
    files = [target] if target.is_file() else sorted(target.glob("*.eml"))
    if not files:
        console.print(f"[red]No .eml files found in {target}")
        sys.exit(1)
    messages = []
    for fp in files:
        try:
            with fp.open("rb") as f:
                msg = BytesParser(policy=policy.default).parse(f)
                messages.append((fp.name, msg))
        except Exception as exc:
            console.print(f"[yellow]Warning:[/] could not parse {fp}: {exc}")
    return messages

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------

def extract_headers(msg):
    wanted = [
        "From",
        "To",
        "Cc",
        "Subject",
        "Date",
        "Message-ID",
        "Return-Path",
        "Reply-To",
        "Delivered-To",
        "List-Unsubscribe",
        "X-Mailer",
    ]
    return {h: msg.get(h, "") for h in wanted}

def _parse_auth_fragment(fragment: str):
    """Return (status, info) for DKIM/SPF/DMARC fragment string."""
    if fragment is None:
        return "?", ""
    m = re.search(r"=(pass|fail|neutral|softfail|none)", fragment, re.I)
    status = m.group(1).lower() if m else "?"
    return status, fragment.strip()

def extract_auth(msg):
    """Return dict {method: {status, info}} with colour‑aware DMARC."""
    auth_hdr = msg.get("Authentication-Results", "")

    dkim_frag = re.search(r"dkim=[^;]+", auth_hdr, re.I)
    spf_frag = re.search(r"spf=[^;]+", auth_hdr, re.I)
    dmarc_frag = re.search(r"dmarc=[^;]+", auth_hdr, re.I)

    dkim_status, dkim_info = _parse_auth_fragment(dkim_frag.group(0) if dkim_frag else None)
    spf_status, spf_info = _parse_auth_fragment(spf_frag.group(0) if spf_frag else None)
    dmarc_status, dmarc_info = _parse_auth_fragment(dmarc_frag.group(0) if dmarc_frag else None)

    # Special case: DMARC policy none ⇒ treat as "none"
    if dmarc_status == "pass" and re.search(r"p=none", auth_hdr, re.I):
        dmarc_status = "none"

    # Fallback SPF header
    if spf_status == "?":
        spf_hdr = msg.get("Received-SPF", "")
        if spf_hdr:
            spf_status = "pass" if "pass" in spf_hdr.lower() else "fail"
            spf_info = spf_hdr.strip()

    return {
        "DKIM": {"status": dkim_status, "info": dkim_info},
        "SPF": {"status": spf_status, "info": spf_info},
        "DMARC": {"status": dmarc_status, "info": dmarc_info},
    }

def extract_attachments(msg):
    attaches = []
    for part in msg.walk():
        if part.is_attachment():
            fname = part.get_filename() or "(no-name)"
            data = part.get_content()
            if isinstance(data, str):
                data = data.encode()
            attaches.append(
                {
                    "name": fname,
                    "mime": part.get_content_type(),
                    "size": len(data), # Praise the sun. Size not being read? 
                    "sha256": sha256(data),
                }
            )
    return attaches

def extract_urls(msg):
    urls = set()
    for part in msg.walk():
        ctype = part.get_content_type()
        try:
            payload = part.get_content()
        except Exception:
            continue
        if isinstance(payload, bytes):
            try:
                payload = payload.decode(errors="ignore")
            except Exception:
                continue
        if ctype == "text/plain":
            urls.update(URL_RE.findall(payload))
        elif ctype == "text/html":
            soup = BeautifulSoup(payload, "html.parser")
            urls.update(a["href"] for a in soup.find_all("a", href=True))
            urls.update(tag["src"] for tag in soup.find_all(src=True) if tag.has_attr("src"))
            urls.update(URL_RE.findall(soup.get_text(" ")))
    return sorted(set(str(u).strip("\"'<>") for u in urls))

# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

# — new Base64‐pattern (2+ 4-char groups, optional padding) —
BASE64_PATTERN = re.compile(
    r'^(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
)

def heuristic_score(auth, urls, attachments):
    score = 0

    for method in ("SPF", "DKIM", "DMARC"):
        if auth[method]["status"] == "fail" or auth[method]["status"] == "?" or auth[method]["status"] == "softfail":
            score += 15

    for u in urls:
        # TLD risk
        suffix = tldextract.extract(u).suffix
        if suffix in DANGEROUS_TLDS:
            score += 10

        #print("The URL is : " + u)
        anom_urls = ["wa.me", "telegram.me", "t.me", "discord.gg", "chat.whatsapp.com", "snapchat.com", "wechat.com", "wetransfer", "dropbox"]
        anomalous_sub = any(pattern in u for pattern in anom_urls)

        if anomalous_sub:
            #print("Social Network and or Anomalous Site Found: " + u)
            score += 10
 
        # Base64‐in‐URL risk
        parsed = urlparse(u)
        parts = parsed.path.split("/") + sum(parse_qs(parsed.query).values(), [])
        for seg in parts:
            token = unquote(seg)
            if BASE64_PATTERN.match(token):
                score += 30
                break

    for a in attachments:
        #if a["mime"] in ("application/x-msdownload", "application/octet-stream") or a["name"].lower().endswith((".exe", ".scr", ".js", ".vbs", ".com")):
        #    score += 35

        # After some deep-thinking I decided to remove MIME/TYPES since they can be easily faked and therefore not provide the real filetype. Yes? Makes sense? I guess so...
        if a["name"].lower().endswith(tuple(DANGEROUS_FILE_EXTENSIONS)):
            score += 35

        if a["name"].lower().endswith(tuple(LEAST_DANGEROUS_FILE_EXTENSIONS)):
            score += 15

    return min(score, 100)

# ---------------------------------------------------------------------------
# YARA autogenerator
# ---------------------------------------------------------------------------

# TODO: Not repeat URLs, currently the YARA exported file works like this: 
# if a domain even with different URI is found 3 times, the very same domain is added 3 times in the YARA Rules.

def yara_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\"", "\\\"")

def generate_yara(ruleset: List[Dict], outfile: pathlib.Path):
    with outfile.open("w", encoding="utf-8") as fh:
        fh.write("// Auto-generated by EH Analyzer (Dagent-E)\n\n")
        fh.write("import \"hash\"\n\n")
        for idx, r in enumerate(ruleset, 1):
            rule_name = f"EHA_{idx}"
            fh.write(f"rule {rule_name} {{\n")
            fh.write("    meta:\n")
            fh.write("        author = \"Dagent-E\"\n")
            fh.write(f"        date = \"{datetime.now(timezone.utc).date()}\"\n")
            fh.write("    strings:\n")
            fh.write(f"        $subject = \"{yara_escape(r['subject'])}\" nocase\n")
            if r["from"]:
                fh.write(f"        $from = \"{yara_escape(r['from'])}\" nocase\n")
            for i, fn in enumerate(r["filenames"], 1):
                fh.write(f"        $fname{i} = \"{yara_escape(fn)}\" nocase\n")
            for i, dom in enumerate(r["domains"], 1):
                fh.write(f"        $url{i} = \"{yara_escape(dom)}\" nocase\n")
            fh.write("    condition:\n")
            fh.write("        any of ($subject, $from, $fname*, $url*)\n")
            fh.write("}\n\n")
    console.print(f"[green]YARA file saved to {outfile}")

# ---------------------------------------------------------------------------
# Renderers – Tables
# ---------------------------------------------------------------------------

def _status_style(status: str) -> str:
    mapping = {"pass": "green", "fail": "red", "none": "orange1", "?": "grey50"}
    return mapping.get(status, "grey50")

def render_report(filename, headers, auth, urls, attachments, score):
    console.rule(f"[bold cyan]{filename}")

    # Headers
    tbl_headers = Table(title="Key Headers", show_lines=True)
    tbl_headers.add_column("Header")
    tbl_headers.add_column("Value", overflow="fold")
    for k, v in headers.items():
        if v:
            tbl_headers.add_row(k, v)
    console.print(tbl_headers)

    # Authentication
    tbl_auth = Table(title="Authentication", show_header=True, show_lines=True)
    tbl_auth.add_column("Method", justify="center")
    tbl_auth.add_column("Status", justify="center")
    tbl_auth.add_column("Info", overflow="fold")
    for method in ("DKIM", "SPF", "DMARC"):
        st = auth[method]["status"]
        info = auth[method]["info"] or "-"
        tbl_auth.add_row(method, f"[{_status_style(st)}]{st}[/]", info)
    console.print(tbl_auth)

    # Attachments
    if attachments:
        tbl_att = Table(title="Attachments")
        tbl_att.add_column("Name")
        tbl_att.add_column("MIME")
        tbl_att.add_column("Size (B)", justify="right")
        tbl_att.add_column("SHA-256", overflow="fold")
        for a in attachments:
            tbl_att.add_row(a["name"], a["mime"], str(a["size"]), a["sha256"])
        console.print(tbl_att)

    # URLs
    if urls:
        tbl_url = Table(title="Detected URLs")
        tbl_url.add_column("URL", overflow="fold")
        for u in urls:
            tbl_url.add_row(u)
        console.print(tbl_url)


    # ChatGPT-powered header analysis (moved to just before Estimated risk)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="EH Analyzer – e-mail forensics CLI")
    parser.add_argument("target", nargs="?", type=pathlib.Path, help=".eml file or directory")
    parser.add_argument("--export", choices=["json","plain"], help="Export consolidated JSON report")
    parser.add_argument("--yara", metavar="FILE", nargs="?", const="eha_rules.yar", help="Generate YARA rules to FILE (default: eha_rules.yar)")
    parser.add_argument("--ai", action="store_true", help="Enable ChatGPT-powered header analysis in the report")
    args = parser.parse_args()

    # Banner
    print_banner()

    if args.target is None:
        parser.print_help()
        return

    console.print(f"[green]Loading e-mails from {args.target}…[/]")
    messages = load_messages(args.target)

    export_data = []
    yara_rules_input = []  # Collect data for YARA generation

    for fname, msg in messages:
        headers = extract_headers(msg)
        auth = extract_auth(msg)
        attachments = extract_attachments(msg)
        urls = extract_urls(msg)
        score = heuristic_score(auth, urls, attachments)

        all_headers = "\n".join(f"{k}: {v}" for k, v in headers.items() if v)
        all_auth    = "\n".join(f"{m}: {info['status']} ({info['info'] or '-'})"
                                for m, info in auth.items())
        all_attchs  = "\n".join(
            f"{a['name']} | {a['mime']} | {a['size']} bytes"
            for a in attachments
        ) or "(no attachments)"
        all_urls    = "\n".join(urls) or "(no URLs)"

        all_gpt_data = "\n\n".join([
            "HEADERS:\n"    + all_headers,
            "AUTH RESULTS:\n"+ all_auth,
            "ATTACHMENTS:\n"+ all_attchs,
            "URLS:\n"       + all_urls,
        ])

        render_report(fname, headers, auth, urls, attachments, score)

        export_data.append({                       # unchanged below
            "file": fname,
            "headers": headers,
            "auth": auth,
            "attachments": attachments,
            "urls": urls,
            "score": score,
        })

        export_data.append(
            {
                "file": fname,
                "headers": headers,
                "auth": auth,
                "attachments": attachments,
                "urls": urls,
                "score": score,
            }
        )

        yara_rules_input.append(
            {
                "subject": headers.get("Subject", ""),
                "from": headers.get("From", ""),
                "filenames": [a["name"] for a in attachments],
                "domains": [tldextract.extract(u).top_domain_under_public_suffix or u for u in urls],
            }
        )

    # JSON export
    if args.export == "json":
        outfile = pathlib.Path("report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json")
        outfile.write_text(json.dumps(export_data, indent=2, ensure_ascii=False))
        console.print(f"[green]JSON report saved to {outfile}")

    # YARA generation
    if args.yara:
        generate_yara(yara_rules_input, pathlib.Path(args.yara))
    # Plain export
    if args.export == "plain":
        txt_file = pathlib.Path("report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt")
        txt_file.write_text(console.export_text(clear=False))
        console.print(f"[green]Plain text report saved to {txt_file}")

    # ChatGPT-powered header analysis
    if args.ai:
        try:
            console.print("")
            with console.status("[bold yellow]Analyzing with ChatGPT…", spinner="dots"):
                time.sleep(0.1)
                chatgpt_insight = gpt_header_analyzer(all_gpt_data)

            # Full forensic analysis panel
            console.print(
                Panel(
                    chatgpt_insight,
                    title="ChatGPT Forensic Analysis",
                    border_style="yellow",
                    box=box.ROUNDED,
                    expand=False
                )
            )

            # Inline score & action
            score_match = re.search(r"GPT Risk score:\s*(\d+(?:\.\d+)?)", chatgpt_insight)
            action_match = re.search(r"GPT Recommended Action:\s*(.+)", chatgpt_insight)
            if score_match and action_match:
                score_text = Text.assemble((score_match.group(1), "bold magenta"))
                action_text = Text.assemble((action_match.group(1), "bold bright_blue"))
                inline = Columns([
                    Panel(score_text, title="Risk Score", border_style="magenta", box=box.SQUARE, expand=True),
                    Panel(action_text, title="Action", border_style="bright_blue", box=box.SQUARE, expand=True)
                ], expand=False)
                console.print(inline)

        except Exception as e:
            console.print(f"[yellow]Warning:[/] ChatGPT analysis failed: {e}")

    console.print(Panel(f"[bold red]Heuristic Estimated risk:[/] {score}/100"))
    console.print()

if __name__ == "__main__":
    main()



