# EH Analyzer — Lightweight e-mail forensics in a single Python file

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open Issues](https://img.shields.io/github/issues/Dagent-E/eh_analyzer.svg)](https://github.com/Dagent-E/eh_analyzer/issues)

> **EH Analyzer** (`eh_analyzer.py`) is a *terminal-first* Swiss-army knife for rapid triage of suspicious **`.eml`** messages or entire mailbox folders.
> It surfaces the most important artefacts, applies a transparent risk-scoring model, and (optionally) calls ChatGPT for a sanity check — all without shipping the raw e-mail anywhere except **your** terminal.

---

## 📑 Table of contents

1. [Key features](#key-features)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [How it works](#how-it-works)
   * [VirusTotal & URLScan.io links](#virustotal--urlscanio-links)
   * [Threat-intel feeds](#threat-intel-feeds)
   * [Risk-scoring model](#risk-scoring-model)
   * [ChatGPT integration](#chatgpt-integration)
5. [Command-line reference](#command-line-reference)
6. [Road-map / TODO](#road-map--todo)
7. [License](#license)

---

## ✨ Key features

| Category                 | What it does                                                                                                                                                                                         |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Authentication**       | Parses **SPF / DKIM / DMARC** results and shows the raw fragments so you can tell *why* something passed or failed.                                                                                  |
| **Routing chain**        | Re-assembles every `Received:` hop (plus Gmail-style `X-Received`) and shows **from → by → IP → timestamp** in chronological order.                                                                  |
| **Reputation shortcuts** | Every domain, IP address *and each extracted URL* becomes a clickable hyperlink:<br>• **VirusTotal** artefact page<br>• **URLScan.io** search pivot (domain / IP).                                   |
| **Threat-intel checks**  | Compares sender, intermediate IPs and URL domains against **Spamhaus DROP**, **Feodo Tracker** and **OpenPhish** (local cache, auto-refreshed every 24 h).                                           |
| **Attachments**          | Lists filename, mime-type, size and SHA-256; flags potentially dangerous extensions (e.g. `.hta`, `.js`, macro-enabled Office).                                                                      |
| **Heuristic score**      | 25-rule weighted model (0–100) that considers auth failures, blacklists, TLD reputation, suspicious keywords, attachment types …                                                                     |
| **YARA autogen**         | `--yara` emits a ready-to-import rule-set derived from Subject, From, attachment names & URL domains — perfect for mailbox hunting.                                                                  |
| **AI assist (opt-in)**   | `--ai` sends headers & indicators to ChatGPT (uses *gpt-4o-mini* by default — configurable via `OPENAI_MODEL`) and embeds the reply — including ChatGPT’s own risk score and recommended next steps. |
| **Exports**              | Pretty terminal report *and/or* consolidated JSON / plaintext. PDF is one `rich --export pdf` away.                                                                                                  |

---

## 🛠 Installation

```bash
# Clone or download the repo
$ git clone https://github.com/Dagent-E/eh_analyzer.git
$ cd eh_analyzer

# Install dependencies (ideally inside a venv)
$ pip install -r requirements.txt
#  — or manually —
$ pip install rich pyfiglet beautifulsoup4 tldextract openai
```

> ✅ **Supports Python 3.9 and newer** (tested on 3.9–3.12, Linux, macOS, WSL).
> 🛟 **No outbound connections** are made *unless* you pass `--ai` (ChatGPT) **or** `--update-feeds` (threat-intel).
> 🔑 To use ChatGPT, set `OPENAI_API_KEY` (and optionally `OPENAI_MODEL`).

---

## 🚀 Quick start

```bash
# 1. Analyse a single message
$ python eh_analyzer.py invoices/strange_invoice.eml

# 2. Recursively scan a mailbox & export JSON
$ python eh_analyzer.py ~/Mail/Inbox --export json > inbox_iocs.json

# 3. Bake a YARA ruleset from a suspicious sample
$ python eh_analyzer.py weird.eml --yara suspicious.yar

# 4. Ask ChatGPT for a second opinion
$ OPENAI_API_KEY=sk-... python eh_analyzer.py spearphish.eml --ai
```

Rich supports colour in *most* modern terminals. Pass `--no-color` (from Rich v13+) if you need plain ASCII.

Example:

![Screenshot 2025-05-31 111938](https://github.com/user-attachments/assets/3946d69d-2942-47c3-b26e-a9dba8a243f2)
![EH_Analyzer_02](https://github.com/user-attachments/assets/fd2b1697-4a5b-4a11-8db2-579c71046019)

---

## 🧩 How it works

### VirusTotal & URLScan.io links

The script **does not** consume any external API credits during analysis.
Instead it constructs direct hyperlinks that many terminals render as *clickable*:

* **Domains** →
  `https://www.virustotal.com/gui/domain/<domain>`
  `https://urlscan.io/search/#domain:<domain>`
* **IP addresses** →
  `https://www.virustotal.com/gui/ip-address/<ip>`
  `https://urlscan.io/search/#ip:<ip>`

```python
# excerpt from eh_analyzer.py
vt_link = f"https://www.virustotal.com/gui/domain/{regdom}"
us_link = f"https://urlscan.io/search/#domain:{regdom}"
```

### Threat-intel feeds

* **Spamhaus DROP / EDROP** – IPv4 blocks tied to botnets & C2s
* **Feodo Tracker** – IcedID / Dridex / Emotet endpoints
* **OpenPhish** – Curated phishing domains

Feeds are cached under `./threat_feeds/` and refreshed automatically once per day (or immediately with `--update-feeds`).
All look-ups are *local*; nothing is submitted upstream.

### Risk-scoring model

Twenty-five heuristic rules contribute a weighted value that caps at 100:

```
✔️  +10  Sender IP in Spamhaus DROP
⚠️  +20  SPF fail (hard)
❌ +30  Exec-capable attachment (.hta)
⚠️  +15  URL with homoglyph/punycode
...
```

Run the tool with `--export plain` to see the full rule list and individual weights.
ChatGPT’s score (if enabled) is shown side-by-side for comparison in the final report panel.

---

### 🤖 ChatGPT integration

When you pass `--ai`, EH Analyzer gathers key indicators — authentication results, routing hops, attachment summaries, extracted URLs, and the local heuristic score — then sends them to OpenAI’s API. By default it uses model `gpt-4o-mini` (override via `OPENAI_MODEL`). ChatGPT returns a concise analysis that includes:

* **Risk assessment**: ChatGPT’s numerical risk score (0–100).
* **Summary** of suspicious artefacts (e.g., phishing keywords, anomalous headers).
* **Recommended next steps** (e.g., block sender, quarantine attachment).

The response is embedded in the final report, side-by-side with the local heuristic score. EH Analyzer never sends raw e-mail bodies — only metadata and computed indicators — to preserve privacy.

```python
# in eh_analyzer.py
if args.ai:
    payload = build_ai_payload(eml_data, indicators, local_score)
    chat_response = send_to_chatgpt(
        payload,
        model=os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
    )
    embed_chat_output(chat_response)
```

> **Note:** Ensure `OPENAI_API_KEY` is set before using `--ai`.
> **Tip:** Set `OPENAI_MODEL` to `gpt-4o-nano` for faster, cost-effective responses.

---

## 📄 Command-line reference

```text
usage: eh_analyzer.py [-h] target [--export {json,plain}] [--yara [FILE]]
                      [--ai] [--update-feeds]

positional arguments:
  target                 .eml file or directory

optional arguments:
  -h, --help             show this help message & exit
  --export json|plain    write consolidated report file
  --yara [FILE]          generate YARA rules (default: eha_rules.yar)
  --ai                   embed ChatGPT analysis (needs OPENAI_API_KEY)
  --update-feeds         refresh threat-intel feeds now
```

---

## 🛣️ Road-map / TODO

* [ ] Deduplicate domains in YARA generator
* [ ] Detect file-transfer services (WeTransfer, Dropbox, GoFile …)
* [ ] Magic-byte sniffing for attachment MIME types
* [ ] Optional Markdown / HTML output for GitHub Pages

Contributions are welcome — please open an Issue first so we can avoid duplicate work 🙌

---

## ⚖️ License

**MIT** — do whatever you like, just keep the notice intact.

> *EH Analyzer is an analysis helper, not a silver bullet. Always verify findings
> and use professional judgement before taking actions such as blocking,
> deletion or account suspension.*
