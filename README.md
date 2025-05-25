# eh-analyzer
Email Header Analyzer, a python3 based tool which helps analyze email headers by two different methods, either by making use of heuristic patterns and/or via ChatGPT integration, the latter allows for a more in-depth analysis with a detailed response and recommended action section. 

# EH Analyzer

**EH Analyzer** is a lightweight, single-file e-mail forensics tool designed to give you a quick, color-coded analysis of email headers, attachments, URLs, and optional YARA rule generation. It also includes an optional ChatGPT integration for deeper header analysis when you have an `OPENAI_API_KEY` set.

---

## Features

* **Header Extraction & Display**
  Parses and displays key headers (From, To, Subject, SPF/DKIM/DMARC results, etc.) in a color-coded table.

* **Authentication Results**
  Summarizes SPF, DKIM, and DMARC status with pass/fail/neutral, highlighting anomalies.

* **Attachment Analysis**
  Lists attachments with MIME type, size, and SHA-256 hash. Flags potentially dangerous extensions.

* **URL Extraction**
  Finds and lists all URLs in both plain-text and HTML parts. Scores based on TLD risk, anomalous domains, and embedded Base64 tokens.

* **Heuristic Scoring**
  Computes a risk score (0–100) based on authentication failures, attachment risk, URL risk, and more.

* **YARA Rule Auto-Generator**
  With `--yara`, produces a ready-to-use `.yar` file containing rules for subjects, senders, attachment names, and domains.

* **ChatGPT-Powered Analysis**
  With `--ai`, sends headers & metadata to the OpenAI API for expert-style forensic commentary, risk scoring, and action recommendations.

---

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com//eh-analyzer.git
   cd eh-analyzer
   ```

2. **Install dependencies**

   ```bash
   pip install rich pyfiglet beautifulsoup4 tldextract
   # Optional for AI support:
   pip install openai
   ```

---

## Usage

```bash
# Basic analysis of a single .eml file
python eh_analyzer.py path/to/message.eml

# Analyze all .eml files in a folder and export JSON report
python eh_analyzer.py inbox/ --export json

# Generate a YARA rule file (default name eha_rules.yar)
python eh_analyzer.py phish.eml --yara

# Enable ChatGPT header analysis (requires OPENAI_API_KEY env var)
export OPENAI_API_KEY="your_api_key_here"
python eh_analyzer.py message.eml --ai
```

### Command-Line Options

| Option            | Description                                                          |                                                                                 |
| ----------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `target`          | Path to a single `.eml` file or directory containing `.eml` files.   |                                                                                 |
| `--export \[json | plain]\`                                                              | Export a consolidated report as JSON or plain text (in `report_<timestamp>.*`). |
| `--yara [FILE]`   | Auto-generate YARA rules to `FILE` (default: `eha_rules.yar`).       |                                                                                 |
| `--ai`            | Enable ChatGPT forensic header analysis (requires `OPENAI_API_KEY`). |                                                                                 |

---

## Configuration

* **OpenAI API Key**
  To use the `--ai` option, set the `OPENAI_API_KEY` environment variable:

  ```bash
  export OPENAI_API_KEY="sk-..."
  ```

---

## Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or submit a pull request.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m "Add YourFeature"`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a pull request

---

## License

This project is released under the [MIT License](LICENSE).

---

## Author

Agent E — 2025
Lightweight email forensics by Agent E

