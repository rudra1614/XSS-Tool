<div align="center">

# 🛡️ AI-Enhanced Reflected XSS Scanner

**A context-aware Reflected Cross-Site Scripting (XSS) scanner powered by Python and Google Gemini AI.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-AI%20Powered-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev/)
[![License](https://img.shields.io/badge/License-Educational%20Use-green?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Authorized%20Testing%20Only-red?style=for-the-badge&logo=shield&logoColor=white)]()

---

*Combines a curated library of static "golden" payloads with optional AI-generated vectors to maximize coverage when testing input reflection vulnerabilities.*

</div>

---

> [!WARNING]
> **Disclaimer:** This tool is intended for **educational purposes** and **authorized security testing only**.
> Do not use this tool against any system for which you do not have **explicit written permission**.

---

## 📋 Table of Contents

| # | Section |
|---|---------|
| 1 | [✅ Project Assumptions](#1-project-assumptions) |
| 2 | [⚙️ Payload Generation Strategy](#2-payload-generation-strategy) |
| 3 | [🔍 Reflection Detection](#3-reflection-detection-approach) |
| 4 | [🚀 Setup & Usage](#4-setup--usage) |
| 5 | [▶️ Running the Scanner](#5-running-the-scanner) |
| 6 | [🏗️ Code Quality & Design Choices](#6-code-quality--design-choices) |
| 7 | [🤝 Contributing](#7-contributing) |

---

## ✨ Features at a Glance

- 🎯 **Context-aware payloads** — tailors injection vectors based on where user input is reflected
- 🤖 **AI integration** — optionally calls Google Gemini to generate novel, context-specific payloads
- 📄 **HTML report** — automatically produces an `xss_report.html` summary of all findings
- 🔄 **Graceful degradation** — falls back to static payloads when no API key is available
- 🐍 **Clean Python design** — type hints, enums, and modular architecture throughout

---

## 1. Project Assumptions

| Assumption | Detail |
|------------|--------|
| **Parameter knowledge** | The user provides a list of parameters to test (e.g. `q`, `id`). The scanner does **not** crawl sites to discover parameters automatically. |
| **Reflection as indicator** | If an injected payload appears in the HTTP response body, it is flagged as a potential reflected XSS. A full headless browser is **not** used to validate JS execution. |
| **HTTP status** | Only `200 OK` responses are treated as successful. `403`/`500` responses are recorded but not counted as exploitations. |

---

## 2. Payload Generation Strategy

The `PayloadGenerator` uses a **hybrid approach** combining static payloads with optional AI generation.

### 2a. Context Awareness

The scanner classifies each injection point into one of four `InjectionContext` types:

| Context | Example | Strategy |
|---------|---------|----------|
| `TEXT_NODE` | `<div>[HERE]</div>` | Inject full `<script>` or `<img>` tags |
| `ATTRIBUTE_VALUE` | `<input value="[HERE]">` | Break out of quotes and append event handlers — e.g. `"><img src=x onerror=alert(1)>` |
| `ATTRIBUTE_NAME` | `<div [HERE]>` | Inject event handlers or attributes directly — e.g. `autofocus onfocus=alert(1)` |
| `SCRIPT_TAG` | Inside existing JS | Break out of strings or comments — e.g. `\';alert(1);//` |

### 2b. AI Integration (Google Gemini)

If a **Google Gemini API key** is supplied, the tool requests a small batch (default: **5**) of unique, live-generated vectors per context and merges them with the static payload list.

> **Note:** AI integration is entirely optional — the scanner operates fully on static payloads when no key is provided.

---

## 3. Reflection Detection Approach

```
┌──────────────┐    inject     ┌─────────────┐    inspect    ┌──────────────┐
│  Payload +   │ ──────────►  │   Target    │ ──────────►  │   Response   │
│  Fingerprint │              │   Server    │              │    Body      │
└──────────────┘              └─────────────┘              └──────┬───────┘
                                                                   │
                                              marker in body? ─────┤
                                              status == 200?       │
                                                                   ▼
                                                          ✅ Potential XSS
```

| Step | Description |
|------|-------------|
| **Tokenization** | Each payload is assigned a unique fingerprint to make detection reliable |
| **Analysis** | The scanner inspects the full HTTP response body for each fingerprint |
| **Verification** | If the marker appears **and** the status is `200`, the reflection is recorded |

> **Important:** Detection indicates *potential* vulnerability. A successful exploit requires the browser to parse and execute the reflected input.

---

## 4. Setup & Usage

### Prerequisites

- 🐍 **Python 3.8** or newer
- 🔑 *(Optional)* Google Gemini API key — enables AI payload generation

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/rudra1614/XSS-Tool.git
cd XSS-Tool

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows (Command Prompt): venv\Scripts\activate.bat

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 5. Running the Scanner

```bash
python3 Tool.py
```

When prompted, provide the following inputs:

| Prompt | Description |
|--------|-------------|
| **Target URL** | Full URL to scan — e.g. `http://localhost:8000/search.php` |
| **API Key** | Google Gemini API key for AI payloads, or press **Enter** to use static payloads only |

### Outputs

| Output | Description |
|--------|-------------|
| **Terminal** | Real-time findings are printed as they are discovered |
| **`xss_report.html`** | A full HTML report is generated in the project folder |

---

## 6. Code Quality & Design Choices

| Principle | Implementation |
|-----------|----------------|
| **Modularity** | `XSSScanner` (scanning logic) is decoupled from `PayloadGenerator` (payload sourcing) — swap payload sources without touching scanner logic |
| **Type hints** | Python type hints (`List`, `Dict`, `Enum`) are used throughout for clarity and better IDE/tooling support |
| **Enums** | `InjectionContext` enum replaces raw strings to eliminate typos and clarify intent |
| **Graceful degradation** | Missing `google.generativeai` library or invalid API key causes an automatic, silent fallback to static payloads — no crash |

---

## 7. Contributing

Contributions, bug reports, and pull requests are **welcome and encouraged**! 🎉

- 🐛 **Bug reports** — open an issue with a reproduction case
- ✨ **New payloads** — submit a PR with a description of the context the payload targets
- 🔧 **Feature improvements** — include tests or example usage where appropriate

---

<div align="center">

*Built for learning and authorized testing · Use responsibly*

</div>

