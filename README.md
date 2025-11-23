AI-Enhanced Reflected XSS Scanner

A context-aware Reflected Cross-Site Scripting (XSS) scanner built in Python. This tool combines static "golden vector" payloads with dynamic, AI-generated payloads (via Google Gemini) to test web applications for vulnerability.

Disclaimer: This tool is for educational purposes and authorized security testing only. Do not use this tool on targets without explicit written permission.

1. Project Assumptions

Given the open-ended nature of the assignment specifications, the following assumptions were made during development:

Parameter Knowledge: The user knows which parameters (e.g., q, id) are worth testing. The scanner does not crawl the site to discover parameters automatically; it fuzzes a pre-defined list.

Reflection is Key: The primary success metric is "Input Reflection." If the payload comes back in the response, it is flagged. The tool does not execute a headless browser to verify JavaScript execution (alert popups), as this would require significantly heavier dependencies (Selenium/Playwright).

State Codes: A 200 OK response is required for a successful reflection. Blocked requests (403/WAF) or Server Errors (500) are logged but not treated as successful exploitations.

2. Payload Generation Strategy (The PayloadGenerator Class)

The core logic resides in the PayloadGenerator class, which uses a hybrid approach:

A. Context-Awareness

Instead of spraying every payload everywhere, the scanner classifies attacks into specific Injection Contexts:

TEXT_NODE: For injections into raw HTML (e.g., <div>[HERE]</div>).

Strategy: Inject full <script> or <img> tags.

ATTRIBUTE_VALUE: For injections into tag attributes (e.g., <input value="[HERE]">).

Strategy: Attempt to break out of quotes (", ') and add event handlers (e.g., "><img src=x onerror=alert(1)>).

ATTRIBUTE_NAME: For injections into the tag structure itself (e.g., <div [HERE]>).

Strategy: Inject event handlers directly (e.g., autofocus onfocus=alert(1)).

SCRIPT_TAG: For injections inside existing JS blocks.

Strategy: Break JS string syntax (e.g., ';alert(1);//).

B. AI Integration (Gemini)

If a Google Gemini API Key is provided, the tool performs a "Live Generation" step before scanning:

It contacts the Gemini API.

It requests 5 unique, raw XSS vectors specifically tailored for each of the contexts above.

These AI-generated payloads are merged with the static list, increasing the chance of bypassing specific WAF rules or filters.

3. Reflection Detection Approach

The detection logic uses a robust substring matching technique:

Tokenization: Every payload includes a unique marker or specific structural fingerprint.

Analysis: After sending the request, the scanner reads the HTTP Response Body.

Verification: if payload in response.text:

This confirms that the server received the malicious input and returned it to the client without encoding or sanitizing it effectively enough to remove the payload string.

Note: This detects vulnerability potential. A real-world exploit would require the browser to parse and execute this reflection.

4. Setup and Usage

Prerequisites

Python 3.8+

Google Gemini API Key (Optional, for AI features)

Installation

Clone this repository.

Open Folder

cd XSS-Tool

Create Virtual Environment

python3 -m venv venv

Activate the virtual environment

source venv/bin/activate

Install dependencies:

pip install -r requirements.txt


Running the Scanner

Execute the script:

python3 Tool.py


Target URL: Enter the full URL (e.g., http://localhost:8000/search.php).

API Key: Enter your Gemini Key when prompted. (Press Enter to skip and use static payloads only).

Results:

Real-time findings are printed to the terminal.

A comprehensive xss_report.html is generated in the same folder.

5. Code Quality & Design Choices

Modularity: The scanning logic (XSSScanner) is decoupled from the weaponization logic (PayloadGenerator). This allows for easy swapping of payload sources (file-based vs AI-based) without breaking the scanner loop.

Type Hinting: Python Type Hints (List, Dict, Enum) are used throughout to ensure code clarity and help IDEs catch bugs during development.

Enums for Context: InjectionContext Enums are used instead of raw strings (like "html", "attr"). This prevents typo-based bugs and makes the "thought process" of the code explicit.

Graceful Degradation: The tool checks for the existence of the AI library (google.generativeai). If it's missing or the key is invalid, it automatically falls back to the static list without crashing.
