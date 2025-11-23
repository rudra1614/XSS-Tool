AI-Enhanced Reflected XSS Scanner

A context-aware Reflected Cross-Site Scripting (XSS) scanner written in Python. This tool combines a curated set of static "golden" payloads with optional dynamic, AI-generated payloads (via Google Gemini) to improve coverage when testing input reflection vulnerabilities.

Disclaimer

This tool is intended for educational purposes and for authorized security testing only. Do not use this tool against systems for which you do not have explicit written permission.

Table of Contents

- Project assumptions
- Payload generation strategy
- Reflection detection
- Setup & usage
- Running the scanner
- Results
- Code quality & design choices
- Contributing

1. Project assumptions

- Parameter knowledge: The user provides a list of parameters to test (for example: q, id). The scanner does not crawl sites to discover parameters automatically.
- Reflection is the primary indicator: If an injected payload is returned in the HTTP response body, it is flagged as a potential reflected XSS. The scanner does not execute a full browser (headless) to validate JavaScript execution.
- HTTP status: A 200 OK response is required to consider a reflection successful. 403/500 responses are recorded but not treated as successful exploitations.

2. Payload generation strategy (PayloadGenerator)

The PayloadGenerator uses a hybrid approach:

A. Context awareness

The scanner classifies injection points into specific InjectionContexts and tailors payloads accordingly:

- TEXT_NODE: Injection into raw HTML (example: <div>[HERE]</div>). Strategy: inject full <script> or <img> tags.
- ATTRIBUTE_VALUE: Injection inside an attribute value (example: <input value="[HERE]">). Strategy: attempt to break out of quotes and append event handlers (e.g., "><img src=x onerror=alert(1)>).
- ATTRIBUTE_NAME: Injection into the tag structure itself (example: <div [HERE]>). Strategy: inject event handlers or attributes directly (e.g., autofocus onfocus=alert(1)).
- SCRIPT_TAG: Injection inside existing JavaScript. Strategy: break out of strings or comments (e.g., '\';alert(1);//').

B. AI integration (Gemini)

If a Google Gemini API key is provided, the tool can request additional, live-generated payloads tailored to each context. The scanner requests a small number (default: 5) of unique vectors per context and merges them with the static payload list. This is optional — the scanner will fall back to the static payloads if the AI key or library is not available.

3. Reflection detection approach

- Tokenization: Each payload includes a unique marker or fingerprint to make detection reliable.
- Analysis: After sending requests, the scanner inspects the HTTP response body.
- Verification: If the payload marker appears in response.text (and the response status is 200), the reflection is recorded as a potential reflected XSS.

Note: Detection indicates potential vulnerability. A successful exploit requires the browser to parse and execute the reflected input.

4. Setup & usage

Prerequisites

- Python 3.8 or newer
- (Optional) Google Gemini API key to enable AI payload generation

Installation

```bash
# clone the repository
git clone https://github.com/rudra1614/XSS-Tool.git
cd XSS-Tool

# create and activate a venv
python3 -m venv venv
source venv/bin/activate

# install dependencies
pip install -r requirements.txt
```

5. Running the scanner

```bash
python3 Tool.py
```

When prompted:

- Target URL: Provide the full URL (for example: http://localhost:8000/search.php)
- API Key: Enter your Google Gemini API key to enable live AI payload generation, or press Enter to skip and use only the static payloads.

Outputs

- Real-time findings are printed to the terminal.
- A report file (xss_report.html) is generated in the project folder with details of findings.

6. Code quality & design choices

- Modularity: Scanning logic (XSSScanner) is separated from payload generation (PayloadGenerator), allowing payload sources to be swapped without changing scanner logic.
- Type hints: Python type hints (List, Dict, Enum) are used for clarity and better tooling support.
- Enums: An InjectionContext enum is used instead of raw strings to reduce typos and clarify intent.
- Graceful degradation: If the google.generativeai library or API key is missing/invalid, the tool automatically falls back to static payloads without crashing.

7. Contributing

Contributions, bug reports, and pull requests are welcome. If you add new payloads or features, please include tests or example usage where appropriate.

