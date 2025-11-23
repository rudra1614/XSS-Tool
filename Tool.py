import requests
import time
import datetime
import html
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional

# Attempt to import Gemini SDK
try:
    import google.generativeai as genai
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# --- Configuration & Enums ---

class InjectionContext(Enum):
    TEXT_NODE = "text_node"           # <div>PAYLOAD</div>
    ATTRIBUTE_VALUE = "attr_value"    # <input value="PAYLOAD">
    ATTRIBUTE_NAME = "attr_name"      # <div PAYLOAD="x"> or <div PAYLOAD>
    SCRIPT_TAG = "script_tag"         # <script>var x = 'PAYLOAD';</script>

    def description(self):
        """Returns the 'Thought Process' behind this injection context."""
        if self == InjectionContext.TEXT_NODE:
            return "Standard HTML Injection: Attempts to insert new HTML tags directly into the page content."
        elif self == InjectionContext.ATTRIBUTE_VALUE:
            return "Attribute Breakout: Attempts to close an existing attribute quote to inject a new event handler."
        elif self == InjectionContext.ATTRIBUTE_NAME:
            return "Attribute Injection: Attempts to inject a new attribute (e.g., onmouseover) directly into an existing tag."
        elif self == InjectionContext.SCRIPT_TAG:
            return "JS Context Escape: Attempts to break out of a JavaScript string or statement to execute arbitrary code."
        return "General Injection"

@dataclass
class ScanResult:
    url: str
    parameter: str
    method: str
    context: InjectionContext
    payload: str
    reflected: bool
    response_code: int
    timestamp: datetime.datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.datetime.now()

# --- Payload Generator ---

class PayloadGenerator:
    """
    Generates payloads adapted for specific HTML contexts using static lists and AI.
    """
    
    def __init__(self, api_key: str = None):
        self.probe_token = "XSSPROBE" + str(12345)
        self.api_key = api_key
        
        # Initialize container for dynamic payloads (AI generated)
        self.custom_payloads = {ctx: [] for ctx in InjectionContext}
        
        # If API key is present, generate dynamic payloads
        if self.api_key and AI_AVAILABLE:
            self._generate_ai_payloads()
        elif self.api_key and not AI_AVAILABLE:
            print("[!] Warning: API Key provided but 'google-generativeai' library not found.")

    def _generate_ai_payloads(self):
        """Uses Gemini API to generate context-specific payloads."""
        print("[*] Contacting Gemini API to generate dynamic payloads...")
        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')

        for context in InjectionContext:
            print(f"    > Generating vectors for context: {context.value}...")
            try:
                # Prompt Engineering for security context
                prompt = f"""
                You are a security researcher. Generate 5 concise, raw XSS payloads specifically for 
                injection into an HTML {context.value}. 
                The payload MUST contain the string '{self.probe_token}' to verify reflection.
                Do not include markdown, explanations, or backticks. Just the raw payloads, one per line.
                """
                
                response = model.generate_content(prompt)
                
                if response.text:
                    ai_payloads = [line.strip() for line in response.text.split('\n') if line.strip()]
                   
                    if context in self.custom_payloads:
                        self.custom_payloads[context].extend(ai_payloads)
                        
            except Exception as e:
                print(f"    [!] AI Generation failed for {context.value}: {e}")
                time.sleep(1) 

    def get_payloads(self) -> Dict[InjectionContext, List[str]]:
        """Returns merged dictionary of default and AI payloads."""
        payloads = {
            InjectionContext.TEXT_NODE: [
                f"<script>console.log('{self.probe_token}')</script>",
                f"<img src=x onerror=console.log('{self.probe_token}')>",
                f"<!-- {self.probe_token} -->" 
            ],
            InjectionContext.ATTRIBUTE_VALUE: [
                f'"{self.probe_token}',                 
                f'"><script>console.log({self.probe_token})</script>', 
                f'" onmouseover="console.log(\'{self.probe_token}\')', 
            ],
            InjectionContext.ATTRIBUTE_NAME: [
                self.probe_token,                      
                f'autofocus onfocus=console.log({self.probe_token})', 
                f'>{self.probe_token}<'                
            ],
            InjectionContext.SCRIPT_TAG: [
                f"';console.log('{self.probe_token}');//",
                f'";console.log("{self.probe_token}");//'
            ]
        }

      
        for ctx, custom_list in self.custom_payloads.items():
            if ctx in payloads:
                payloads[ctx].extend(custom_list)

        return payloads

# --- The Scanner ---

class XSSScanner:
    def __init__(self, target_url: str, method: str = "GET", headers: dict = None, api_key: str = None):
        self.target_url = target_url
        self.method = method.upper()
        self.headers = headers or {"User-Agent": "Python-XSS-Scanner/1.0"}
        self.generator = PayloadGenerator(api_key)
        self.results: List[ScanResult] = []

    def scan(self, params: Dict[str, str]):
        print(f"[*] Starting scan on {self.target_url} with method {self.method}")
        
        all_payloads_map = self.generator.get_payloads()

        for param_name in params.keys():
            print(f"[*] Testing parameter: {param_name}")
            
            for context, payload_list in all_payloads_map.items():
                # Limit payload count if list is huge to prevent hanging
                limit = 20 
                active_payloads = payload_list[:limit]
                
                print(f"    > Context: {context.name} ({len(active_payloads)} active payloads)")
                
                for payload in active_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload

                    try:
                        response = self._send_request(test_params)
                        reflected = self._analyze_response(response, payload)
                        
                        result = ScanResult(
                            url=self.target_url,
                            parameter=param_name,
                            method=self.method,
                            context=context,
                            payload=payload,
                            reflected=reflected,
                            response_code=response.status_code
                        )
                        self.results.append(result)

                        if reflected:
                            print(f"    [!] REFLECTION FOUND in {context.value}: {payload[:50]}...")

                    except requests.RequestException as e:
                        print(f"    [x] Request failed: {e}")

    def _send_request(self, data: Dict[str, str]):
        if self.method == "GET":
            return requests.get(self.target_url, params=data, headers=self.headers, timeout=5)
        elif self.method == "POST":
            return requests.post(self.target_url, data=data, headers=self.headers, timeout=5)
        else:
            raise ValueError("Unsupported method")

    def _analyze_response(self, response, payload: str) -> bool:
        #  check for reflection
        if payload in response.text:
            return True
        return False

    def generate_report(self):
        self._print_terminal_report()
        self._generate_html_report()

    def _print_terminal_report(self):
        print("\n" + "="*60)
        print(f"SCAN REPORT FOR {self.target_url}")
        print("="*60)
        
        found_vulns = [r for r in self.results if r.reflected]
        
        if not found_vulns:
            print("No reflections detected.")
            return

        print(f"{'PARAMETER':<15} | {'CONTEXT':<15} | {'PAYLOAD (Truncated)':<40}")
        print("-" * 75)
        
        for r in found_vulns:
            disp_payload = (r.payload[:37] + '...') if len(r.payload) > 37 else r.payload
            print(f"{r.parameter:<15} | {r.context.value:<15} | {disp_payload:<40}")
        
        print("\nTotal reflections found:", len(found_vulns))
        print("="*60)

    def _generate_html_report(self):
        filename = "xss_report.html"
        print(f"\n[*] Generating HTML report: {filename}")
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>XSS Scan Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; color: #333; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                .summary {{ background: #fff; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #3498db; color: white; }}
                tr:hover {{ background-color: #f1f1f1; }}
                .vuln-true {{ background-color: #e74c3c; color: white; font-weight: bold; padding: 3px 8px; border-radius: 3px; }}
                .vuln-false {{ background-color: #27ae60; color: white; padding: 3px 8px; border-radius: 3px; }}
                .context-desc {{ font-size: 0.85em; color: #666; font-style: italic; display: block; margin-top: 4px; }}
                code {{ background-color: #eee; padding: 2px 5px; border-radius: 3px; font-family: 'Consolas', monospace; display: block; white-space: pre-wrap; word-break: break-all; }}
            </style>
        </head>
        <body>
            <h1>Reflected XSS Scan Report</h1>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Target:</strong> {self.target_url}</p>
                <p><strong>Method:</strong> {self.method}</p>
                <p><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p><strong>Total Requests:</strong> {len(self.results)}</p>
                <p><strong>Vulnerabilities Found:</strong> {len([r for r in self.results if r.reflected])}</p>
            </div>

            <h2>Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Result</th>
                        <th>Parameter</th>
                        <th>Context & Thought Process</th>
                        <th>Payload Injected</th>
                        <th>Status Code</th>
                    </tr>
                </thead>
                <tbody>
        """

        for r in self.results:
            status_class = "vuln-true" if r.reflected else "vuln-false"
            status_text = "REFLECTED" if r.reflected else "Blocked/Safe"
            
            
            html_content += f"""
                    <tr>
                        <td><span class="{status_class}">{status_text}</span></td>
                        <td><strong>{html.escape(r.parameter)}</strong></td>
                        <td>
                            <strong>{r.context.value}</strong>
                            <span class="context-desc">{r.context.description()}</span>
                        </td>
                        <td><code>{html.escape(r.payload)}</code></td>
                        <td>{r.response_code}</td>
                    </tr>
            """

        html_content += """
                </tbody>
            </table>
            
            <p style="text-align: center; margin-top: 30px; color: #777;">Generated by Python XSS Scanner</p>
        </body>
        </html>
        """
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"[*] HTML Report successfully written to {filename}")
        except Exception as e:
            print(f"[!] Failed to write HTML report: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    print("--- Reflected XSS Scanner (AI Enabled) ---")
    
    # Input target
    default_url = "http://localhost:8000/vulnerable_page.php"
    user_url = input(f"Enter target URL (default: {default_url}): ").strip()
    TARGET = 'http://' + user_url if user_url and not user_url.startswith(('http://', 'https://')) else (user_url or default_url)
    
    # Input API Key (Optional)
    api_key = input("Enter Gemini API Key (Press Enter to skip): ").strip()
    
    # Parameters to fuzz
    PARAMETERS = {
        "q": "search_term",
        "user_input": "default",
        "id": "1"
    }

    try:
        scanner = XSSScanner(TARGET, method="GET", api_key=api_key)
        scanner.scan(PARAMETERS)
        scanner.generate_report()
        
    except requests.exceptions.ConnectionError:
        print(f"\n[!] Error: Could not connect to {TARGET}")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
