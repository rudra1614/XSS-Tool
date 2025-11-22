import requests
import time
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

@dataclass
class ScanResult:
    url: str
    parameter: str
    method: str
    context: InjectionContext
    payload: str
    reflected: bool
    response_code: int

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
                    # Determine where to store them
                    if context in self.custom_payloads:
                        self.custom_payloads[context].extend(ai_payloads)
                        
            except Exception as e:
                print(f"    [!] AI Generation failed for {context.value}: {e}")
                time.sleep(1) # Short backoff

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

        # Merge dynamic lists
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
        # Basic check for reflection
        if payload in response.text:
            return True
        return False

    def generate_report(self):
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
