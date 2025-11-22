import requests
import urllib.parse
import re
import os  # Added to handle file operations
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional

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
    Generates payloads adapted for specific HTML contexts.
    """
    
    def __init__(self):
        # A unique token to verify reflection without triggering alerts during initial probing
        self.probe_token = "XSSPROBE" + str(12345)
        self.payload_file = "xss-payload-list.txt"
        self.custom_payloads = self._load_custom_payloads()

    def _load_custom_payloads(self) -> Dict[InjectionContext, List[str]]:
        """
        Loads payloads from the external file if it exists and categorizes them.
        """
        categorized = {
            InjectionContext.TEXT_NODE: [],
            InjectionContext.ATTRIBUTE_VALUE: [],
            InjectionContext.ATTRIBUTE_NAME: [],
            InjectionContext.SCRIPT_TAG: []
        }

        if not os.path.exists(self.payload_file):
            print(f"[!] Info: Payload file '{self.payload_file}' not found. Using defaults only.")
            return categorized

        print(f"[*] Loading payloads from {self.payload_file}...")
        try:
            with open(self.payload_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue

                    # --- Heuristics for Categorization ---
                    # 1. Tags (Text Node)
                    if line.startswith('<'):
                        categorized[InjectionContext.TEXT_NODE].append(line)
                    
                    # 2. Quote breakouts (Attribute Values)
                    elif line.startswith('"') or line.startswith("'"):
                        categorized[InjectionContext.ATTRIBUTE_VALUE].append(line)
                    
                    # 3. Attribute Names / Weird Protocol handlers / Polyglots
                    # If it doesn't fit strictly elsewhere, we often try it in multiple spots
                    else:
                        # Add to Attribute Value (often works for inputs)
                        categorized[InjectionContext.ATTRIBUTE_VALUE].append(line)
                        # Add to Text Node (just in case it's raw text reflection)
                        categorized[InjectionContext.TEXT_NODE].append(line)
                        
                        # If it looks like an event handler or attribute injection
                        if '=' in line or 'on' in line.lower():
                            categorized[InjectionContext.ATTRIBUTE_NAME].append(line)

            count = sum(len(v) for v in categorized.values())
            print(f"[*] Successfully loaded {count} variants from file.")
            
        except Exception as e:
            print(f"[!] Error reading payload file: {e}")

        return categorized

    def get_payloads(self, context: InjectionContext = None) -> Dict[InjectionContext, List[str]]:
        """
        Returns a dictionary of payloads keyed by context. 
        If a specific context is requested, only that list is returned.
        """
        # Default built-in payloads (High confidence/Low noise)
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
                f"' onmouseover='console.log(\'{self.probe_token}\')", 
            ],
            InjectionContext.ATTRIBUTE_NAME: [
                self.probe_token,                      
                f'style=expression(console.log({self.probe_token}))', 
                f'autofocus onfocus=console.log({self.probe_token})', 
                f'>{self.probe_token}<'                
            ],
            InjectionContext.SCRIPT_TAG: [
                f"';console.log('{self.probe_token}');//",
                f'";console.log("{self.probe_token}");//'
            ]
        }

        # Merge Custom Payloads from File
        for ctx, custom_list in self.custom_payloads.items():
            if ctx in payloads:
                # Extend the default list with custom ones
                payloads[ctx].extend(custom_list)

        if context:
            return {context: payloads.get(context, [])}
        return payloads

# --- The Scanner ---

class XSSScanner:
    def __init__(self, target_url: str, method: str = "GET", headers: dict = None):
        self.target_url = target_url
        self.method = method.upper()
        self.headers = headers or {"User-Agent": "Python-XSS-Scanner/1.0"}
        self.generator = PayloadGenerator()
        self.results: List[ScanResult] = []

    def scan(self, params: Dict[str, str]):
        """
        Iterates through parameters and injection contexts to test for reflections.
        params: Initial values for parameters (e.g., {'q': 'search', 'id': '1'})
        """
        print(f"[*] Starting scan on {self.target_url} with method {self.method}")
        
        all_payloads_map = self.generator.get_payloads()

        for param_name in params.keys():
            print(f"[*] Testing parameter: {param_name}")
            
            # Iterate through every context type we defined
            for context, payload_list in all_payloads_map.items():
                # Optimization: Don't spam thousands of requests if the user didn't ask for heavy scan.
                # For this assignment, we run them all, but be aware it might take time.
                print(f"    > Context: {context.name} ({len(payload_list)} payloads)")
                
                for payload in payload_list:
                    
                    # Prepare data
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
        """
        Simple reflection detection. 
        In a real scanner, you would parse the HTML to see WHERE it reflected.
        For this assignment, substring match is sufficient.
        """
        # Basic check: is the payload string literally in the response?
        if payload in response.text:
            return True
            
        # Advanced check (Optional): Sometimes browsers/servers URL-encode symbols.
        # If our payload was <script>, the server might reflect %3Cscript%3E.
        # This simple scanner might miss those if we don't decode the response or encode the check.
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
            # Truncate payload for display
            disp_payload = (r.payload[:37] + '...') if len(r.payload) > 37 else r.payload
            print(f"{r.parameter:<15} | {r.context.value:<15} | {disp_payload:<40}")
        
        print("\nTotal reflections found:", len(found_vulns))
        print("="*60)

# --- Main Execution ---

if __name__ == "__main__":
    # --- CONFIGURATION ---
    print("--- Reflected XSS Scanner ---")
    
    # Get URL from user input
    default_url = "http://localhost:8000/vulnerable_page.php"
    user_url = input(f"Enter target URL (default: {default_url}): ").strip()
    
    # Ensure scheme exists
    if user_url and not user_url.startswith(('http://', 'https://')):
        user_url = 'http://' + user_url
        
    TARGET = user_url if user_url else default_url
    
    # Parameters to fuzz
    PARAMETERS = {
        "q": "search_term",
        "user_input": "default",
        "id": "1"
    }

    # --- RUN SCANNER ---
    print(f"[*] Target set to: {TARGET}")
    
    try:
        # Example 1: Scanning using GET
        scanner = XSSScanner(TARGET, method="GET")
        
        # Run the actual scan against the user-provided URL
        scanner.scan(PARAMETERS)
        scanner.generate_report()
        
    except requests.exceptions.ConnectionError:
        print(f"\n[!] Error: Could not connect to {TARGET}")
        print("    Please ensure the target server is running and accessible.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
