import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def check_permissions():
    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
    if not api_key:
        print("No API Key found")
        return

    url = "https://www.hybrid-analysis.com/api/v2/key/current"
    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox"
    }
    
    try:
        print("[*] Checking permissions for key...")
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            # print("\n--- API Key Details ---")
            # print(f"Role: {data.get('role', 'Unknown')}")
            # print(f"API Limit: {data.get('api_limit', 'Unknown')}")
            # print(f"Granted Capabilities: {data.get('granted_capabilities', [])}")
            print(json.dumps(data, indent=2))
        else:
            print(f"[-] Error: {response.status_code} {response.text}")
            
    except Exception as e:
        print(f"[-] Exception: {e}")

if __name__ == "__main__":
    check_permissions()
