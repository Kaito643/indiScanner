import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def inspect_feed():
    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
    url = "https://www.hybrid-analysis.com/api/v2/feed/latest"
    headers = {"api-key": api_key, "User-Agent": "Falcon Sandbox"}
    
    print("[*] and fetching feed...")
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json().get('data', [])
            print(f"[+] Got {len(data)} items.")
            if data:
                # Print first 2 items to see structure
                print(json.dumps(data[:2], indent=2))
                
                # Check for specific tags
                ransomware_samples = [d for d in data if 'ransomware' in str(d).lower()]
                print(f"[+] Found {len(ransomware_samples)} potential ransomware items in feed.")
        else:
            print(f"[-] Error: {r.status_code} {r.text}")
    except Exception as e: print(e)

if __name__ == "__main__":
    inspect_feed()
