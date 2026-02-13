import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def debug_ha():
    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
    url_base = "https://www.hybrid-analysis.com/api/v2"
    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox"
    }

    print(f"[*] Testing HA with Key: {api_key[:4]}...")

    # Test 1: GET /search/hash (Sanity check for search namespace)
    print("\n--- Test 1: GET /search/hash ---")
    # Using a known hash (e.g. EICAR or from feed)
    test_hash = "7a0c5c404975762696032049652a8a8174542289c89280d85971a814bd980d2d"
    try:
        r = requests.get(f"{url_base}/search/hash", params={"hash": test_hash}, headers=headers)
        print(f"Status: {r.status_code}")
        print(f"Body: {r.text[:200]}")
    except Exception as e: print(e)

    # Test 2: POST /search/terms (Form Data)
    print("\n--- Test 2: POST /search/terms (Form Data) ---")
    try:
        r = requests.post(f"{url_base}/search/terms", data={"tag": "ransomware"}, headers=headers)
        print(f"Status: {r.status_code}")
        print(f"Body: {r.text[:200]}")
    except Exception as e: print(e)

    # Test 3: POST /search/terms (JSON Body)
    print("\n--- Test 3: POST /search/terms (JSON Body) ---")
    try:
        r = requests.post(f"{url_base}/search/terms", json={"tag": "ransomware"}, headers=headers)
        print(f"Status: {r.status_code}")
        print(f"Body: {r.text[:200]}")
    except Exception as e: print(e)
    
    # Test 4: POST /search/terms (Explicit Headers)
    print("\n--- Test 4: POST /search/terms (Explicit Headers) ---")
    h2 = headers.copy()
    h2["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        r = requests.post(f"{url_base}/search/terms", data="tag=ransomware", headers=h2)
        print(f"Status: {r.status_code}")
        print(f"Body: {r.text[:200]}")
    except Exception as e: print(e)

if __name__ == "__main__":
    debug_ha()
