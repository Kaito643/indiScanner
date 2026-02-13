import os
import sys
from dotenv import load_dotenv
from loguru import logger

# Add src to path
sys.path.append(os.getcwd())

from src.sources.hybrid_analysis import HybridAnalysis

load_dotenv()

def test_fallback():
    # Configure logger to stdout for visibility
    logger.remove()
    logger.add(sys.stdout, level="INFO")

    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
    if not api_key:
        print("No API Key found")
        return

    ha = HybridAnalysis(api_key)
    print("[-] Starting search for 'Rhysida' (expecting 404 -> fallback)")
    
    # search yields items
    count = 0
    try:
        for item in ha.search("Rhysida"):
            print(f"[+] Found item: {item.get('hash')}")
            count += 1
            if count >= 3: break
    except Exception as e:
        print(f"[-] Exception during search: {e}")

    print(f"[-] Finished. Found {count} items.")

if __name__ == "__main__":
    test_fallback()
