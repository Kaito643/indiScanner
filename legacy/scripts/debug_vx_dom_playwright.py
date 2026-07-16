from playwright.sync_api import sync_playwright
import time

def dump_vx_dom():
    with sync_playwright() as p:
        print("[-] Launching Browser (Headful)...")
        # Headless=False so user can see it
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = context.new_page()
        
        url = "https://vx-underground.org/?value=Black+Basta"
        print(f"[-] Navigating to {url}...")
        
        try:
            # Go to page
            page.goto(url, timeout=30000, wait_until="domcontentloaded")
            
            print("[-] Waiting 15s for results to render...")
            time.sleep(15)
            
        except Exception as e:
            print(f"[-] Navigation/Wait warning: {e}")
            
        finally:
            print("[-] Dumping HTML...")
            try:
                html = page.content()
                with open("vx_dump.html", "w", encoding="utf-8") as f:
                    f.write(html)
                print("[+] HTML dumped to vx_dump.html")
            except Exception as e:
                print(f"[-] Failed to dump HTML: {e}")
            
            browser.close()

if __name__ == "__main__":
    dump_vx_dom()
