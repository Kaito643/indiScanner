from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.edge.service import Service as EdgeService
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
import time
import os

def dump_vx_dom():
    print("[-] Initializing Selenium...")
    
    driver = None
    
    # Common paths to check
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Users\{}\AppData\Local\Google\Chrome\Application\chrome.exe".format(os.getenv('USERNAME'))
    ]
    
    edge_paths = [
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    ]

    # Try Chrome
    try:
        print("[-] Trying Chrome...")
        options = ChromeOptions()
        options.add_argument("--headless") 
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        # Check for binary
        binary = next((p for p in chrome_paths if os.path.exists(p)), None)
        if binary:
            print(f"[-] Found Chrome at {binary}")
            options.binary_location = binary
            
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
    except Exception as e:
        print(f"[-] Chrome failed: {e}")
        
    # Try Edge if Chrome failed
    if not driver:
        try:
            print("[-] Trying Edge...")
            options = EdgeOptions()
            options.add_argument("--headless")
            options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            
            binary = next((p for p in edge_paths if os.path.exists(p)), None)
            if binary:
                print(f"[-] Found Edge at {binary}")
                options.binary_location = binary

            driver = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
        except Exception as e:
            print(f"[-] Edge failed: {e}")
            return

    try:
        url = "https://vx-underground.org/?value=Black+Basta"
        print(f"[-] Navigating to {url}...")
        driver.get(url)
        
        print("[-] Waiting for page load (15s)...")
        time.sleep(15) 
        
        print("[-] Dumping HTML...")
        html = driver.page_source
        
        # Save HTML
        with open("vx_dump.html", "w", encoding="utf-8") as f:
            f.write(html)
            
        print("[+] HTML dumped to vx_dump.html")
        
    except Exception as e:
        print(f"[-] Error during navigation: {e}")
    finally:
        if driver:
            driver.quit()

if __name__ == "__main__":
    dump_vx_dom()
