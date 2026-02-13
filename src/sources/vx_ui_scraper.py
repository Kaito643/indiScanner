import os
import time
import requests
from typing import List, Dict, Generator
from playwright.sync_api import sync_playwright
from loguru import logger
from ..source_base import SourceBase

# Ensure downloads directory exists
DOWNLOADS_DIR = "downloads/Imported"
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

class VXInteractiveScraper(SourceBase):
    """
    Interactive Scraper for VX Underground using Playwright.
    Launches a visible browser, asks user to solve Captcha, then scrapes PDF/Samples.
    """
    def __init__(self, api_key: str = ""):
        super().__init__(api_key)
        self.name = "VXScraper (Interactive)"
        self.base_url = "https://vx-underground.org/?value="

    def search(self, group_name: str, limit: int = 100) -> Generator[Dict, None, None]:
        logger.info(f"Launching Interactive Search for '{group_name}'...")
        logger.warning("🔴 A Browser Window will open. Please solve any Cloudflare Captchas!")
        
        with sync_playwright() as p:
            # Launch Headful Browser with Advanced Evasion
            # Attempt to use Edge or Chrome to bypass Cloudflare
            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--start-maximized",
                "--no-sandbox",
                "--disable-infobars"
            ]
            exclude_args = ["--enable-automation"]
            
            try:
                logger.info("Launching Microsoft Edge (headless=False)...")
                browser = p.chromium.launch(
                    headless=False, 
                    channel="msedge", 
                    args=launch_args,
                    ignore_default_args=exclude_args
                )
            except Exception as e:
                logger.warning(f"Edge not found, trying Chrome...")
                try:
                    browser = p.chromium.launch(
                        headless=False, 
                        channel="chrome", 
                        args=launch_args,
                        ignore_default_args=exclude_args
                    )
                except Exception as e2:
                    logger.warning(f"Chrome not found, using bundled Chromium...")
                    browser = p.chromium.launch(
                        headless=False, 
                        args=launch_args,
                        ignore_default_args=exclude_args
                    )

            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                viewport=None, # Let it be responsive
                no_viewport=True
            )
            
            # Apply Manual Stealth (Robust & Self-Contained)
            context.add_init_script("""
                // Pass the Webdriver Test.
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });

                // Pass the Chrome Test.
                // We mock the chrome object to look like a real chrome instance.
                window.chrome = {
                    runtime: {},
                    // Add other properties if needed
                };

                // Pass the Permissions Test.
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                    Promise.resolve({ state: 'denied', onchange: null }) :
                    originalQuery(parameters)
                );

                // Pass the Plugins Length Test.
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });

                // Pass the Languages Test.
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en'],
                });
            """)
            
            page = context.new_page()
            
            # Construct Search URL
            search_url = f"{self.base_url}{group_name}"
            logger.info(f"Navigating to: {search_url}")
            
            try:
                page.goto(search_url, timeout=60000, wait_until="domcontentloaded")
            except Exception as e:
                logger.error(f"Navigation error (might be okay if page loaded): {e}")

            # Wait for User
            print("\n" + "="*50)
            print("🛑 ACTION REQUIRED 🛑")
            print("1. Check the opened browser window.")
            print("2. Solve any Cloudflare Captchas.")
            print("3. Wait until you see the list of files/results.")
            print("4. Press ENTER in this terminal to start scraping.")
            print("="*50 + "\n")
            input("Press Enter to continue...")
            
            # Scrape Links
            logger.info("Scraping links from current page...")
            try:
                # Get all 'a' tags
                links = page.query_selector_all("a")
                found_count = 0
                
                for link in links:
                    if found_count >= limit: break
                    
                    href = link.get_attribute("href")
                    if not href: continue
                    
                    # fix relative urls
                    if href.startswith("/"):
                        href = "https://vx-underground.org" + href
                        
                    text = link.inner_text()
                    
                    # Logic to identify result items (PDFs or Zips typically)
                    # VX results usually have names like "2022-11-05 - Black Basta..."
                    # We look for file extensions or specific classes if known? 
                    # Since we don't know classes, let's look for likely file extensions in href or text
                    if any(ext in href.lower() for ext in ['.pdf', '.zip', '.7z', '.rar', '.exe', '.bin']) or \
                       any(ext in text.lower() for ext in ['.pdf', '.zip', '.7z']):
                        
                        logger.info(f"Found IOC Target: {text[:50]}...")
                        
                        local_path = self._download_file(page, href, text)
                        if local_path:
                            yield {
                                "hash": f"LOCAL:{local_path}", # Special marker
                                "filename": os.path.basename(local_path),
                                "first_seen": "2024-01-01",
                                "source": "VXScraper",
                                "local_path": local_path
                            }
                            found_count += 1
                            
            except Exception as e:
                logger.error(f"Scraping failed: {e}")
                
            logger.success(f"Session finished. Found {found_count} files.")
            browser.close()

    def _download_file(self, page, url: str, name: str) -> str:
        """Downloads a file using the active Playwright page context."""
        try:
            # Generate safe filename
            safe_name = "".join(c for c in name if c.isalnum() or c in (' ', '.', '-', '_')).strip()
            if not safe_name.lower().endswith(('.pdf', '.zip', '.7z')):
                 # Try to guess from URL
                 if url.lower().endswith('.pdf'): safe_name += ".pdf"
                 elif url.lower().endswith('.zip'): safe_name += ".zip"
                 else: safe_name += ".bin"
            
            save_path = os.path.join(DOWNLOADS_DIR, safe_name)
            if os.path.exists(save_path):
                logger.info(f"File already exists: {save_path}")
                return save_path

            logger.info(f"Downloading {url}...")
            
            # Let's try grabbing cookies and using requests (faster)
            cookies = page.context.cookies()
            session = requests.Session()
            for cookie in cookies:
                session.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])
            
            # Mimic User-Agent
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "Referer": page.url
            }
            
            with session.get(url, headers=headers, stream=True, timeout=60) as r:
                r.raise_for_status()
                with open(save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                        
            logger.success(f"Saved to {save_path}")
            return save_path
            
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return None

    def download(self, file_hash: str) -> bytes:
        # Not used in this flow as search() handles downloading
        return None
