import os
import sys
import argparse
import time
import json
from datetime import datetime
from dotenv import load_dotenv
from loguru import logger

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import Config
from src.state_manager import StateManager
from src.downloader import Downloader
from src.sources.malware_bazaar import MalwareBazaar
from src.sources.hybrid_analysis import HybridAnalysis
from src.sources.vx_underground import VXUnderground
from src.sources.triage import Triage
# from src.sources.vx_ui_scraper import VXInteractiveScraper # Deferred
from src.ioc_processor import IOCProcessor

GROUPS_FILE = "groups.txt"
ENV_FILE = ".env"
FILTERS_FILE = "filters.json"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def setup_env():
    print("\n--- API Configuration ---")
    mb_key = input(f"Enter MalwareBazaar API Key (Current: {'*' * 8 if Config.MALWARE_BAZAAR_API_KEY else 'None'}): ").strip()
    ha_key = input(f"Enter Hybrid Analysis API Key (Current: {'*' * 8 if Config.HYBRID_ANALYSIS_API_KEY else 'None'}): ").strip()
    # vx_key = input(f"Enter VX Underground API Key (Current: {'*' * 8 if Config.VX_UNDERGROUND_API_KEY else 'None'}): ").strip()
    triage_key = input(f"Enter Triage API Key (Current: {'*' * 8 if Config.TRIAGE_API_KEY else 'None'}): ").strip()

def setup_env():
    while True:
        clear_screen()
        print("\n--- API Configuration ---")
        print(f"1. MalwareBazaar Key   : {'*' * 8 if Config.MALWARE_BAZAAR_API_KEY else 'Not Set'}")
        print(f"2. Hybrid Analysis Key : {'*' * 8 if Config.HYBRID_ANALYSIS_API_KEY else 'Not Set'}")
        print(f"3. Triage API Key      : {'*' * 8 if Config.TRIAGE_API_KEY else 'Not Set'}")
        print("4. Back to Main Menu")
        
        choice = input("\nSelect an option to change: ").strip()
        
        if choice == '1':
            val = input("Enter MalwareBazaar API Key: ").strip()
            if val: Config.MALWARE_BAZAAR_API_KEY = val
        elif choice == '2':
            val = input("Enter Hybrid Analysis API Key: ").strip()
            if val: Config.HYBRID_ANALYSIS_API_KEY = val
        elif choice == '3':
            val = input("Enter Triage API Key: ").strip()
            if val: Config.TRIAGE_API_KEY = val
        elif choice == '4':
            break
        
        # Save after each change
        with open(ENV_FILE, "w") as f:
            f.write(f"MALWARE_BAZAAR_API_KEY={Config.MALWARE_BAZAAR_API_KEY}\n")
            f.write(f"HYBRID_ANALYSIS_API_KEY={Config.HYBRID_ANALYSIS_API_KEY}\n")
            f.write(f"TRIAGE_API_KEY={Config.TRIAGE_API_KEY}\n")
            f.write("DOWNLOAD_DIR=./downloads\n")
            f.write("LOG_LEVEL=INFO\n")
        
        load_dotenv(override=True)
        print("Configuration successfully updated.")
        time.sleep(1)

def setup_groups():
    while True:
        clear_screen()
        current_groups = load_groups()
        print("\n--- Group Configuration ---")
        print(f"Current Groups ({len(current_groups)}):")
        print(", ".join(current_groups[:10]) + ("..." if len(current_groups) > 10 else ""))
        
        print("\n1. Enter Groups Manually (Comma or Newline separated)")
        print("2. Import Groups from File (.txt)")
        print("3. Back to Main Menu")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            print("\nEnter groups below (Paste allowed).")
            print("Type 'DONE' (or press Enter twice) to finish.")
            print("-" * 30)
            
            new_groups = []
            empty_lines = 0
            while True:
                line = input().strip()
                if line == 'DONE': break
                
                if not line:
                    empty_lines += 1
                    if empty_lines >= 2: break
                    continue
                else:
                    empty_lines = 0
                
                # Split by comma in case mixed
                parts = [p.strip() for p in line.replace(',', '\n').split('\n') if p.strip()]
                new_groups.extend(parts)
            
            if new_groups:
                with open(GROUPS_FILE, "w") as f:
                    for g in new_groups:
                        f.write(f"{g}\n")
                print(f"Successfully saved {len(new_groups)} groups.")
                time.sleep(1)
        
        elif choice == '2':
            path = input("Enter file path: ").strip()
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        file_groups = [line.strip() for line in f if line.strip()]
                    
                    if file_groups:
                        with open(GROUPS_FILE, "w") as f:
                            for g in file_groups:
                                f.write(f"{g}\n")
                        print(f"Imported {len(file_groups)} groups from file!")
                        time.sleep(1)
                    else:
                        print("File is empty.")
                        time.sleep(1)
                except Exception as e:
                    print(f"Error reading file: {e}")
                    time.sleep(1)
            else:
                print("File not found.")
                time.sleep(1)
                
        elif choice == '3':
            break
    else:
        print("No changes made.")

def load_groups(filename=GROUPS_FILE):
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []

def load_filters():
    if os.path.exists(FILTERS_FILE):
        try:
            with open(FILTERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_filters(filters):
    with open(FILTERS_FILE, 'w') as f:
        json.dump(filters, f, indent=4)

def setup_filters():
    while True:
        clear_screen()
        current = load_filters()
        
        print("\n--- Filter & Verification Configuration ---")
        print(f"1. Max Count per Group   : {current.get('max_count', 'Unlimited')}")
        print(f"2. Start Date (YYYY-MM)  : {current.get('start_date', 'None')}")
        print(f"3. End Date (YYYY-MM)    : {current.get('end_date', 'None')}")
        print("-" * 30)
        print(f"4. Verify MB Signature   : {'ENABLED' if current.get('verify_mb_signature', True) else 'DISABLED'}")
        print(f"5. Allow MB Tag Fallback : {'ENABLED' if current.get('allow_mb_tag_fallback', False) else 'DISABLED'}")
        print(f"6. Verify HA Family      : {'ENABLED' if current.get('verify_ha_family', True) else 'DISABLED'}")
        print(f"7. Allow HA Tags Fallback: {'ENABLED' if current.get('allow_ha_community_tags', True) else 'DISABLED'}")
        print("-" * 30)
        print(f"8. Cross-Check Sources   : {'ENABLED' if current.get('cross_check_sources', True) else 'DISABLED'}")
        print(f"9. Source: MalwareBazaar : {'ENABLED' if current.get('enable_source_mb', True) else 'DISABLED'}")
        print(f"10. Source: HybridAnalysis: {'ENABLED' if current.get('enable_source_ha', True) else 'DISABLED'}")
        print("11. Back to Main Menu")
        
        choice = input("\nSelect setting to change: ").strip()
        
        if choice == '1':
            mc = input("Enter max downloads (or 'unset'): ").strip()
            if mc.lower() == 'unset': current['max_count'] = None
            elif mc.isdigit(): current['max_count'] = int(mc)
        elif choice == '2':
            sd = input("Enter Start Date (YYYY-MM) or 'unset': ").strip()
            current['start_date'] = None if sd.lower() == 'unset' else sd
        elif choice == '3':
            ed = input("Enter End Date (YYYY-MM) or 'unset': ").strip()
            current['end_date'] = None if ed.lower() == 'unset' else ed
        elif choice == '4':
            current['verify_mb_signature'] = not current.get('verify_mb_signature', True)
        elif choice == '5':
            current['allow_mb_tag_fallback'] = not current.get('allow_mb_tag_fallback', False)
        elif choice == '6':
            current['verify_ha_family'] = not current.get('verify_ha_family', True)
        elif choice == '7':
            current['allow_ha_community_tags'] = not current.get('allow_ha_community_tags', True)
        elif choice == '8':
            current['cross_check_sources'] = not current.get('cross_check_sources', True)
        elif choice == '9':
            current['enable_source_mb'] = not current.get('enable_source_mb', True)
        elif choice == '10':
            current['enable_source_ha'] = not current.get('enable_source_ha', True)
        elif choice == '11':
            break
            
        save_filters(current)
        print("Settings successfully updated.")
        time.sleep(0.5)

def check_date_filter(date_str, start_date_str, end_date_str):
    if not date_str: return True # Keep unknown dates
    
    try:
        # date_str is typically "2023-10-25 10:00:00" or similar ISO
        dt_item = datetime.fromisoformat(date_str.replace("Z", "+00:00").split(" ")[0])
        
        if start_date_str:
            dt_start = datetime.strptime(start_date_str, "%Y-%m")
            if dt_item < dt_start:
                return False
                
        if end_date_str:
            dt_end = datetime.strptime(end_date_str, "%Y-%m")
            # For end date, we generally want inclusive of that month
            if dt_item.replace(day=1) > dt_end:
                return False

        return True
    except Exception as e:
        return True 

def run_downloader(args=None):
    # Setup Logging
    logger.remove()
    log_level = Config.LOG_LEVEL
    logger.add(sys.stderr, level=log_level)
    logger.add("downloader.log", rotation="10 MB", level=log_level)
    
    # Load Filters
    filters = load_filters()
    
    # Default Filter Values
    max_count = filters.get("max_count")
    start_date = filters.get("start_date")
    end_date = filters.get("end_date")
    verify_mb_signature = filters.get("verify_mb_signature", True)
    allow_mb_tag_fallback = filters.get("allow_mb_tag_fallback", False)
    verify_ha_family = filters.get("verify_ha_family", True)
    allow_ha_community_tags = filters.get("allow_ha_community_tags", True)
    cross_check_sources = filters.get("cross_check_sources", True)
    enable_source_mb = filters.get("enable_source_mb", True)
    enable_source_ha = filters.get("enable_source_ha", True)
    
    groups = []

    # --- ARGS Priority Overrides ---
    if args:
        # API Keys
        if args.mb_key: Config.MALWARE_BAZAAR_API_KEY = args.mb_key
        if args.ha_key: Config.HYBRID_ANALYSIS_API_KEY = args.ha_key
        if args.triage_key: Config.TRIAGE_API_KEY = args.triage_key
        
        # Filters
        if args.max_count is not None: max_count = args.max_count
        if args.start_date: start_date = args.start_date
        if args.end_date: end_date = args.end_date
        
        # Verification (BooleanOptionalAction returns True/False/None)
        if args.verify_mb_sig is not None: verify_mb_signature = args.verify_mb_sig
        if args.allow_mb_fallback is not None: allow_mb_tag_fallback = args.allow_mb_fallback
        if args.verify_ha_family is not None: verify_ha_family = args.verify_ha_family
        if args.allow_ha_tags is not None: allow_ha_community_tags = args.allow_ha_tags
        
        # Sources
        if args.cross_check is not None: cross_check_sources = args.cross_check
        if args.source_mb is not None: enable_source_mb = args.source_mb
        if args.source_ha is not None: enable_source_ha = args.source_ha
        
        # Groups override
        if args.groups:
            groups = [g.strip() for g in args.groups.split(',')]
    
    
    logger.info(f"Starting Downloader... Filters: Max={max_count}, Start={start_date}, End={end_date}")
    logger.info(f"files will be saved to: {os.path.abspath(Config.DOWNLOAD_DIR)}")
    logger.info(f"Verification: MB_Sig={verify_mb_signature} (Fallback={allow_mb_tag_fallback}), HA_Family={verify_ha_family}")

    # Initialize Components
    downloader = Downloader()

    # Initialize Sources
    sources = {}
    
    if Config.MALWARE_BAZAAR_API_KEY and enable_source_mb:
        sources["MalwareBazaar"] = MalwareBazaar(Config.MALWARE_BAZAAR_API_KEY)
    
    if Config.HYBRID_ANALYSIS_API_KEY and enable_source_ha:
        sources["HybridAnalysis"] = HybridAnalysis(Config.HYBRID_ANALYSIS_API_KEY)
    
    # ... (Other sources like Triage, VXUnderground can be added here)

    if not sources:
        logger.error("No sources enabled or configured!")
        return

    # Load Groups if not provided via args
    if not groups:
        groups = load_groups()
        
    if not groups:
        logger.warning("No groups found! Please configure groups first or pass --groups.")
        return

    # Main Loop
    for group in groups:
        logger.info(f"Processing Group: {group}")
        
        # --- MODE 1: STRICT CROSS-CHECK ---
        if cross_check_sources:
            # Primary Source Selection (Default to MB if available, else first available)
            primary_source_name = "MalwareBazaar" if "MalwareBazaar" in sources else list(sources.keys())[0]
            primary_source = sources[primary_source_name]
            secondary_sources = {k: v for k, v in sources.items() if k != primary_source_name}
            
            download_count = 0
            
            try:
                logger.info(f"[Mode: Strict Cross-Check] Searching {primary_source_name} for tag: {group}")
                search_limit = max_count * 2 if max_count else 100
                
                # Search Primary
                results = list(primary_source.search(group, limit=search_limit))
                
                if not results:
                    logger.warning(f"No results found in {primary_source_name} for {group}")
                    # In strict mode, if not in primary, we can't cross-check, so move to next group
                    continue
                    
                logger.info(f"Found {len(results)} candidates in {primary_source_name}. Starting strict verification...")

                for sample in results:
                    if max_count and download_count >= max_count:
                        logger.info("Max count reached for this group.")
                        break
                    
                    file_hash = sample.get("hash")
                    date_str = sample.get("first_seen")

                    # Verification 1: Primary Source Metadata (e.g. MB Signature)
                    if primary_source_name == "MalwareBazaar" and verify_mb_signature:
                        signature = sample.get("signature", "")
                        logger.debug(f"[Strict] Checking MB Signature: '{signature}' against '{group}'")
                        
                        if not signature or group.lower() not in signature.lower():
                            accepted_via_fallback = False
                            if allow_mb_tag_fallback:
                                sample_tags = sample.get("tags", []) or []
                                logger.debug(f"[Strict] Checking MB Tag Fallback: Tags={sample_tags}")
                                if any(group.lower() in t.lower() for t in sample_tags):
                                    accepted_via_fallback = True
                                    logger.debug(f"[Strict] Accepted via MB Tag Fallback.")
                            
                            if not accepted_via_fallback:
                                logger.debug(f"[Strict] MB Signature rejected.")
                                continue

                    # Date Filter
                    if not check_date_filter(date_str, start_date, end_date):
                        continue

                    # Verification 2: Secondary Sources (Strict)
                    verified_in_all = True
                    if secondary_sources:
                        logger.info(f"Verifying {file_hash} across {len(secondary_sources)} secondary sources...")
                        for src_name, src_obj in secondary_sources.items():
                            verified_in_src = False
                            
                            # Hybrid Analysis Verification
                            if src_name == "HybridAnalysis":
                                overview = src_obj.get_file_overview(file_hash)
                                if overview:
                                    vx_family = overview.get("vx_family", "")
                                    threat_name = overview.get("threat_name", "")
                                    tags = overview.get("tags", [])
                                    verdict = overview.get("verdict", "")
                                    
                                    logger.debug(f"[Strict] HA Overview: Family='{vx_family}', Threat='{threat_name}', Verdict='{verdict}', Tags={tags}")
                                    
                                    if (vx_family and group.lower() in vx_family.lower()) or \
                                       (threat_name and group.lower() in threat_name.lower()):
                                        verified_in_src = True
                                    elif allow_ha_community_tags and tags and any(group.lower() in t.lower() for t in tags):
                                        verified_in_src = True
                                        logger.info(f"Verified in HA via Tags: {tags}")
                                    
                                    # Malicious Verdict Fallback
                                    elif verdict == "malicious" and not vx_family and not threat_name:
                                        verified_in_src = True
                                        logger.info(f"Verified in HA via Verdict (Malicious, but unknown family). Primary source attribution remains: '{group}'.")
                            
                            # Add other sources here...

                            if not verified_in_src:
                                logger.warning(f"Cross-check FAILED for {file_hash} in {src_name}")
                                verified_in_all = False
                                break
                    
                    if not verified_in_all:
                        continue

                    # Download (Verified in ALL)
                    logger.success(f"Sample {file_hash} verified! Initiating download...")
                    target_dir = downloader.get_target_dir(group, date_str)
                    
                    # Download from Primary
                    primary_path = os.path.join(target_dir, f"{file_hash}.zip")
                    if not os.path.exists(primary_path):
                        content = primary_source.download(file_hash)
                        if content:
                            meta = sample.copy()
                            meta["source"] = primary_source_name
                            meta["archive_password"] = "infected"
                            if downloader.save_file(content, meta, group):
                                download_count += 1
                    
                    time.sleep(1)

            except Exception as e:
                logger.error(f"Error in strict mode for {group}: {e}")

        # --- MODE 2: INDEPENDENT COLLECTION ---
        else:
            logger.info(f"[Mode: Independent Collection] Processing sources separately...")
            
            # Track downloaded hashes for this group to prevent duplicates across sources
            downloaded_hashes = set()
            
            for src_name, src_obj in sources.items():
                logger.info(f"--- Source: {src_name} ---")
                download_count = 0
                
                try:
                    search_limit = max_count * 2 if max_count else 100
                    results = list(src_obj.search(group, limit=search_limit))
                    
                    if not results:
                        logger.warning(f"No results found in {src_name} for {group}")
                        continue
                        
                    logger.info(f"Found {len(results)} candidates in {src_name}...")
                    
                    for sample in results:
                        if max_count and download_count >= max_count:
                            logger.info(f"Max count reached for {src_name}.")
                            break
                        
                        file_hash = sample.get("hash")
                        
                        # Dedup check (if already downloaded by previous source in this run)
                        if file_hash in downloaded_hashes:
                            logger.info(f"Skipping {file_hash} (Already downloaded via another source).")
                            continue
                            
                        # Also check file system for existence
                        date_str = sample.get("first_seen") # Might differ per source format
                        target_dir = downloader.get_target_dir(group, date_str)
                        
                        # Check likely filename permutations
                        probable_filenames = [f"{file_hash}.zip", f"{file_hash}_{src_name}.zip"]
                        if any(os.path.exists(os.path.join(target_dir, f)) for f in probable_filenames):
                             logger.info(f"Skipping {file_hash} (Already exists on disk).")
                             downloaded_hashes.add(file_hash)
                             continue

                        # Verify Source-Specific Logic
                        verified = False
                        if src_name == "MalwareBazaar":
                             if verify_mb_signature:
                                signature = sample.get("signature", "")
                                logger.debug(f"[Indep] Checking MB Signature: '{signature}'")
                                if signature and group.lower() in signature.lower(): verified = True
                                elif allow_mb_tag_fallback:
                                    tags = sample.get("tags", [])
                                    logger.debug(f"[Indep] Checking MB Tag Fallback: {tags}")
                                    if any(group.lower() in t.lower() for t in tags): verified = True
                             else:
                                 logger.debug(f"[Indep] MB Verification disabled.")
                                 verified = True # Verification disabled, trust search result

                        elif src_name == "HybridAnalysis":
                             if verify_ha_family:
                                 # We treat search results as valid candidates, assuming HA search handles the filtering well enough.
                                 # Or implement extra check if search result object has family info.
                                 # For simplicity/speed in independent mode, we often trust the search query.
                                 # But let's check basic fields if available.
                                 vx_family = sample.get("vx_family", "")
                                 threat_name = sample.get("threat_name", "") # Needs 'overview' usually but let's assume search result has it or strict logic is simpler here
                                 logger.debug(f"[Indep] HA Search Result: Family='{vx_family}', Threat='{threat_name}'")
                                 
                                 if (vx_family and group.lower() in vx_family.lower()) or \
                                    (threat_name and group.lower() in threat_name.lower()):
                                     verified = True
                                 else:
                                     # Fallback to tags or assume search was correct if verify_ha_family is lax?
                                     # Let's be strict if the flag is on.
                                     logger.debug(f"[Indep] HA Family mismatch.")
                                     verified = False 
                             else:
                                 verified = True

                        if not verified:
                            continue
                            
                        # Date Filter
                        if not check_date_filter(date_str, start_date, end_date):
                            continue

                        # Download
                        logger.info(f"Downloading {file_hash} from {src_name}...")
                        content = src_obj.download(file_hash)
                        if content:
                            meta = sample.copy()
                            meta["source"] = src_name
                            meta["archive_password"] = "infected"
                            # Save with standard name to facilitate dedup detection
                            meta["filename"] = f"{file_hash}.zip" 
                            
                            if downloader.save_file(content, meta, group):
                                download_count += 1
                                downloaded_hashes.add(file_hash)
                        
                        time.sleep(1)

                except Exception as e:
                    logger.error(f"Error in independent mode for {src_name}: {e}")
            
    logger.success("Workflow completed.")
    input("\nPress Enter to return to menu...")

def interactive_menu():
    while True:
        clear_screen()
        print("==========================================")
        print("   RANSOC (RANSOMWARE IOC DOWNLOADER)   ")
        print("==========================================")
        print("1. Initiate Collection Workflow")
        print("2. Configure API Credentials")
        print("3. Configure Target Groups")
        print("4. Configure Filters & Verification Modules")
        print("5. Exit Application")
        print("==========================================")
        
        choice = input("Select an option: ").strip()
        
        if choice == "1":
            try:
                run_downloader()
            except KeyboardInterrupt:
                print("\n\nOperation cancelled by user. Returning to menu...")
                time.sleep(1)
        elif choice == "2":
            setup_env()
        elif choice == "3":
            setup_groups()
        elif choice == "4":
            setup_filters()
        elif choice == "5":
            print("Exiting...")
            sys.exit(0)
        else:
            input("Invalid option. Press Enter to try again.")

def parse_args():
    parser = argparse.ArgumentParser(description="RanSoc - Automated Threat Intelligence Collection")
    
    # Execution Mode
    parser.add_argument("--interactive", action="store_true", help="Force interactive mode (default if no args provided)")
    
    # Filter Overrides
    parser.add_argument("--groups", type=str, help="Comma-separated list of ransomware groups to process (overrides groups.txt)")
    parser.add_argument("--max-count", type=int, help="Maximum number of downloads per group")
    parser.add_argument("--start-date", type=str, help="Start Date filter (YYYY-MM)")
    parser.add_argument("--end-date", type=str, help="End Date filter (YYYY-MM)")
    
    # Verification Toggles (Boolean Flags)
    parser.add_argument("--verify-mb-sig", action=argparse.BooleanOptionalAction, help="Verify MalwareBazaar signature")
    parser.add_argument("--allow-mb-fallback", action=argparse.BooleanOptionalAction, help="Allow MalwareBazaar tag fallback")
    parser.add_argument("--verify-ha-family", action=argparse.BooleanOptionalAction, help="Verify Hybrid Analysis family")
    parser.add_argument("--allow-ha-tags", action=argparse.BooleanOptionalAction, help="Allow Hybrid Analysis community tags fallback")
    
    # Source Toggles
    parser.add_argument("--cross-check", action=argparse.BooleanOptionalAction, help="Enable cross-check between sources")
    parser.add_argument("--source-mb", action=argparse.BooleanOptionalAction, help="Enable MalwareBazaar source")
    parser.add_argument("--source-ha", action=argparse.BooleanOptionalAction, help="Enable Hybrid Analysis source")
    
    # API Key Overrides
    parser.add_argument("--mb-key", type=str, help="MalwareBazaar API Key")
    parser.add_argument("--ha-key", type=str, help="Hybrid Analysis API Key")
    parser.add_argument("--triage-key", type=str, help="Triage API Key")
    
    # Debug
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    return parser.parse_args()

if __name__ == "__main__":
    load_dotenv()
    
    # If no arguments provided (len=1), default to interactive
    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parse_args()
        
        # Handle Debug Flag Global Override
        if args.debug:
            Config.LOG_LEVEL = "DEBUG"
            logger.configure(handlers=[{"sink": sys.stderr, "level": "DEBUG"}])
            logger.debug("Debug mode enabled via CLI flag.")
            
        if args.interactive:
            interactive_menu()
        else:
            run_downloader(args)
