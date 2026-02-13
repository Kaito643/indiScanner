import os
import json
import hashlib
from datetime import datetime
from loguru import logger
from .config import Config

class Downloader:
    def __init__(self, base_dir=Config.DOWNLOAD_DIR):
        self.base_dir = base_dir

    def calculate_sha256(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def get_target_dir(self, group_name: str, date_str: str) -> str:
        """
        Determines the directory path based on date.
        Expected date_str format: 'YYYY-MM-DD...'
        Result: base_dir/Group/Year/Month
        """
        try:
            # Flexible parsing: try to get YYYY and MM
            # If date_str is None or invalid, use 'Unknown'
            if not date_str:
                year, month = "Unknown", "Unknown"
            else:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00").split(" ")[0]) # Basic ISO handling
                year = str(dt.year)
                month = f"{dt.month:02d}"
        except Exception:
            year, month = "Unknown", "Unknown"

        return os.path.join(self.base_dir, group_name, year, month)

    def save_file(self, content: bytes, metadata: dict, group_name: str) -> bool:
        file_hash = metadata.get("hash")
        if not file_hash:
            file_hash = self.calculate_sha256(content)

        # Determine path
        first_seen = metadata.get("first_seen")
        target_dir = self.get_target_dir(group_name, first_seen)
        
        os.makedirs(target_dir, exist_ok=True)
        original_name = metadata.get("filename")
        if original_name and "unknown" not in original_name.lower():
            # Basic sanitization
            safe_name = os.path.basename(original_name)
            if not safe_name.lower().endswith(".zip"):
                safe_name += ".zip"
            file_name = safe_name
        else:
            file_name = f"{file_hash}.zip"
            
        file_path = os.path.join(target_dir, file_name)
        meta_path = os.path.join(target_dir, f"{file_hash}.json")

        if os.path.exists(file_path):
            logger.info(f"File already exists: {file_path}")
            return True

        try:
            with open(file_path, "wb") as f:
                f.write(content)
            
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=4)
                
            logger.success(f"Saved {file_hash} to {target_dir}")
            return True
        except Exception as e:
            logger.error(f"Failed to save file: {e}")
            return False

    def exists(self, file_hash: str, group_name: str) -> bool:
        # This is a simple check. For absolute certainty we'd need a DB or efficient index.
        # But checking if the file exists in the filesystem requires knowing the date.
        # If we don't know the date, we can't easily check without walking directories.
        # For now, we rely on the download logic. If we download and it exists, we skip overwrite.
        # But to save bandwidth, StateManager usage is preferred.
        return False 
