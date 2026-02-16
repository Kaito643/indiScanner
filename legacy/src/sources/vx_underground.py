import requests
from typing import Generator, Dict
from ..source_base import SourceBase
from loguru import logger

class VXUnderground(SourceBase):
    API_URL = "https://api.vx-underground.org/api/v2"

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.name = "VXUnderground"
        self.headers = {}
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    def search(self, group_name: str, limit: int = 100) -> Generator[Dict, None, None]:
        if not self.api_key:
            logger.warning("VX Underground API key not provided. Skipping.")
            return

        logger.info(f"Searching VX Underground for family: {group_name}")
        endpoint = f"{self.API_URL}/samples/list"
        
        # This is a hypothetical endpoint based on common VXUG API structure
        # Real structure may vary; usually it's /Samples/{Family}
        
        # If API doesn't support search, we might need to list directories
        # For this implementation, I'm assuming a standard search/list capability
        
        try:
            # Attempting to list samples for a family
            # Note: VX API endpoints change. This is a best-effort implementation.
            payload = {"family": group_name, "limit": limit}
            response = requests.get(endpoint, params=payload, headers=self.headers, timeout=30)
            
            if response.status_code == 404:
                return # No samples found

            response.raise_for_status()
            data = response.json()
            
            for item in data:
                yield {
                    "hash": item.get("sha256"),
                    "filename": item.get("filename", "unknown.bin"),
                    "first_seen": item.get("uploaded", "2024-01-01"),
                    "tags": [group_name],
                    "source": "VXUnderground"
                }

        except Exception as e:
            logger.error(f"Error searching VX Underground: {e}")

    def download(self, file_hash: str) -> bytes:
        if not self.api_key:
            return None

        logger.info(f"Downloading {file_hash} from VX Underground")
        endpoint = f"{self.API_URL}/samples/download/{file_hash}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=60)
            
            if response.status_code == 404:
                logger.warning(f"File not found in VX Underground: {file_hash}")
                return None

            response.raise_for_status()
            return response.content
        except Exception as e:
            logger.error(f"Error downloading from VX Underground: {e}")
            return None
