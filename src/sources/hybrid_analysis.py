import requests
import time
from typing import Generator, Dict
from ..source_base import SourceBase
from loguru import logger

class HybridAnalysis(SourceBase):
    API_URL = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.name = "HybridAnalysis"
        self.headers = {
            "api-key": self.api_key,
            "User-Agent": "RansomwareDownloader/1.0"
        }

    def search(self, group_name: str, limit: int = 100) -> Generator[Dict, None, None]:
        logger.info(f"Searching Hybrid Analysis for tag: {group_name}")
        endpoint = f"{self.API_URL}/search/terms"
        
        # HA uses POST for search
        payload = {
            "query": f"tags:{group_name}",
            "limit": limit
        }

        try:
            response = requests.post(endpoint, headers=self.headers, data=payload, timeout=30)
            
            if response.status_code == 429:
                logger.warning("Hybrid Analysis rate limit reached during search.")
                return

            response.raise_for_status()
            data = response.json()
            
            # The search/terms endpoint returns a list of results
            results = data.get("result", [])
            for item in results:
                yield {
                    "hash": item.get("sha256"),
                    "filename": item.get("submit_name", "unknown.bin"),
                    "first_seen": item.get("analysis_start_time"), # Using analysis time as proxy for first seen
                    "tags": item.get("tags", []),
                    "verdict": item.get("verdict", "unknown")
                }

        except Exception as e:
            if "404" in str(e) and "search/terms" in endpoint:
                logger.warning("Hybrid Analysis Search API seems unavailable (404). Falling back to Feed.")
                yield from self._fetch_from_feed(group_name)
            else:
                logger.error(f"Error searching Hybrid Analysis: {e}")

    def _fetch_from_feed(self, group_name: str) -> Generator[Dict, None, None]:
        """Fallback method to check latest feed for the group."""
        endpoint = f"{self.API_URL}/feed/latest"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=30)
            response.raise_for_status()
            data = response.json().get("data", [])
            
            count = 0
            for item in data:
                # Check for match in various fields
                vx_family = item.get("vx_family", "") or ""
                tags = item.get("tags", []) or []
                description = item.get("description", "") or ""
                
                # Simple case-insensitive match
                match = False
                if group_name.lower() in vx_family.lower(): match = True
                if any(group_name.lower() in t.lower() for t in tags): match = True
                if group_name.lower() in description.lower(): match = True
                
                if match:
                    count += 1
                    yield {
                        "hash": item.get("sha256"),
                        "filename": item.get("name", "unknown.bin"),
                        "first_seen": item.get("analysis_start_time"),
                        "tags": tags,
                        "verdict": item.get("threat_level_readable", "unknown")
                    }
            
            if count > 0:
                logger.info(f"Found {count} items in Hybrid Analysis Feed for {group_name}")
                
        except Exception as e:
            logger.error(f"Error fetching from HA feed: {e}")

    def download(self, file_hash: str) -> bytes:
        logger.info(f"Downloading {file_hash} from Hybrid Analysis")
        endpoint = f"{self.API_URL}/overview/{file_hash}/sample"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=60, stream=True)
            
            if response.status_code == 429:
                logger.warning("Hybrid Analysis rate limit reached during download.")
                return None
            
            if response.status_code == 404:
                logger.warning(f"File not found in Hybrid Analysis: {file_hash}")
                return None

            response.raise_for_status()
            return response.content

        except Exception as e:
            logger.error(f"Error downloading from Hybrid Analysis: {e}")
            return None

    def get_file_overview(self, file_hash: str) -> Dict:
        """Fetches the summary/overview of a file to check vx_family/verdict."""
        endpoint = f"{self.API_URL}/overview/{file_hash}/summary"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=30)
            if response.status_code == 404: return None
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching HA overview for {file_hash}: {e}")
            return None
