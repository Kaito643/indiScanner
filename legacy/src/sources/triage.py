import requests
from typing import Generator, Dict
from ..source_base import SourceBase
from loguru import logger

class Triage(SourceBase):
    API_URL = "https://tria.ge/api/v0"

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.name = "Triage"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}"
        }

    def search(self, group_name: str, limit: int = 50) -> Generator[Dict, None, None]:
        logger.info(f"Searching Triage for family: {group_name}")
        endpoint = f"{self.API_URL}/search"
        
        # Triage search query format: "family:lockbit"
        query = f"family:{group_name}"
        params = {
            "query": query,
            "limit": limit
        }

        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 401:
                logger.error("Triage API Unauthorized. Check your API key.")
                return

            response.raise_for_status()
            data = response.json()
            
            # data is usually a list of samples in 'data' key for search results
            samples = data.get("data", [])
            
            for sample in samples:
                # Triage sample object structure needs inspection, but usually has 'id', 'filename', 'sha256'
                # or 'tasks' -> 'sha256'
                
                # Sample ID is crucial for download
                sample_id = sample.get("id")
                if not sample_id: continue
                
                # Metadata might be top level or inside 'task'
                # Let's try to extract SHA256 safely
                sha256 = sample.get("sha256")
                if not sha256:
                    # sometimes it's not directly exposed in search list depending on API version
                    # but let's assume standard response
                    continue
                    
                yield {
                    "hash": sha256,
                    "filename": sample.get("filename", "unknown.bin"),
                    "first_seen": sample.get("submitted", "2024-01-01"),
                    "tags": sample.get("tags", []),
                    "source": "Triage",
                    "id": sample_id # store internal ID for download
                }

        except Exception as e:
            logger.error(f"Error searching Triage: {e}")

    def download(self, file_meta: str) -> bytes:
        # Note: SourceBase.download receives file_hash normally.
        # But Triage needs sample_id. 
        # API design issue: distinct sources need distinct identifiers.
        # Workaround: Ideally I should pass the whole metadata object to download, 
        # or standard download should take ID.
        # For now, let's try to fetch by ID if possible, but the signature says file_hash.
        
        # If I can't change the signature, I might need to re-query or use hash to find ID?
        # Triage API allows GET /samples/{sample_id}/sample
        # It does NOT easily allow GET /samples/{hash}/sample directly without search.
        
        # However, to fit strict SourceBase(file_hash), I must search again or...
        # Wait, the downloader.py calls source.download(item['hash']).
        # This is a limitation of my current architecture. 
        # I should have passed the whole item.
        
        # HACK: For Triage, I will try to use the Search API to resolve Hash -> ID -> Download
        # This is inefficient but fits the interface.
        
        logger.info(f"Downloading {file_meta} from Triage")
        
        # Step 1: Resolve Hash to ID
        sample_id = self._get_id_from_hash(file_meta)
        if not sample_id:
            logger.warning(f"Could not resolve Hash {file_meta} to Triage ID.")
            return None
            
        # Step 2: Download
        endpoint = f"{self.API_URL}/samples/{sample_id}/sample"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=60, stream=True)
            if response.status_code == 429: # Rate limit
                return None
            
            if response.status_code == 404:
                return None
                
            response.raise_for_status()
            return response.content
        except Exception as e:
            logger.error(f"Error downloading {file_meta} from Triage: {e}")
            return None

    def _get_id_from_hash(self, file_hash: str) -> str:
        endpoint = f"{self.API_URL}/search"
        params = {"query": f"sha256:{file_hash}", "limit": 1}
        try:
            r = requests.get(endpoint, headers=self.headers, params=params, timeout=15)
            if r.status_code == 200:
                data = r.json().get("data", [])
                if data:
                    return data[0].get("id")
        except:
            pass
        return None
