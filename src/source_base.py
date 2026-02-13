from abc import ABC, abstractmethod
from typing import List, Dict, Generator

class SourceBase(ABC):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.name = "Unknown"

    @abstractmethod
    def search(self, group_name: str, limit: int = 100) -> Generator[Dict, None, None]:
        """
        Searches for samples related to the group.
        Should yield dictionaries containing at least:
        - 'hash': SHA256 usually
        - 'filename': Original filename
        - 'first_seen': Date string
        - 'tags': List of tags
        """
        pass

    @abstractmethod
    def download(self, file_hash: str) -> bytes:
        """
        Downloads the file content as bytes.
        Returns None if failed.
        """
        pass
