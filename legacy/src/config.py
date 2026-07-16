import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
    MALWARE_BAZAAR_API_KEY = os.getenv("MALWARE_BAZAAR_API_KEY", "").strip()
    VX_UNDERGROUND_API_KEY = os.getenv("VX_UNDERGROUND_API_KEY", "").strip()
    OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
    TRIAGE_API_KEY = os.getenv("TRIAGE_API_KEY", "").strip()
    
    DOWNLOAD_DIR = os.getenv("DOWNLOAD_DIR", "./downloads")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    @staticmethod
    def validate_keys():
        """Checks which keys are available and returns a list of active sources."""
        active_sources = []
        if Config.MALWARE_BAZAAR_API_KEY:
            active_sources.append("MalwareBazaar")
        if Config.HYBRID_ANALYSIS_API_KEY:
            active_sources.append("HybridAnalysis")
        if Config.VX_UNDERGROUND_API_KEY:
            active_sources.append("VXUnderground")
        if Config.TRIAGE_API_KEY:
            active_sources.append("Triage")
        return active_sources
