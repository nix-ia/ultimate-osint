import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")
ABSTRACTAPI_PHONE_KEY = os.getenv("ABSTRACTAPI_PHONE_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "")
DEHASHED_EMAIL = os.getenv("DEHASHED_EMAIL", "")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; OSINTBot/1.0; +https://github.com/nix-ia/ultimate-osint)"
}

TIMEOUT = 15
