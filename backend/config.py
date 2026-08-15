import os

from dotenv import load_dotenv

load_dotenv()

LLM_API_KEYS = [
    k.strip() for k in os.getenv("LLM_API_KEYS", "").split(",") if k.strip()
]
LLM_MODEL = os.getenv("LLM_MODEL", "openai/gpt-oss-120b")
ZAP_DOCKER_IMAGE = os.getenv("ZAP_DOCKER_IMAGE", "zaproxy/zap-stable")
NUCLEI_TEMPLATES_PATH = os.getenv(
    "NUCLEI_TEMPLATES_PATH", os.path.expanduser("~/nuclei-templates")
)
WORDLIST_COMMON = os.getenv(
    "WORDLIST_COMMON",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "wordlists", "common.txt"),
)
WORDLIST_LIGHT = os.getenv(
    "WORDLIST_LIGHT",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "wordlists", "light.txt"),
)
WORDLIST_MICRO = os.getenv(
    "WORDLIST_MICRO",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "wordlists", "micro.txt"),
)
STORAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage")
SCREENSHOTS_DIR = os.path.join(STORAGE_DIR, "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)