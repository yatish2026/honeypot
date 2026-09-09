import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

# Directory Paths
MODULES_DIR = BASE_DIR / "modules"
DATASETS_DIR = BASE_DIR / "datasets"
MODELS_DIR = MODULES_DIR / "honeypot_detector" / "models"
PAYLOADS_DIR = MODULES_DIR / "prompt_shield" / "payloads"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure directories exist
MODELS_DIR.mkdir(parents=True, exist_ok=True)
PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# API Keys (Can be set via .env or Streamlit UI sidebar)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# Default Port List to Scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 502, 1433, 2222, 3306, 5000, 8080, 8443, 8888]

# Risk Thresholds
HONEYPOT_RISK_THRESHOLDS = {
    "CRITICAL": 0.80,
    "HIGH": 0.60,
    "MEDIUM": 0.35,
    "LOW": 0.0
}
