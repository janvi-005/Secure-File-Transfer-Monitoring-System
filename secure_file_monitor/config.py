import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

MONITOR_DIRECTORIES = [
    os.path.join(os.environ.get("USERPROFILE", ""), "Documents"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
]

SENSITIVE_PATTERNS = [
    "*.pdf",
    "*.docx",
    "*.xlsx",
    "*.pptx",
    "*.key",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.env",
    "*.sql",
    "*.db",
    "*.sqlite",
]

SENSITIVE_KEYWORDS = [
    "confidential",
    "secret",
    "private",
    "password",
    "credential",
    "api_key",
    "token",
]

LOG_FILE = BASE_DIR / "logs" / "audit.log"
ALERT_LOG_FILE = BASE_DIR / "logs" / "alerts.log"
REPORT_DIR = BASE_DIR / "reports"
HASH_DB = BASE_DIR / "logs" / "file_hashes.json"

HASH_ALGORITHM = "sha256"

ALERT_THRESHOLDS = {
    "max_transfers_per_minute": 10,
    "max_sensitive_access_per_hour": 20,
    "suspicious_hours": (22, 6),  # 10 PM to 6 AM
}

AUTHORIZATION_RULES = {
    "allowed_extensions": [".txt", ".log", ".csv", ".json", ".xml"],
    "blocked_extensions": [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js"],
    "max_file_size_mb": 100,
}

MONITOR_CONFIG = {
    "recursive": True,
    "follow_symlinks": False,
    "event_delay_ms": 100,
}
