"""
Configuration for QFAT

Centralised config file for constants and settings used across modules
"""

import os
from pathlib import Path

# VirusTotal API key
VT_API_KEY = os.environ.get("QFAT_VT_API_KEY", "")

# Free tier request limits: 4/min, 500/day
# Sleep between submit and poll calls
VT_RATE_LIMIT_SECONDS = 20
VT_URL_POLL_ATTEMPTS = 10
VT_FILE_POLL_ATTEMPTS = 20

# Paths
PROJECT_ROOT = Path(__file__).parent.resolve()
INPUT_FOLDER = PROJECT_ROOT / "input_emails"
OUTPUT_CSV = PROJECT_ROOT / "output" / "forensic_report.csv"

# Detection logic
# Any VT vector count above this means the article was flagged as malicious
SAFE_URL_REPUTATION_THRESHOLD = 0

# Forensic presentation settings
TOOL_VERSION = '1.0.0'
EVIDENCE_DIR = PROJECT_ROOT / "output" / "evidence"
AUDIT_LOG = PROJECT_ROOT / "output" / "qfat_audit.log"