# config.py
import os

# --- Tool Configuration ---
# Attempt to find tools in PATH, allow override via environment variables
OLEVBA_CMD = os.environ.get("OLEVBA_CMD", "olevba")
MSODDE_CMD = os.environ.get("MSODDE_CMD", "msodde")
OLEOBJ_CMD = os.environ.get("OLEOBJ_CMD", "oleobj")
PYTHON_CMD = os.environ.get("PYTHON_CMD", "python") # For running modules
XLMMACRO_MODULE = "XLMMacroDeobfuscator.deobfuscator"
XLMMACRO_DEFAULT_ENTRY = "Sheet1!A1" # Default, may need adjustment

# --- Analysis Parameters ---
SUBPROCESS_TIMEOUT = int(os.environ.get("SUBPROCESS_TIMEOUT", 120)) # Increased timeout
MAX_FILE_SIZE_BYTES = int(os.environ.get("MAX_FILE_SIZE_BYTES", 50 * 1024 * 1024)) # 50 MB limit

# List of allowed MIME types (using python-magic)
# Example: Adjust based on the exact types you want to support
ALLOWED_MIME_TYPES = [
    "application/vnd.ms-excel", # .xls
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", # .xlsx
    "application/vnd.ms-excel.sheet.macroEnabled.12", # .xlsm
    "application/msword", # .doc
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", # .docx
    "application/vnd.ms-word.document.macroEnabled.12", # .docm
    "application/vnd.ms-powerpoint", # .ppt
    "application/vnd.openxmlformats-officedocument.presentationml.presentation", # .pptx
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12", # .pptm
    # Add RTF, OLE containers if needed
    "application/rtf",
    "text/rtf",
    "application/vnd.ms-outlook", # .msg (oleobj might handle)
    "application/octet-stream", # Allow generic binary as fallback? Be cautious.
]

# --- Classification Scoring ---
# Define points for different indicators
SCORE_THRESHOLD_MALICIOUS = 5 # Score >= this is flagged as malicious
SCORES = {
    "VBA_AUTOEXEC": 3,
    "VBA_SUSPICIOUS": 4,
    "XLM_SUSPICIOUS_FUNC": 4,
    "DDE_LINK_ACTIVE": 5,
    "EMBEDDED_EXE": 3,
    "FOUND_URL": 1, # Score per URL (maybe cap?)
    "FOUND_IP": 1,  # Score per IP (maybe cap?)
    "TOOL_WARNING": 1, # General warning from a tool
}

# --- IOC Extraction ---
# Filter out common private/local IPs during classification scoring
PRIVATE_IP_PREFIXES = ('192.168.', '10.', '172.16.', '172.17.', '172.18.',
                     '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                     '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                     '172.29.', '172.30.', '172.31.', '127.0.0.')