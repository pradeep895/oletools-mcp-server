from mcp.server.fastmcp import FastMCP
import subprocess
import json
import os
import shutil
import logging
import tempfile
from typing import List, Dict, Any, Optional

# --- Dependency Imports ---
try:
    import magic
except ImportError:
    magic = None # Handle gracefully if python-magic is not installed
    logging.error("python-magic library not found. MIME type checking will be disabled. "
                  "Install it via 'pip install python-magic' and ensure libmagic is available.")

try:
    import iocextract
except ImportError:
    iocextract = None # Handle gracefully
    logging.error("iocextract library not found. Advanced IOC extraction will be disabled. "
                  "Install it via 'pip install iocextract'.")

# --- Configuration ---
try:
    import config
except ImportError:
    logging.fatal("config.py not found. Please create it.")
    exit(1)


# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(funcName)s] %(message)s')


# --- Helper Functions ---

def _check_dependencies():
    """Checks if required external tools are available."""
    tools = {
        "olevba": config.OLEVBA_CMD,
        "msodde": config.MSODDE_CMD,
        "oleobj": config.OLEOBJ_CMD,
        "python": config.PYTHON_CMD,
    }
    missing = []
    for name, cmd in tools.items():
        if not shutil.which(cmd):
            logging.error(f"Required command '{cmd}' (for {name}) not found in PATH.")
            missing.append(cmd)
    if magic is None:
        missing.append("python-magic library")
    if iocextract is None:
        missing.append("iocextract library")

    if missing:
        logging.error(f"Missing dependencies: {', '.join(missing)}. Please install them.")
        # Decide if you want to exit or continue with reduced functionality
        # For now, we log errors but allow continuation where possible.
        # raise RuntimeError(f"Missing dependencies: {', '.join(missing)}")
    else:
        logging.info("All external tool dependencies seem to be present.")

def _validate_input_file(file_path: str) -> Optional[str]:
    """Validate file existence, size, and type. Returns error message or None."""
    if not os.path.exists(file_path):
        return f"File not found: {file_path}"
    if not os.path.isfile(file_path):
        return f"Path is not a file: {file_path}"

    # Check file size
    try:
        file_size = os.path.getsize(file_path)
        if file_size > config.MAX_FILE_SIZE_BYTES:
            return f"File size {file_size} bytes exceeds limit of {config.MAX_FILE_SIZE_BYTES} bytes."
        if file_size == 0:
            return "File is empty."
    except OSError as e:
        return f"Error accessing file properties: {e}"

    # Check MIME type
    if magic:
        try:
            mime_type = magic.from_file(file_path, mime=True)
            logging.info(f"Detected MIME type for {os.path.basename(file_path)}: {mime_type}")
            if mime_type not in config.ALLOWED_MIME_TYPES:
                 # Allow octet-stream only if explicitly listed as allowed
                 if mime_type == "application/octet-stream" and mime_type not in config.ALLOWED_MIME_TYPES:
                      return f"File type '{mime_type}' is application/octet-stream and not explicitly allowed."
                 elif mime_type != "application/octet-stream": # Don't reject if it's an allowed non-octet-stream type
                      # Log a warning but don't reject if it's not octet-stream and not in the list? Or reject? Let's reject.
                      logging.warning(f"File type '{mime_type}' not in allowed list: {config.ALLOWED_MIME_TYPES}")
                      return f"File type '{mime_type}' is not in the list of allowed types."

        except Exception as e: # Catch potential errors from libmagic
            logging.error(f"Could not determine MIME type using python-magic: {e}")
            # Decide whether to proceed without type check or return an error
            # return f"Failed to determine file type: {e}" # Safer option
    else:
        logging.warning("Skipping MIME type check as python-magic is not available.")

    return None # Validation passed

def _run_tool(command: list, file_path: str, tool_name: str, output_dir: Optional[str] = None) -> dict:
    """
    Helper function to run an external tool via subprocess securely.
    Handles timeout, captures output/error, checks return code.
    Includes optional output directory argument for tools like oleobj.
    """
    # Command structure: [executable, arg1, arg2, ..., file_path]
    # For tools needing an output dir: [executable, -d, output_dir, ..., file_path]
    cmd_list = command

    # Add output directory if provided *before* the file path
    if output_dir:
        # Find where to insert -d and output_dir (assuming it's before file_path)
        # This is a bit fragile; depends on tool conventions. oleobj uses "-d dir file"
        cmd_list = cmd_list[:-1] + ["-d", output_dir] + [cmd_list[-1]]

    cmd_list.append(file_path) # Add file_path at the end

    result_dict = {
        "output": "",
        "stderr": "",
        "status": -1, # Default to error
        "error": "",
        "command_used": " ".join(cmd_list) # For debugging
    }

    try:
        logging.info(f"[{tool_name}] Running command: {' '.join(cmd_list)}")
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            encoding='utf-8', # Explicitly set encoding
            errors='replace', # Handle potential decoding errors
            check=False,
            timeout=config.SUBPROCESS_TIMEOUT
        )
        logging.info(f"[{tool_name}] Command finished with return code: {result.returncode}")

        result_dict.update({
            "output": result.stdout.strip() if result.stdout else "",
            "stderr": result.stderr.strip() if result.stderr else "",
            "status": result.returncode,
        })

        if result.returncode != 0:
            error_msg = f"{tool_name} failed with exit code {result.returncode}."
            # Include stderr snippet in the primary error message for quick context
            if result_dict["stderr"]:
                stderr_snippet = result_dict["stderr"][:200] + ('...' if len(result_dict["stderr"]) > 200 else '')
                error_msg += f" Stderr (partial): {stderr_snippet}"
            result_dict["error"] = error_msg
            logging.warning(error_msg) # Log the failure

    except FileNotFoundError:
        err = f"Command '{command[0]}' not found. Ensure prerequisites are installed and in PATH."
        logging.exception(f"[{tool_name}] {err}")
        result_dict["error"] = err
    except subprocess.TimeoutExpired:
        err = f"{tool_name} analysis timed out after {config.SUBPROCESS_TIMEOUT} seconds."
        logging.error(f"[{tool_name}] {err} Command: {' '.join(cmd_list)}")
        result_dict["error"] = err
        result_dict["status"] = -2 # Specific status for timeout
    except Exception as e:
        err = f"Unexpected error running {tool_name}: {str(e)}"
        logging.exception(f"[{tool_name}] {err} Command: {' '.join(cmd_list)}")
        result_dict["error"] = err

    return result_dict

# --- MCP Server Setup ---
mcp = FastMCP("oletools-secure-mcp")
_check_dependencies() # Check dependencies when the server starts

# --- MCP Tools ---

@mcp.tool()
def analyze_vba_macros(file_path: str, validation_error: Optional[str] = None) -> dict:
    """Analyze VBA macros using OLETools (olevba)."""
    if validation_error: return {"error": validation_error, "status": -1}
    return _run_tool([config.OLEVBA_CMD], file_path, "olevba")

@mcp.tool()
def detect_xlm_macros(file_path: str, validation_error: Optional[str] = None) -> dict:
    """Detect XLM macros using XLMMacroDeobfuscator (XLS) or Olevba (others)."""
    if validation_error: return {"error": validation_error, "status": -1}

    file_extension = os.path.splitext(file_path.lower())[1]
    tool_name = "XLMMacroDeobfuscator"
    command = [config.PYTHON_CMD, "-m", config.XLMMACRO_MODULE, "-f"]

    if file_extension == '.xls':
        # Add default start point - make configurable if needed
        command.extend(["--start-point", config.XLMMACRO_DEFAULT_ENTRY])
        result = _run_tool(command, file_path, tool_name)
    else:
        # Use Olevba for non-XLS files, as it can detect XLM indicators too
        tool_name = "olevba (for XLM)"
        logging.info(f"Using {tool_name} for XLM detection in non-XLS file: {file_path}")
        result = _run_tool([config.OLEVBA_CMD], file_path, tool_name)
        # Add context to olevba output if successful
        if result['status'] == 0:
            result['output'] = (result['output'] + "\n(Checked for XLM indicators using olevba)").strip()

    # Improve default "no findings" messages
    if result['status'] == 0 and not result['output']:
        result['output'] = f"No significant macro indicators found by {tool_name}."
    elif result['status'] != 0 and "error" in result and not result["error"].startswith(tool_name):
        # Prepend tool name to error if not already there
        result['error'] = f"{tool_name} failed: {result['error']}"

    return result

@mcp.tool()
def check_dde_links(file_path: str, validation_error: Optional[str] = None) -> dict:
    """Check for DDE links using OLETools (msodde)."""
    if validation_error: return {"error": validation_error, "status": -1}
    result = _run_tool([config.MSODDE_CMD], file_path, "msodde")
    if result['status'] == 0 and not result['output']:
        result['output'] = "No DDE links detected by msodde."
    return result

@mcp.tool()
def extract_ole_objects(file_path: str, output_dir: str, validation_error: Optional[str] = None) -> dict:
    """Extract OLE objects using OLETools (oleobj) into a specified directory."""
    if validation_error: return {"error": validation_error, "status": -1}

    # oleobj command needs -d <dir> before the file path
    command_base = [config.OLEOBJ_CMD] # file_path added by _run_tool
    result = _run_tool(command_base, file_path, "oleobj", output_dir=output_dir)

    extracted_files = []
    if result['status'] == 0:
        try:
            # List files actually created by oleobj in the temp dir
            extracted_files = [f for f in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, f))]
            if not extracted_files and not result['output']: # If tool output is empty AND no files extracted
                 result['output'] = "No OLE objects detected or extracted by oleobj."
            elif extracted_files:
                 result['output'] = (result['output'] + f"\nExtracted files: {', '.join(extracted_files)}").strip()

        except OSError as e:
            logging.error(f"[oleobj] Error listing extracted files in {output_dir}: {e}")
            result['error'] = result.get('error', '') + f" | Error listing extracted files: {e}"
            # Keep status as 0 if oleobj succeeded, but add error about listing

    result["extracted_files"] = extracted_files # Add list of filenames to result
    return result


@mcp.tool()
def combined_analysis(file_path: str) -> dict:
    """
    Run comprehensive analysis (VBA, XLM, DDE, OLE), extract IOCs, return structured results.
    """
    logging.info(f"Starting combined analysis for: {file_path}")
    overall_status = 0 # Success unless validation or a tool fails critically
    analysis_results: Dict[str, Any] = {}
    errors: List[str] = []
    iocs: Dict[str, List[str]] = {"urls": [], "ips": [], "emails": [], "hashes": [], "filepaths": []}

    # 1. Validate Input File
    validation_error = _validate_input_file(file_path)
    if validation_error:
        logging.error(f"Input validation failed for {file_path}: {validation_error}")
        return {
            "file_path": file_path,
            "analysis_summary": {},
            "iocs": iocs,
            "errors": [validation_error],
            "status": -1,
        }

    # 2. Create Temporary Directory for extractions
    try:
        with tempfile.TemporaryDirectory(prefix="ole_extract_") as temp_dir:
            logging.info(f"Created temporary directory for OLE extraction: {temp_dir}")

            # 3. Run Individual Analyses
            analysis_results["vba"] = analyze_vba_macros(file_path)
            analysis_results["xlm"] = detect_xlm_macros(file_path)
            analysis_results["dde"] = check_dde_links(file_path)
            # Pass temp_dir to oleobj analysis
            analysis_results["ole"] = extract_ole_objects(file_path, output_dir=temp_dir)

            # 4. Consolidate Results and Check for Tool Errors
            combined_output_text = "" # For IOC extraction
            for tool_name, result in analysis_results.items():
                if result.get("status", -1) != 0:
                    # Distinguish critical failure vs. non-zero exit code with output
                    # For now, any non-zero status marks overall failure for simplicity
                    overall_status = -1
                    err_msg = result.get("error", f"{tool_name} analysis failed with unknown error.")
                    errors.append(err_msg)
                    logging.warning(f"Tool '{tool_name}' failed or reported issues: {err_msg}")
                # Append successful or partially successful output for IOC scanning
                if result.get("output"):
                    combined_output_text += f"-- {tool_name.upper()} OUTPUT --\n{result.get('output')}\n\n"
                # Also scan stderr for IOCs, as some tools might report them there
                if result.get("stderr"):
                     combined_output_text += f"-- {tool_name.upper()} STDERR --\n{result.get('stderr')}\n\n"


            # 5. Extract IOCs (if iocextract is available)
            if iocextract:
                logging.info("Extracting IOCs using iocextract...")
                try:
                    # Consider scanning extracted OLE files too if feasible/safe
                    iocs["urls"] = list(iocextract.extract_urls(combined_output_text, defang=True)) # Defang helps safety
                    iocs["ips"] = list(iocextract.extract_ips(combined_output_text, defang=True))
                    iocs["emails"] = list(iocextract.extract_emails(combined_output_text, defang=True))
                    # Add hash extraction if needed
                    iocs["hashes"] = list(iocextract.extract_hashes(combined_output_text))
                    # File paths might be noisy, use with caution
                    # iocs["filepaths"] = list(iocextract.extract_filepaths(combined_output_text))
                    logging.info(f"IOCs extracted: { {k: len(v) for k, v in iocs.items()} }")
                except Exception as e:
                    logging.exception("Error during IOC extraction with iocextract.")
                    errors.append(f"IOC extraction failed: {str(e)}")
                    overall_status = -1 # Mark failure if IOC extraction crashes
            else:
                logging.warning("iocextract library not available, skipping advanced IOC extraction.")
                errors.append("IOC extraction skipped (library missing).")


    except Exception as e:
        # Catch errors related to temp dir creation/cleanup or other unexpected issues
        logging.exception(f"Critical error during combined analysis wrapper for {file_path}")
        errors.append(f"Combined analysis failed unexpectedly: {str(e)}")
        overall_status = -1


    # 6. Structure Final Result
    return {
        "file_path": file_path,
        "analysis_summary": analysis_results, # Include detailed results from each tool
        "iocs": iocs,
        "errors": errors,
        "status": overall_status # 0 if validation passed and all tools exited 0, -1 otherwise
    }

@mcp.tool()
def classify_malware(file_path: str) -> dict:
    """
    Classify the file based on combined analysis results using a scoring system.
    """
    analysis_result = combined_analysis(file_path)
    score = 0
    reasons = []
    is_malicious = False

    # If analysis itself failed, cannot classify reliably
    if analysis_result["status"] != 0:
        return {
            "file_path": file_path,
            "is_malicious": False, # Cannot determine
            "classification_score": score,
            "reasons": ["Analysis failed or incomplete, classification aborted."],
            "iocs_found": analysis_result["iocs"], # Still report any IOCs found before failure
            "errors": analysis_result["errors"],
            "status": -1
        }

    summary = analysis_result.get("analysis_summary", {})
    iocs = analysis_result.get("iocs", {})
    errors = analysis_result.get("errors", []) # Include non-fatal errors from analysis

    # --- Apply Scoring Logic ---

    # VBA Analysis (check output for keywords)
    vba_res = summary.get("vba", {})
    vba_output = vba_res.get("output", "").lower()
    if vba_res.get("status", -1) == 0: # Only score if tool succeeded
        if any(k in vba_output for k in ["autoexec", "autoopen", "workbook_open", "document_open"]):
            score += config.SCORES["VBA_AUTOEXEC"]
            reasons.append(f"VBA auto-execution keyword found (+{config.SCORES['VBA_AUTOEXEC']})")
        if "suspicious" in vba_output: # Olevba often flags suspicious indicators
            score += config.SCORES["VBA_SUSPICIOUS"]
            reasons.append(f"Olevba flagged suspicious VBA characteristics (+{config.SCORES['VBA_SUSPICIOUS']})")

    # XLM Analysis (check output for keywords)
    xlm_res = summary.get("xlm", {})
    xlm_output = xlm_res.get("output", "").lower()
    if xlm_res.get("status", -1) == 0:
        # Add keywords relevant to XLMMacroDeobfuscator or olevba's XLM detection
        xlm_keywords = ["exec(", "call(", "run(", "formulatext(", "register("]
        if any(k in xlm_output for k in xlm_keywords):
             score += config.SCORES["XLM_SUSPICIOUS_FUNC"]
             reasons.append(f"Potentially suspicious XLM function found (+{config.SCORES['XLM_SUSPICIOUS_FUNC']})")

    # DDE Analysis (check output)
    dde_res = summary.get("dde", {})
    dde_output = dde_res.get("output", "") # Case sensitive check might be better here? Check msodde output format.
    if dde_res.get("status", -1) == 0:
         # Check for explicit findings, not just headers
        if ("DDEAUTO" in dde_output or "DDE Link" in dde_output) and "0 DDE links found" not in dde_output:
            score += config.SCORES["DDE_LINK_ACTIVE"]
            reasons.append(f"Active DDE link detected (+{config.SCORES['DDE_LINK_ACTIVE']})")

    # OLE Object Analysis (check for embedded executables)
    ole_res = summary.get("ole", {})
    if ole_res.get("status", -1) == 0:
        extracted = ole_res.get("extracted_files", [])
        for fname in extracted:
            # Basic check, could be improved by checking file type of extracted obj
            if fname.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr")):
                score += config.SCORES["EMBEDDED_EXE"]
                reasons.append(f"Embedded potentially executable file '{fname}' found (+{config.SCORES['EMBEDDED_EXE']})")
                break # Score only once for embedded exe presence

    # IOC Scoring
    if iocs.get("urls"):
        count = len(iocs["urls"])
        score += config.SCORES["FOUND_URL"] * count # Simple count based score
        reasons.append(f"{count} URL(s) found (+{config.SCORES['FOUND_URL'] * count})")

    if iocs.get("ips"):
        # Filter private IPs before scoring
        public_ips = [ip for ip in iocs["ips"] if not ip.startswith(config.PRIVATE_IP_PREFIXES)]
        if public_ips:
            count = len(public_ips)
            score += config.SCORES["FOUND_IP"] * count
            reasons.append(f"{count} potentially public IP(s) found (+{config.SCORES['FOUND_IP'] * count})")

    # General Tool Warnings/Errors (even if tool exited 0, stderr might have info)
    for tool_name, result in summary.items():
        stderr_lower = result.get("stderr", "").lower()
        if result.get("status", -1) == 0 and ("warning" in stderr_lower or "error" in stderr_lower):
             # Avoid adding score if already scored specifically (e.g., VBA suspicious)
             if f"Tool '{tool_name}' reported warnings/errors" not in reasons:
                  score += config.SCORES["TOOL_WARNING"]
                  reasons.append(f"Tool '{tool_name}' reported warnings/errors in stderr (+{config.SCORES['TOOL_WARNING']})")


    # --- Final Classification ---
    is_malicious = score >= config.SCORE_THRESHOLD_MALICIOUS

    if not reasons and not errors:
        reasons.append("No specific malicious indicators found based on configured rules.")
    elif not reasons and errors:
        reasons.append("Analysis encountered non-fatal errors, but no specific malicious indicators found.")


    return {
        "file_path": file_path,
        "is_malicious": is_malicious,
        "classification_score": score,
        "score_threshold": config.SCORE_THRESHOLD_MALICIOUS,
        "reasons": reasons,
        "iocs_found": iocs,
        "errors": errors, # Pass through any analysis errors
        "status": 0 # Classification completed
    }


# --- Main Execution ---
if __name__ == "__main__":
    logging.info("Starting OLETools Secure MCP Server...")
    logging.info(f"Configuration: Timeout={config.SUBPROCESS_TIMEOUT}s, MaxFileSize={config.MAX_FILE_SIZE_BYTES}b")
    logging.info(f"Malicious Score Threshold: {config.SCORE_THRESHOLD_MALICIOUS}")
    # Note: For production, consider running MCP behind a proper web server (like Gunicorn/Uvicorn)
    # and potentially using multiple workers if using async/background tasks later.
    # Ensure sandboxing/containerization is implemented at the infrastructure level for security.
    mcp.run() # Consider host/port binding options: mcp.run(host="0.0.0.0", port=8080)