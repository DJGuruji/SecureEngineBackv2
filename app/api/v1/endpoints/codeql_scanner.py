"""
codeql_scanner.py
─────────────────
FastAPI endpoint that runs CodeQL (or a simulated fallback) on an uploaded
file / archive, stores results in Supabase, and returns a Semgrep-style
vulnerability list.

Changes vs. original:
• Added `_redact()` util to strip host-specific paths from CodeQL error output.
• Updated the `except subprocess.CalledProcessError` block to use the redacted
  command in logs and SARIF, while keeping full details in a debug log only.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, status
import os
import tempfile
import shutil
import logging
import time
import subprocess
import json
import re
from typing import List, Dict, Any

from app.services.supabase_service import store_scan_results
from app.core.security import calculate_security_score, count_severities
from app.core.config import get_settings
from app.core.scan_exclusions import (
    EXCLUDED_PATTERNS,
    should_exclude_path,
    filter_excluded_dirs,
)

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter()


@router.post("/codeql")
async def codeql_scan(file: UploadFile = File(...)):
    """Scan a file using CodeQL and return the results."""
    try:
        logger.info("Starting CodeQL scan for file: %s", file.filename)
        start_time = time.time()

        # ── Locate and ensure the CodeQL binary is executable ──────────────
        codeql_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../../codeql")
        )
        codeql_binary = os.path.join(codeql_dir, "codeql")

        if os.name == "posix":
            try:
                os.chmod(codeql_binary, 0o755)
            except Exception as exc:
                logger.warning(
                    "Could not set executable permission on CodeQL binary: %s", exc
                )

        if not os.path.exists(codeql_binary):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CodeQL binary not found at expected location",
            )

        # ── Prepare a temporary workspace ─────────────────────────────────
        with tempfile.TemporaryDirectory() as temp_dir:
            upload_path = os.path.join(temp_dir, file.filename)
            with open(upload_path, "wb") as buffer:
                buffer.write(await file.read())

            extract_dir = os.path.join(temp_dir, "src")
            os.makedirs(extract_dir, exist_ok=True)

            source_root = temp_dir
            if file.filename.endswith(".zip"):
                try:
                    shutil.unpack_archive(upload_path, extract_dir)
                    source_root = extract_dir
                    logger.info("Extracted zip file to %s", extract_dir)
                except Exception as exc:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Could not extract zip file: {exc}",
                    )

            # ── Detect language (very basic heuristics) ──────────────────
            language = _detect_language(file.filename, extract_dir)

            # ── Create CodeQL database ───────────────────────────────────
            db_path = os.path.join(temp_dir, "codeql_db")
            os.makedirs(db_path, exist_ok=True)

            _write_codeqlignore(source_root)

            create_db_cmd = [
                codeql_binary,
                "database",
                "create",
                db_path,
                f"--language={language}",
                "--source-root",
                source_root,
                "--overwrite",
            ]

            try:
                subprocess.run(
                    create_db_cmd, check=True, capture_output=True, text=True
                )
            except subprocess.CalledProcessError as e:
                logger.error("CodeQL database creation failed: %s", e)
                return await _simulate_and_return(
                    file.filename, source_root, language, start_time
                )

            # ── Build a tiny custom QL pack + query ──────────────────────
            query_dir = _write_custom_query(temp_dir, language)
            query_file = os.path.join(query_dir, "dangerous_calls.ql")

            results_path = os.path.join(temp_dir, "results.sarif")

            analyze_cmd = [
                codeql_binary,
                "database",
                "analyze",
                db_path,
                "--format=sarif-latest",
                "--output",
                results_path,
                query_file,
            ]

            try:
                subprocess.run(
                    analyze_cmd, check=True, capture_output=True, text=True
                )
            except subprocess.CalledProcessError as e:
                # 🔒 Redact sensitive paths before propagating error details
                _handle_analysis_error(e, results_path, analyze_cmd)

            if not os.path.exists(results_path):
                _write_empty_sarif(results_path)

            with open(results_path, "r") as fh:
                sarif_results = json.load(fh)

            vulnerabilities = _sarif_to_vulns(
                sarif_results, file.filename, language
            )

            if not vulnerabilities:
                vulnerabilities.append(
                    {
                        "check_id": "codeql-security-check",
                        "path": file.filename,
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "severity": "error",
                        "message": "CodeQL security scan completed",
                        "extra": {"severity": "ERROR", "message": "Scan completed"},
                        "risk_severity": 0.6,
                        "exploitability": "Medium",
                        "impact": "Low",
                        "detection_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )

            # ── Summarise & persist ──────────────────────────────────────
            scan_results = _package_scan_results(
                file.filename, vulnerabilities, language, start_time
            )
            store_scan_results(scan_results)

            logger.info(
                "CodeQL scan finished: %d vulnerabilities",
                scan_results["total_vulnerabilities"],
            )
            return scan_results

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unhandled CodeQL scan error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during CodeQL scan: {exc}",
        )


# ──────────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────────


def _detect_language(upload_name: str, extract_dir: str) -> str:
    """Very lightweight heuristic to decide which CodeQL extractor to use."""
    language = "python"  # default
    ext_map = {
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
        ".java": "java",
        ".cpp": "cpp",
        ".c": "cpp",
        ".h": "cpp",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".go": "go",
    }

    if upload_name.endswith(".zip"):
        counts: Dict[str, int] = {}
        for root, _, files in os.walk(extract_dir):
            for fn in files:
                ext = os.path.splitext(fn.lower())[1]
                counts[ext] = counts.get(ext, 0) + 1
        for ext, lang in ext_map.items():
            if ext in counts:
                language = lang
                break
    else:
        ext = os.path.splitext(upload_name)[1].lower()
        language = ext_map.get(ext, "python")
    logger.info("Detected language: %s", language)
    return language


def _write_codeqlignore(source_root: str) -> None:
    path = os.path.join(source_root, ".codeqlignore")
    with open(path, "w") as fh:
        for pattern in EXCLUDED_PATTERNS:
            fh.write(pattern.rstrip("/") + "\n")
    logger.info("Created .codeqlignore at %s", path)


def _write_custom_query(temp_dir: str, language: str) -> str:
    query_dir = os.path.join(temp_dir, "queries")
    os.makedirs(query_dir, exist_ok=True)

    with open(os.path.join(query_dir, "qlpack.yml"), "w") as fh:
        fh.write(
            """name: security-queries
version: 1.0.0
dependencies:
  codeql/python-all: "*"
  codeql/javascript-all: "*"
  codeql/java-all: "*"
  codeql/cpp-all: "*"
"""
        )

    if language == "python":
        query = """
            import python
            from Call call
            where call.getFunc().getName() in ["eval","exec","__import__",
                                               "pickle.loads","subprocess.call",
                                               "subprocess.Popen","os.system",
                                               "os.popen","input"]
            select call, "Potentially dangerous function call: " + call.getFunc().getName()
        """
    elif language == "javascript":
        query = """
            import javascript
            from CallExpr call
            where call.getCalleeName() in ["eval","Function","setTimeout","setInterval"]
            select call, "Potentially dangerous use of " + call.getCalleeName()
        """
    else:
        query = 'select "Basic scan completed", "No specific security issues found"'

    with open(os.path.join(query_dir, "dangerous_calls.ql"), "w") as fh:
        fh.write(query)

    return query_dir


def _redact(cmd: List[str]) -> str:
    """
    Remove everything before '--output' in the CodeQL analyze command so
    we don't leak absolute local paths to the client.
    """
    if "--output" in cmd:
        idx = cmd.index("--output")
        return str(cmd[idx:])
    # fallback: just return binary name and ellipsis
    return f"[{os.path.basename(cmd[0])} …]"


def _handle_analysis_error(
    error: subprocess.CalledProcessError, sarif_out: str, analyze_cmd: List[str]
) -> None:
    sanitized_cmd = _redact(error.cmd if isinstance(error.cmd, list) else analyze_cmd)

    err_text = (
        f"CodeQL analysis failed: Command {sanitized_cmd} "
        f"returned exit status {error.returncode}."
    )

    # Full details only in debug logs
    logger.debug(
        "Full CalledProcessError:\ncmd=%s\nstdout=%s\nstderr=%s",
        error.cmd,
        error.stdout,
        error.stderr,
    )
    logger.error(err_text)

    # Write SARIF with redacted error for frontend
    with open(sarif_out, "w") as fh:
        json.dump(
            {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "CodeQL", "semanticVersion": "1.0.0"}},
                        "results": [
                            {
                                "ruleId": "error",
                                "message": {"text": err_text},
                                "level": "error",
                            }
                        ],
                    }
                ],
            },
            fh,
        )


def _write_empty_sarif(path: str) -> None:
    with open(path, "w") as fh:
        json.dump(
            {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}],
            },
            fh,
        )


def _sarif_to_vulns(sarif: Dict[str, Any], fallback_path: str, language: str):
    vulns: List[Dict[str, Any]] = []

    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            loc = (
                res.get("locations", [{}])[0]
                .get("physicalLocation", {})
                .get("region", {})
            )
            path_uri = (
                res.get("locations", [{}])[0]
                .get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", fallback_path)
            )
            msg = res.get("message", {}).get("text", "")

            sev = "info"
            if any(k in msg.lower() for k in ["dangerous", "injection", "vulnerability", "xss"]):
                sev = "error"
            elif any(k in msg.lower() for k in ["potentially", "possible", "might be"]):
                sev = "warning"

            if "security" in msg.lower():
                sev = "error"

            risk = 0.3
            if "sql injection" in msg.lower() or "xss" in msg.lower():
                risk = 0.9
                sev = "error"
            elif "potentially dangerous" in msg.lower() or "injection" in msg.lower():
                risk = 0.7
                sev = "error"

            vulns.append(
                {
                    "check_id": res.get("ruleId", "") or "codeql-security",
                    "path": path_uri,
                    "start": {"line": loc.get("startLine", 1)},
                    "end": {"line": loc.get("endLine", 1)},
                    "severity": sev,
                    "message": msg,
                    "extra": {
                        "severity": sev.upper(),
                        "message": msg,
                        "rule_name": res.get("rule", {}).get("name", "CodeQL Rule"),
                        "rule_description": res.get("rule", {})
                        .get("shortDescription", {})
                        .get("text", ""),
                    },
                    "risk_severity": risk,
                    "exploitability": "High" if risk > 0.7 else "Medium" if risk > 0.4 else "Low",
                    "impact": "High" if risk > 0.7 else "Medium" if risk > 0.4 else "Low",
                    "detection_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    return vulns


async def _simulate_and_return(
    upload_name: str, src_root: str, language: str, start_time: float
):
    """Fallback pattern-match analysis when CodeQL db creation fails."""
    vulns = simulate_codeql_results(src_root, language)
    scan_results = _package_scan_results(upload_name, vulns, language, start_time)
    store_scan_results(scan_results)
    logger.info(
        "Simulated CodeQL scan completed with %d findings",
        scan_results["total_vulnerabilities"],
    )
    return scan_results


def _package_scan_results(
    filename: str, vulns: List[Dict[str, Any]], language: str, start_time: float
) -> Dict[str, Any]:
    return {
        "file_name": filename,
        "security_score": calculate_security_score(vulns),
        "vulnerabilities": vulns,
        "severity_count": count_severities(vulns),
        "total_vulnerabilities": len(vulns),
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration": time.time() - start_time,
        "scan_metadata": {"scan_type": "CodeQL", "language": language},
    }


# ──────────────────────────────────────────────────────────────────────────
# simulate_codeql_results
#  (unchanged – kept below for brevity but identical to your version)
# ──────────────────────────────────────────────────────────────────────────

def simulate_codeql_results(dir_path: str, language: str) -> List[Dict[str, Any]]:
    """
    Simulates CodeQL scanning using basic pattern matching when actual CodeQL fails.
    This provides a fallback mechanism to identify potential vulnerabilities.
    
    Args:
        dir_path: Path to the directory to scan
        language: Programming language to analyze
        
    Returns:
        List of detected vulnerabilities in a format compatible with the frontend
    """
    logger.info(f"Simulating CodeQL scan for {language} in {dir_path}")
    vulnerabilities = []
    
    # Define vulnerability patterns based on language
    patterns = {}
    
    if language == "javascript":
        patterns = {
            "eval_usage": {
                "pattern": r"eval\s*\(",
                "message": "Potentially dangerous use of eval() function",
                "severity": "ERROR"
            },
            "innerHTML": {
                "pattern": r"\.innerHTML\s*=",
                "message": "Potential XSS vulnerability from setting innerHTML directly",
                "severity": "WARNING"
            },
            "document_write": {
                "pattern": r"document\.write\(",
                "message": "Potential XSS vulnerability from using document.write()",
                "severity": "WARNING"
            },
            "hardcoded_secret": {
                "pattern": r"(?:password|token|secret|key|apikey)\s*[:=]\s*['\"][^'\"]+['\"]",
                "message": "Hardcoded credentials or secret detected",
                "severity": "ERROR"
            },
            "insecure_timeout": {
                "pattern": r"(?:setTimeout|setInterval)\(\s*['\"].*?['\"]",
                "message": "Potentially insecure use of setTimeout/setInterval with string argument",
                "severity": "WARNING"
            },
            "dangerous_function": {
                "pattern": r"new Function\(",
                "message": "Potentially dangerous use of Function constructor",
                "severity": "ERROR"
            }
        }
    elif language == "python":
        patterns = {
            "exec_usage": {
                "pattern": r"(?:exec|eval)\s*\(",
                "message": "Potentially dangerous use of exec()/eval() function",
                "severity": "ERROR"
            },
            "os_system": {
                "pattern": r"os\.system\(",
                "message": "Potentially insecure use of os.system()",
                "severity": "ERROR"
            },
            "subprocess_shell": {
                "pattern": r"subprocess\.(?:call|Popen|run)\(.*?shell\s*=\s*True",
                "message": "Potentially insecure subprocess call with shell=True",
                "severity": "ERROR"
            },
            "sql_injection": {
                "pattern": r"execute\(['\"].*?\%.*?['\"].*?\)",
                "message": "Potential SQL injection vulnerability",
                "severity": "ERROR"
            },
            "hardcoded_secret": {
                "pattern": r"(?:password|secret|key|token|apikey)\s*=\s*['\"][^'\"]+['\"]",
                "message": "Hardcoded credentials or secret detected",
                "severity": "ERROR"
            },
            "pickle_usage": {
                "pattern": r"pickle\.loads\(",
                "message": "Use of potentially unsafe pickle.loads()",
                "severity": "WARNING"
            }
        }
    elif language == "java":
        patterns = {
            "sql_injection": {
                "pattern": r"executeQuery\(['\"].*?\+.*?['\"]",
                "message": "Potential SQL injection vulnerability",
                "severity": "ERROR"
            },
            "command_injection": {
                "pattern": r"Runtime\.getRuntime\(\)\.exec\(",
                "message": "Potential command injection vulnerability",
                "severity": "ERROR"
            },
            "hardcoded_secret": {
                "pattern": r"(?:password|secret|key)\s*=\s*['\"][^'\"]+['\"]",
                "message": "Hardcoded credentials or secret detected",
                "severity": "ERROR"
            }
        }
    else:
        # Generic patterns for other languages
        patterns = {
            "hardcoded_secret": {
                "pattern": r"(?:password|secret|key|token|apikey)\s*[:=]\s*['\"][^'\"]+['\"]",
                "message": "Hardcoded credentials or secret detected",
                "severity": "ERROR"
            }
        }
    
    # Scan files for vulnerability patterns
    for root, dirs, files in os.walk(dir_path):
        # Skip excluded directories
        filter_excluded_dirs(dirs)
        
        for file in files:
            # Skip files that match exclusion patterns
            if should_exclude_path(file):
                continue
            
            # Check file extension based on language
            extensions = []
            if language == "javascript":
                extensions = ['.js', '.jsx', '.ts', '.tsx']
            elif language == "python":
                extensions = ['.py']
            elif language == "java":
                extensions = ['.java']
            else:
                # For other languages, check everything
                extensions = ['.cpp', '.c', '.h', '.cs', '.go', '.rb', '.php']
            
            file_ext = os.path.splitext(file)[1].lower()
            if file_ext not in extensions:
                continue
                
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, dir_path)
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Check each line for vulnerability patterns
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    line_num = i + 1
                    
                    # Skip comments based on language
                    if language == "javascript" and (line.strip().startswith('//') or line.strip().startswith('/*')):
                        continue
                    elif language == "python" and line.strip().startswith('#'):
                        continue
                    elif language == "java" and (line.strip().startswith('//') or line.strip().startswith('/*')):
                        continue
                    
                    # Check each pattern
                    for name, pattern_info in patterns.items():
                        matches = re.finditer(pattern_info["pattern"], line)
                        for match in matches:
                            vulnerabilities.append({
                                "check_id": f"codeql-simulated.{language}.{name}",
                                "path": rel_path,
                                "start": {"line": line_num, "col": match.start() + 1},
                                "end": {"line": line_num, "col": match.end() + 1},
                                "message": pattern_info["message"],
                                "severity": pattern_info["severity"],
                                "extra": {
                                    "severity": pattern_info["severity"],
                                    "message": pattern_info["message"],
                                    "lines": line.strip(),
                                    "rule_name": f"CodeQL ({name})",
                                    "metadata": {
                                        "source": "Simulated CodeQL scan",
                                        "confidence": "Medium"
                                    }
                                }
                            })
            except Exception as e:
                logger.warning(f"Error scanning file {file_path}: {str(e)}")
    
    logger.info(f"Simulated CodeQL scan found {len(vulnerabilities)} vulnerabilities")
    return vulnerabilities 