"""
chatgpt_service.py
------------------
Static-analysis helper that sends code to OpenAI Chat Completions
and normalises the result into Semgrep-style findings.
"""
from __future__ import annotations

import os
import json
import logging
import tempfile
import shutil
import zipfile
import re
from typing import Dict, Any, List, Tuple, Optional, NamedTuple
import math
import asyncio
from dataclasses import dataclass
from fastapi import HTTPException, status
import time
from datetime import datetime, timezone

import openai
from app.config import settings
from .architecture_analyzer import analyze_architecture
from app.core.scan_exclusions import should_exclude_path
from app.core.security import calculate_security_score, count_severities

logger = logging.getLogger(__name__)

# Initialize OpenAI client
openai.api_key = settings.chatgpt_api_key

# Constants for chunking
CHUNK_SIZE = 2000  # Number of lines per chunk
OVERLAP_SIZE = 100  # Number of lines to overlap between chunks
MAX_PARALLEL_CHUNKS = 5  # Maximum number of chunks to process in parallel

# Load security rules
with open(os.path.join(os.path.dirname(__file__), '../rules/security_rules.json')) as f:
    SECURITY_RULES = json.load(f)

# Hardcoded system message for AI SAST
SYSTEM_MSG = """
You are a static application security tester. Your task is to analyze code for security vulnerabilities and quality issues.
Focus on identifying these critical security issues:

1. CRITICAL SECURITY VULNERABILITIES:
   - SQL Injection (CWE-89)
   - Command Injection (CWE-78)
   - Cross-site Scripting (CWE-79)
   - Path Traversal (CWE-22)
   - File Inclusion (CWE-98)
   - Hardcoded Credentials (CWE-259)
   - Buffer Overflows (CWE-120)
   - Format String Vulnerabilities (CWE-134)
   - Race Conditions (CWE-362)

2. CODE QUALITY ISSUES:
   - God Class (over 500 LOC)
   - Long Methods (over 50 LOC)
   - Inefficient Loops
   - Blocking Operations
   - Poor Error Handling

For each issue found, you MUST provide:
1. Exact line number where the vulnerability exists
2. Detailed explanation of the vulnerability
3. Severity level (high/medium/low)
4. CWE ID if applicable
5. Code snippet showing the vulnerability
6. Specific recommendations to fix the issue

Return findings in this JSON format:
{
    "vulnerabilities": [
        {
            "check_id": "rule_id",
            "path": "file_path",
            "start": {"line": line_number, "col": col_number},
            "end": {"line": line_number, "col": col_number},
            "message": "detailed_message",
            "severity": "error|warning|info",
            "extra": {
                "metadata": {
                    "cwe": "CWE-ID",
                    "owasp": "OWASP Category",
                    "category": "Security|Architecture|Performance"
                },
                "lines": "affected_code",
                "score": risk_score
            }
        }
    ]
}

IMPORTANT INSTRUCTIONS:
1. Be thorough - analyze EVERY line of code
2. Report ALL potential vulnerabilities, even if you're not 100% certain
3. Provide detailed explanations for each finding
4. Focus on security implications of the code
5. Consider the context and potential attack vectors
"""

@dataclass
class CodeChunk:
    """Represents a chunk of code from one or more files."""
    files: List[Tuple[str, List[int]]]  # List of (file_path, line_numbers) tuples
    content: str
    chunk_num: int
    total_chunks: int

async def _analyze_chunk(chunk: CodeChunk) -> List[Dict[str, Any]]:
    """Analyze a chunk of code that may span multiple files."""
    vulnerabilities = []
    
    # Prepare the user message with chunk context
    files_info = "\n".join([
        f"- {path}: lines {lines[0]}-{lines[-1]}"
        for path, lines in chunk.files
    ])
    
    user_msg = f"""
    Please analyze this code chunk for security vulnerabilities and code quality issues.
    Pay special attention to any potential security vulnerabilities.
    
    Files in this chunk:
    {files_info}
    Chunk: {chunk.chunk_num} of {chunk.total_chunks}
    
    ```
    {chunk.content}
    ```
    
    For each vulnerability found, you MUST provide:
    1. Exact line number where the vulnerability exists
    2. Detailed explanation of the vulnerability and its impact
    3. Severity level (high/medium/low)
    4. CWE ID if applicable
    5. Code snippet showing the vulnerability
    6. SPECIFIC remediation steps to fix the issue - be detailed and practical
    
    Analyze the code thoroughly and report ALL potential security issues, no matter how minor they might seem.
    Report the exact file and line number for each vulnerability found.
    """
    
    try:
        response = await openai.ChatCompletion.acreate(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": SYSTEM_MSG},
                {"role": "user", "content": user_msg}
            ],
            temperature=settings.openai_temperature,
            max_tokens=4000
        )
        
        # Parse the response
        if response.choices and response.choices[0].message.content:
            try:
                result = json.loads(response.choices[0].message.content)
                if "vulnerabilities" in result:
                    # Map the findings back to correct files and line numbers
                    for vuln in result["vulnerabilities"]:
                        # Find the correct file and adjust line numbers
                        for file_path, line_numbers in chunk.files:
                            if vuln.get("path") == file_path:
                                if "start" in vuln:
                                    relative_line = vuln["start"]["line"]
                                    if 0 <= relative_line < len(line_numbers):
                                        vuln["start"]["line"] = line_numbers[relative_line]
                                if "end" in vuln:
                                    relative_line = vuln["end"]["line"]
                                    if 0 <= relative_line < len(line_numbers):
                                        vuln["end"]["line"] = line_numbers[relative_line]
                                
                                # Ensure remediation is included
                                if not vuln.get("remediation"):
                                    vuln["remediation"] = generate_remediation_guidance(vuln)
                                
                                vulnerabilities.extend(result["vulnerabilities"])
                else:
                    logger.warning(f"No vulnerabilities found in chunk {chunk.chunk_num}")
            except json.JSONDecodeError:
                logger.error(f"Failed to parse ChatGPT response as JSON for chunk {chunk.chunk_num}")
                
    except Exception as e:
        logger.error(f"Error calling ChatGPT API for chunk {chunk.chunk_num}: {str(e)}")
        
    return vulnerabilities

def generate_remediation_guidance(vuln: Dict[str, Any]) -> str:
    """Generate detailed remediation guidance based on vulnerability type."""
    cwe = vuln.get("cwe", "")
    vuln_type = vuln.get("type", "").lower()
    severity = vuln.get("severity", "").lower()
    
    # Base remediation template
    base_remediation = """To fix this vulnerability:

1. {primary_action}
2. {secondary_action}
3. {validation_step}
4. {testing_step}
5. {monitoring_step}"""
    
    # Remediation mappings
    remediation_map = {
        "sql injection": {
            "primary_action": "Use parameterized queries or prepared statements instead of string concatenation",
            "secondary_action": "Implement input validation and sanitization for all user inputs",
            "validation_step": "Apply proper escaping for special characters",
            "testing_step": "Test with various malicious SQL injection payloads",
            "monitoring_step": "Monitor database query logs for suspicious patterns"
        },
        "xss": {
            "primary_action": "Use context-aware output encoding for all user-supplied data",
            "secondary_action": "Implement Content Security Policy (CSP) headers",
            "validation_step": "Validate and sanitize all user inputs",
            "testing_step": "Test with various XSS payloads",
            "monitoring_step": "Monitor for XSS attempts in application logs"
        },
        "command injection": {
            "primary_action": "Use safe APIs instead of direct command execution",
            "secondary_action": "Implement strict input validation and whitelisting",
            "validation_step": "Escape special shell characters",
            "testing_step": "Test with various command injection payloads",
            "monitoring_step": "Monitor system command execution logs"
        },
        "default": {
            "primary_action": "Review and fix the identified security issue",
            "secondary_action": "Implement proper input validation and sanitization",
            "validation_step": "Add appropriate security controls",
            "testing_step": "Test the fix thoroughly",
            "monitoring_step": "Monitor for security events"
        }
    }
    
    # Get remediation details based on vulnerability type
    remediation_details = remediation_map.get("default")
    for key, value in remediation_map.items():
        if key in vuln_type:
            remediation_details = value
            break
    
    # Format the remediation guidance
    remediation = base_remediation.format(**remediation_details)
    
    # Add CWE-specific guidance if available
    if cwe:
        cwe_guidance = get_cwe_remediation_guidance(cwe)
        if cwe_guidance:
            remediation += f"\n\nCWE-{cwe} Additional Guidance:\n{cwe_guidance}"
    
    return remediation

def get_cwe_remediation_guidance(cwe: str) -> str:
    """Get CWE-specific remediation guidance."""
    cwe_guidance = {
        "78": """- Use secure APIs that don't require command shell
- If shell is required, strictly validate and sanitize all inputs
- Consider using a whitelist of allowed commands
- Run with minimal privileges""",
        "89": """- Use parameterized queries or ORMs
- Validate all SQL inputs
- Use prepared statements
- Implement least privilege database access""",
        "79": """- Use proper output encoding
- Implement CSP headers
- Validate all inputs
- Use modern framework's built-in XSS protection""",
        "200": """- Use proper error handling
- Don't expose sensitive information in errors
- Implement custom error pages
- Log errors securely""",
        "287": """- Implement strong authentication
- Use secure session management
- Add multi-factor authentication
- Regular security audits"""
    }
    
    return cwe_guidance.get(cwe, "")

async def _analyse_files_with_chatgpt(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """Submit code to ChatGPT and parse the response."""
    all_vulnerabilities = []
    
    # First, prepare all lines from all files
    all_lines = []  # List of (file_path, line_number, content) tuples
    for file_path, content in files.items():
        if len(content) > settings.max_file_size:
            logger.warning(f"File {file_path} is too large for analysis ({len(content)} bytes)")
            continue
        
        lines = content.splitlines()
        all_lines.extend((file_path, i + 1, line) for i, line in enumerate(lines))
    
    total_lines = len(all_lines)
    num_chunks = math.ceil(total_lines / (CHUNK_SIZE - OVERLAP_SIZE))
    
    # Prepare chunks that may span multiple files
    chunk_tasks = []
    for i in range(num_chunks):
        start_idx = i * (CHUNK_SIZE - OVERLAP_SIZE)
        end_idx = min(start_idx + CHUNK_SIZE, total_lines)
        
        # Get the lines for this chunk
        chunk_lines = all_lines[start_idx:end_idx]
        
        # Group lines by file
        files_in_chunk = {}
        for file_path, line_num, line_content in chunk_lines:
            if file_path not in files_in_chunk:
                files_in_chunk[file_path] = ([], [])  # (line_numbers, line_contents)
            files_in_chunk[file_path][0].append(line_num)
            files_in_chunk[file_path][1].append(line_content)
        
        # Create the chunk content with file markers
        chunk_content_parts = []
        files_info = []
        for file_path, (line_numbers, line_contents) in files_in_chunk.items():
            chunk_content_parts.append(f"\n# File: {file_path}\n")
            chunk_content_parts.extend(line_contents)
            files_info.append((file_path, line_numbers))
        
        chunk = CodeChunk(
            files=files_info,
            content="\n".join(chunk_content_parts),
            chunk_num=i + 1,
            total_chunks=num_chunks
        )
        
        # Create task for chunk analysis
        task = _analyze_chunk(chunk)
        chunk_tasks.append(task)
    
    # Process chunks in parallel with rate limiting
    chunk_vulnerabilities = []
    for i in range(0, len(chunk_tasks), MAX_PARALLEL_CHUNKS):
        batch = chunk_tasks[i:i + MAX_PARALLEL_CHUNKS]
        batch_results = await asyncio.gather(*batch)
        for result in batch_results:
            chunk_vulnerabilities.extend(result)
    
    # Deduplicate vulnerabilities from overlapping chunks
    seen = set()
    deduplicated_vulns = []
    for vuln in chunk_vulnerabilities:
        # Create a key based on the vulnerability's essential properties
        key = (
            vuln["check_id"],
            vuln["path"],
            vuln["start"]["line"],
            vuln["message"]
        )
        if key not in seen:
            seen.add(key)
            deduplicated_vulns.append(vuln)
    
    return deduplicated_vulns

# ──────────────────────────────────────────────────────────────────────────
#  Public entry point
# ──────────────────────────────────────────────────────────────────────────
async def scan_code_with_chatgpt(file_path: str) -> Dict[str, Any]:
    """
    Expand archives (if needed), read code files, submit them to ChatGPT,
    and return a vulnerability report in the same schema used previously.
    """
    logger.info("ChatGPT scan started for %s", file_path)

    # 1️⃣ Extract *.zip if supplied
    extracted_path, temp_dir = _prepare_source(file_path)

    try:
        file_contents, logical_paths = _get_file_contents(extracted_path)
        if not file_contents:
            raise ValueError("No code files found to analyse")

        # Get vulnerabilities from different analyzers
        chatgpt_vulns = []
        try:
            chatgpt_vulns = await _analyse_files_with_chatgpt(file_contents)
        except Exception as e:
            logger.error(f"ChatGPT analysis failed: {str(e)}")
            # Don't fail the entire scan if ChatGPT fails
            
        # If ChatGPT analysis failed or found no vulnerabilities, use simple pattern fallback
        if not chatgpt_vulns:
            logger.info("ChatGPT analysis produced no results, using pattern fallback")
            chatgpt_vulns = _pattern_fallback(file_contents)
        
        # Always run architecture analysis
        arch_vulns = analyze_architecture(file_contents)
        
        # Combine all vulnerabilities
        vulnerabilities = chatgpt_vulns + arch_vulns

        total = len(vulnerabilities)
        severity_count = _count_by_severity(vulnerabilities)
        security_score = _calculate_security_score(vulnerabilities)

        return {
            "file_name": os.path.basename(file_path),
            "security_score": security_score,
            "vulnerabilities": vulnerabilities,
            "severity_count": severity_count,
            "total_vulnerabilities": total,
            "scan_metadata": {
                "scan_type": "AI",
                "scan_mode": "chatgpt",
                "analyzers": ["chatgpt", "pattern", "architecture"],
                "success": len(chatgpt_vulns) > 0  # Indicate if any vulnerabilities were found
            },
        }

    finally:
        # Clean-up any temp extraction
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────
def _prepare_source(file_path: str) -> Tuple[str, str | None]:
    """If *file_path* is a .zip, extract it and return new path + temp dir."""
    if os.path.isfile(file_path) and file_path.endswith(".zip"):
        temp_dir = tempfile.mkdtemp()
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall(temp_dir)
        return temp_dir, temp_dir
    return file_path, None


def _get_file_contents(path: str) -> Tuple[Dict[str, str], List[str]]:
    """Recursively read code files, skipping exclusions, return {path:code}."""
    contents: Dict[str, str] = {}
    logical: List[str] = []

    if os.path.isfile(path):
        _maybe_add_file(path, contents, logical)
    else:
        for root, dirs, files in os.walk(path):
            # prune excluded dirs
            dirs[:] = [d for d in dirs if not should_exclude_path(os.path.join(root, d))]
            for f in files:
                _maybe_add_file(os.path.join(root, f), contents, logical, root)

    logger.info("Collected %d source files for ChatGPT", len(contents))
    return contents, logical


def _maybe_add_file(
    file_path: str,
    contents: Dict[str, str],
    logical: List[str],
    base: str | None = None,
):
    if should_exclude_path(file_path):
        return
    _, ext = os.path.splitext(file_path)
    if ext in settings.code_file_extensions:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
                if len(content) > settings.max_file_size:
                    logger.warning("Skipping %s – too large for analysis", file_path)
                    return
                rel = os.path.relpath(file_path, base or os.path.dirname(file_path))
                contents[rel] = content
                logical.append(rel)
        except Exception as err:  # pragma: no cover
            logger.warning("Cannot read %s – %s", file_path, err)


# ──────────────────────────────────────────────────────────────────────────
#  Very small regex fallback if ChatGPT returns nothing
# ──────────────────────────────────────────────────────────────────────────
def _pattern_fallback(files: Dict[str, str]) -> List[Dict[str, Any]]:
    patterns = [
        ("exec(", "Command execution", "ERROR", 8),
        ("eval(", "Arbitrary code execution", "ERROR", 9),
        ("password =", "Hard-coded credential", "WARNING", 6),
        ("SELECT * FROM", "Possible SQL injection", "WARNING", 5),
        ("innerHTML", "Potential XSS", "WARNING", 6),
        ("http://", "Unencrypted HTTP", "INFO", 3),
        ("admin", "Privileged term", "INFO", 2),
    ]
    vulns: List[Dict[str, Any]] = []
    for path, content in list(files.items())[:3]:  # sample few files
        for idx, line in enumerate(content.splitlines(), 1):
            for pat, msg, sev, sc in patterns:
                if pat in line:
                    vulns.append(
                        {
                            "check_id": f"ai.security.{pat.strip('(').strip()}",  # simple slug
                            "path": path,
                            "start": {"line": idx, "col": 1},
                            "end": {"line": idx + 1, "col": 1},
                            "extra": {
                                "severity": sev,
                                "metadata": {"category": "Security", "score": sc},
                                "message": f"{msg}: {line.strip()}",
                                "lines": line.strip(),
                                "score": sc,
                            },
                            "severity": sev.lower(),
                        }
                    )
    return vulns


# ──────────────────────────────────────────────────────────────────────────
#  Scoring helpers
# ──────────────────────────────────────────────────────────────────────────
def _count_by_severity(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count vulnerabilities by severity level."""
    # Initialize with all severity levels
    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    
    for vuln in vulns:
        # Get severity from either the root level or extra.severity
        severity = vuln.get("severity", "").upper()
        if not severity:
            severity = vuln.get("extra", {}).get("severity", "INFO").upper()
            
        # Normalize severity
        if severity in ["CRITICAL", "HIGH"]:
            severity = "ERROR"
        elif severity in ["MEDIUM", "MODERATE"]:
            severity = "WARNING"
        elif severity not in ["ERROR", "WARNING", "INFO"]:
            severity = "INFO"
            
        counts[severity] += 1
    
    logger.info(f"Counted vulnerabilities by severity: {counts}")
    return counts


def _calculate_security_score(vulns: List[Dict[str, Any]]) -> float:
    counts = _count_by_severity(vulns)
    score = 10.0 - (
        counts["ERROR"] * 2.0 + counts["WARNING"] * 1.0 + counts["INFO"] * 0.4
    )
    return max(1, int(round(score)))

def normalize_severity(severity: str) -> str:
    """Normalize severity levels to our three-level system."""
    severity = severity.upper()
    if severity in ['CRITICAL', 'HIGH']:
        return 'ERROR'
    elif severity in ['MEDIUM', 'MODERATE']:
        return 'WARNING'
    return 'INFO'

def process_vulnerability(vuln: Dict[str, Any], file_name: str) -> Dict[str, Any]:
    """Process and normalize a vulnerability entry."""
    # Normalize severity
    severity = normalize_severity(vuln.get('severity', 'medium'))
    
    # Get or generate description
    description = vuln.get('description', '')
    if not description and vuln.get('message'):
        description = f"""This vulnerability was detected in the code and represents a {severity.lower()} severity security issue.
The issue is related to {vuln.get('message')}.
Impact: This could potentially lead to security breaches if exploited.""".strip()
    
    # Get or generate remediation guidance based on vulnerability type
    check_id = vuln.get('check_id', '').lower()
    message = (vuln.get('message', '') or vuln.get('extra', {}).get('message', '')).lower()
    
    # Generate remediation based on vulnerability type
    remediation = ''
    if 'sql injection' in message or 'sql-injection' in check_id:
        remediation = """Use parameterized queries or prepared statements instead of string concatenation for SQL queries. 
If using an ORM, ensure you're not using raw query methods with user input. 
Always validate and sanitize user input before using it in database operations."""
    elif 'xss' in message or 'xss' in check_id:
        remediation = """Sanitize and validate all user input before displaying it in HTML context. 
Use context-appropriate encoding (HTML, JavaScript, CSS, URL) when displaying user-controlled data. 
Consider using a Content Security Policy (CSP) as an additional layer of defense."""
    elif 'command injection' in message or 'command-injection' in check_id:
        remediation = """Avoid using shell commands with user input whenever possible. 
If necessary, use allowlists for permitted commands and arguments, and properly escape all user-provided inputs. 
Consider using language-specific APIs for the functionality instead of shell commands."""
    elif 'path traversal' in message or 'path-traversal' in check_id:
        remediation = """Validate and sanitize file paths provided by users. 
Use absolute paths with a whitelist of allowed directories. 
Normalize paths to remove ".." sequences before validation. 
Consider using a library designed for safe file operations."""
    elif 'hardcoded' in message or 'hardcoded' in check_id:
        remediation = """Remove hardcoded credentials from the code. 
Use a secure configuration management system or environment variables to store sensitive values. 
Consider using a secrets management service for production deployments."""
    elif 'ssrf' in message or 'ssrf' in check_id:
        remediation = """Implement strict URL validation using a whitelist of allowed domains, protocols, and ports. 
Avoid using user-controlled input in URL-fetching functions. 
Consider using a dedicated SSRF prevention library."""
    elif 'deserialization' in message or 'deserial' in check_id:
        remediation = """Never deserialize untrusted data. 
If deserialization is necessary, use safer alternatives like JSON or implement integrity checks. 
Run deserialization code with minimal privileges and in a sandbox if possible."""
    elif any(term in message for term in ['crypto', 'encrypt', 'cipher']):
        remediation = """Use established cryptographic libraries and avoid implementing custom cryptographic algorithms. 
Ensure you are using strong encryption algorithms with proper key sizes and secure modes of operation."""
    elif 'csrf' in message or 'csrf' in check_id:
        remediation = """Implement anti-CSRF tokens in all forms and require them for all state-changing operations. 
Verify the origin of requests using strict same-origin policies. 
Use SameSite cookie attributes."""
    elif 'auth' in message or 'password' in message or 'auth' in check_id:
        remediation = """Implement strong password policies, multi-factor authentication, and rate limiting for authentication attempts. 
Use secure, standard authentication frameworks instead of custom implementations."""
    elif 'cors' in message or 'cors' in check_id:
        remediation = """Restrict cross-origin resource sharing (CORS) to trusted domains only. 
Avoid using wildcard origins in production. 
Be careful with Access-Control-Allow-Credentials and ensure it's only used with specific origins."""
    else:
        # Default remediation based on severity
        if severity == 'ERROR':
            remediation = """This is a high-severity issue that requires immediate attention. 
Review the code for security issues related to the reported vulnerability and implement proper input validation, 
output encoding, and strong access controls."""
        elif severity == 'WARNING':
            remediation = """This is a medium-severity issue that should be addressed. 
Implement appropriate security controls including data validation and proper error handling to mitigate this risk."""
        else:
            remediation = """Review the code for security issues related to the reported vulnerability. 
Implement proper input validation, output encoding, and access controls appropriate for this specific type of vulnerability."""
    
    # Get code snippet
    code_snippet = vuln.get('code_snippet', vuln.get('extra', {}).get('code_snippet', ''))
    
    # Ensure proper structure
    processed = {
        "check_id": vuln.get("check_id") or f"AI-{vuln.get('extra', {}).get('metadata', {}).get('cwe', 'GENERIC')}",
        "path": vuln.get("path", file_name),
        "start": vuln.get("start", {"line": 1, "col": 1}),
        "end": vuln.get("end", {"line": 1, "col": 1}),
        "message": vuln.get("message", "Security vulnerability detected"),
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "code_snippet": code_snippet,
        "extra": {
            "message": vuln.get("message", "Security vulnerability detected"),
            "severity": severity,
            "metadata": {
                "cwe": vuln.get("extra", {}).get("metadata", {}).get("cwe", ""),
                "category": "Security",
                "owasp": vuln.get("extra", {}).get("metadata", {}).get("owasp", "")
            },
            "description": description,
            "code_snippet": code_snippet,
            "remediation": remediation
        },
        "impact": vuln.get("impact", "high"),
        "exploitability": vuln.get("exploitability", "medium"),
        "risk_severity": 0.8 if severity == "ERROR" else 0.5 if severity == "WARNING" else 0.3
    }
    
    # Log the structure for debugging
    logger.debug(f"Processed vulnerability structure: {json.dumps(processed, indent=2)}")
    
    return processed

def analyze_with_chatgpt(file_content: str, file_name: str) -> Dict[str, Any]:
    """Analyze code using ChatGPT with predefined rules."""
    try:
        start_time = time.time()
        logger.info(f"Starting ChatGPT analysis for {file_name}")
        
        # Initialize empty vulnerabilities list and severity counts
        vulnerabilities = []
        severity_count = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        
        # First, get AI analysis from ChatGPT
        system_message = """You are a security expert analyzing code for vulnerabilities.
Analyze the code and provide detailed information about any security vulnerabilities found.
For each vulnerability, provide:
1. Vulnerability type (e.g., SQL Injection, Command Injection, etc.)
2. CWE ID if applicable
3. Severity level (ERROR for high, WARNING for medium, INFO for low)
4. Exact line number where the vulnerability exists
5. Detailed description of why this is a vulnerability
6. Specific remediation steps to fix the issue

Format your response as JSON with this structure:
{
  "vulnerabilities": [
    {
      "type": "vulnerability type",
      "cwe": "CWE ID number",
      "severity": "ERROR|WARNING|INFO",
      "line_number": line number,
      "message": "brief description",
      "description": "detailed explanation of the vulnerability",
      "remediation": "specific steps to fix the issue"
    }
  ]
}"""

        try:
            # Get response from ChatGPT
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": file_content}
                ],
                temperature=0.2
            )
            
            # Parse ChatGPT response
            if response.choices and response.choices[0].message.content:
                try:
                    ai_result = json.loads(response.choices[0].message.content)
                    if "vulnerabilities" in ai_result:
                        for vuln in ai_result["vulnerabilities"]:
                            processed_vuln = {
                                "check_id": f"CWE-{vuln.get('cwe', 'AI')}",
                                "path": file_name,
                                "start": {"line": vuln.get("line_number", 1), "col": 1},
                                "end": {"line": vuln.get("line_number", 1), "col": 100},
                                "message": vuln.get("message", "AI detected vulnerability"),
                                "severity": vuln.get("severity", "INFO"),
                                "description": vuln.get("description", ""),
                                "remediation": vuln.get("remediation", ""),
                                "extra": {
                                    "message": vuln.get("message", "AI detected vulnerability"),
                                    "severity": vuln.get("severity", "INFO"),
                                    "metadata": {
                                        "cwe": vuln.get("cwe", ""),
                                        "category": "Security",
                                        "owasp": vuln.get("type", "").replace(" ", "_").upper()
                                    },
                                    "description": vuln.get("description", ""),
                                    "remediation": vuln.get("remediation", ""),
                                    "code_snippet": ""  # Will be filled later
                                }
                            }
                            vulnerabilities.append(processed_vuln)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse ChatGPT response as JSON")
                except Exception as e:
                    logger.warning(f"Error processing ChatGPT response: {str(e)}")
        except Exception as e:
            logger.warning(f"Error getting ChatGPT analysis: {str(e)}")
        
        # Then, apply rules-based analysis
        try:
            rules_file = os.path.join(os.path.dirname(__file__), '../rules/security_rules.json')
            with open(rules_file) as f:
                rules = json.load(f)
            
            # Create line map for code snippets
            lines = file_content.split('\n')
            
            # Apply rules to find vulnerabilities
            for line_num, line in enumerate(lines, 1):
                for rule in rules:
                    if re.search(rule["pattern"], line):
                        # Get context (few lines before and after)
                        start_ctx = max(0, line_num - 2)
                        end_ctx = min(len(lines), line_num + 2)
                        code_snippet = "\n".join(lines[start_ctx:end_ctx])
                        
                        vuln = {
                            "check_id": f"CWE-{rule['cwe']}",
                            "path": file_name,
                            "start": {"line": line_num, "col": 1},
                            "end": {"line": line_num, "col": len(line)},
                            "message": rule["message"],
                            "severity": rule["severity"],
                            "description": f"""A {rule['message'].lower()} was detected in the code.
This vulnerability could allow an attacker to execute malicious code or commands.
The vulnerable code was found at line {line_num}.""",
                            "remediation": rule.get("remediation", ""),
                            "extra": {
                                "message": rule["message"],
                                "severity": rule["severity"],
                                "metadata": {
                                    "cwe": rule["cwe"],
                                    "category": "Security",
                                    "owasp": rule["owasp"]
                                },
                                "description": f"""A {rule['message'].lower()} was detected in the code.
This vulnerability could allow an attacker to execute malicious code or commands.
The vulnerable code was found at line {line_num}.""",
                                "code_snippet": code_snippet,
                                "remediation": rule.get("remediation", "")
                            }
                        }
                        processed_vuln = process_vulnerability(vuln, file_name)
                        vulnerabilities.append(processed_vuln)
                        
                        # Update severity count
                        severity = processed_vuln["severity"].upper()
                        severity_count[severity] = severity_count.get(severity, 0) + 1
        except Exception as e:
            logger.warning(f"Error in rules-based analysis: {str(e)}")
        
        # Calculate final metrics
        total_vulnerabilities = len(vulnerabilities)
        security_score = calculate_security_score(vulnerabilities)
        
        # Double check severity counts
        severity_count = _count_by_severity(vulnerabilities)
        
        logger.info(f"Found {total_vulnerabilities} vulnerabilities")
        logger.info(f"Final severity counts: {severity_count}")
        
        # Log example vulnerability structure if any exist
        if vulnerabilities:
            logger.debug(f"Example vulnerability structure: {json.dumps(vulnerabilities[0], indent=2)}")
        
        # Prepare result with guaranteed severity count structure
        result = {
            "file_name": file_name,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": vulnerabilities,
            "severity_count": severity_count,
            "total_vulnerabilities": total_vulnerabilities,
            "security_score": security_score,
            "scan_status": "completed",
            "scan_duration": time.time() - start_time,
            "scan_metadata": {
                "success": True,
                "analyzers": ["chatgpt", "rules"],
                "scan_mode": "rules",
                "scan_type": "AI"
            }
        }
        
        # Validate severity count structure before returning
        assert all(k in result["severity_count"] for k in ["ERROR", "WARNING", "INFO"]), \
            "Missing severity levels in count"
        
        logger.info(f"Analysis completed - Score: {security_score}, Counts: {severity_count}")
        return result
        
    except Exception as e:
        logger.error(f"Error in ChatGPT analysis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error in ChatGPT analysis: {str(e)}"
        )
