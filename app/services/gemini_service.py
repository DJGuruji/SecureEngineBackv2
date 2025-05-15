import os
import logging
import json
import tempfile
import shutil
import zipfile
import math
from typing import Dict, Any, List, Optional
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Configure the Gemini API client with fallback
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyCtuOKC0ykaMkTzQfiTrqIGmh-qxm_Sr-Y")
if not GEMINI_API_KEY:
    logger.warning("GEMINI_API_KEY not found in environment variables")

genai.configure(api_key=GEMINI_API_KEY)

# Try to list available models
try:
    available_models = [model.name for model in genai.list_models()]
    logger.info(f"Available models: {available_models}")
except Exception as e:
    logger.warning(f"Error listing models: {str(e)}")
    available_models = []

# Define model to use - default to the most common Gemini model names with fallbacks
DEFAULT_MODEL = "models/gemini-pro"
if not available_models:    # If we couldn't list models, use default model name
    AVAILABLE_MODEL = DEFAULT_MODEL
    logger.warning(f"No models available, using default model: {DEFAULT_MODEL}")
else:    # Try to find a suitable Gemini model from available ones
    preferred_models = ["gemini-pro", "gemini-1.5-pro"]
    AVAILABLE_MODEL = DEFAULT_MODEL
    for model_name in available_models:
        for preferred in preferred_models:
            if preferred in model_name:
                AVAILABLE_MODEL = model_name
                logger.info(f"Found matching Gemini model: {AVAILABLE_MODEL}")
                break
        if AVAILABLE_MODEL != DEFAULT_MODEL:
            break
    # If no Gemini model found, fallback to default
    if AVAILABLE_MODEL == DEFAULT_MODEL:
        logger.warning(f"No matching Gemini models found, using default: {DEFAULT_MODEL}")

logger.info(f"Selected model: {AVAILABLE_MODEL}")

async def scan_code_with_gemini(file_path: str) -> Dict[str, Any]:
    """
    Scan a file or directory with Gemini AI to identify potential security vulnerabilities.
    
    Args:
        file_path: Path to the file or directory to scan
        
    Returns:
        Dictionary containing scan results with identified vulnerabilities
    """
    try:
        logger.info(f"Starting Gemini AI scan on: {file_path}")
        
        extracted_path = file_path
        is_zip = False
        
        # Check if the file is a zip and extract it
        if os.path.isfile(file_path) and file_path.endswith('.zip'):
            logger.info(f"Extracting zip file: {file_path}")
            try:
                temp_dir = tempfile.mkdtemp()
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                extracted_path = temp_dir
                is_zip = True
                logger.info(f"Successfully extracted zip file to {temp_dir}")
            except Exception as e:
                logger.error(f"Error extracting zip file: {str(e)}")
                raise Exception(f"Could not extract zip file: {str(e)}")
        
        # Get file contents for analysis
        file_contents, file_paths = get_file_contents(extracted_path)
        
        if not file_contents:
            raise Exception("No code files found to analyze")
        
        # Run Gemini analysis on the code
        vulnerabilities = await analyze_files_with_gemini(file_contents)
        
        # Clean up extracted directory if it was a zip
        if is_zip:
            try:
                shutil.rmtree(extracted_path)
                logger.info(f"Cleaned up temporary directory: {extracted_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary directory: {str(e)}")
        
        # Calculate statistics
        total_vulnerabilities = len(vulnerabilities)
        severity_count = count_vulnerabilities_by_severity(vulnerabilities)
        
        # Prepare scan results
        score = calculate_security_score(vulnerabilities)
        
        # Ensure score is never null
        if score is None:
            score = 5  # Default mid-range score
            
        scan_results = {
            "file_name": os.path.basename(file_path),
            "security_score": score,
            "vulnerabilities": vulnerabilities,
            "severity_count": severity_count,
            "total_vulnerabilities": total_vulnerabilities,
            "scan_metadata": {
                "scan_type": "AI",
                "scan_mode": "gemini"
            }
        }
        
        logger.info(f"Gemini AI scan completed with {total_vulnerabilities} vulnerabilities found")
        return scan_results
        
    except Exception as e:
        logger.error(f"Error in Gemini AI scan: {str(e)}")
        raise Exception(f"Gemini AI scan failed: {str(e)}")

def get_file_contents(path: str) -> tuple[Dict[str, str], List[str]]:
    """
    Get the contents of all code files in the directory
    
    Args:
        path: Path to the file or directory
        
    Returns:
        Tuple of (dict mapping file paths to contents, list of file paths)
    """
    file_contents = {}
    file_paths = []
    
    # Define code file extensions to scan
    code_extensions = {
        '.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs',
        '.php', '.rb', '.go', '.rs', '.html', '.css', '.jsx',
        '.tsx', '.vue', '.swift', '.kt', '.scala', '.sh',
        '.sql', '.dart', '.yaml', '.yml'
    }
    
    if os.path.isfile(path):
        # Single file processing
        try:
            _, ext = os.path.splitext(path)
            if ext in code_extensions:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    file_contents[path] = content
                    file_paths.append(path)
        except Exception as e:
            logger.warning(f"Could not read file {path}: {str(e)}")
    else:
        # Directory processing - walk through directory
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file)
                
                if ext in code_extensions:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # Use relative path for readability
                            rel_path = os.path.relpath(file_path, path)
                            file_contents[rel_path] = content
                            file_paths.append(rel_path)
                    except Exception as e:
                        logger.warning(f"Could not read file {file_path}: {str(e)}")
    
    logger.info(f"Found {len(file_contents)} code files to analyze")
    return file_contents, file_paths

async def analyze_files_with_gemini(file_contents: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Analyze code files with Gemini AI to identify vulnerabilities
    
    Args:
        file_contents: Dictionary mapping file paths to their contents
        
    Returns:
        List of vulnerability dictionaries
    """
    vulnerabilities = []
    
    try:
        # Try to get the model
        try:
            # Choose the right model - use the model we found during initialization
            model = genai.GenerativeModel(AVAILABLE_MODEL)
            logger.info(f"Successfully created GenerativeModel with {AVAILABLE_MODEL}")
        except Exception as model_error:
            # If that fails, fall back to a known working model
            fallback_model = "models/gemini-pro"
            logger.warning(f"Error creating model with {AVAILABLE_MODEL}: {str(model_error)}. Falling back to {fallback_model}")
            model = genai.GenerativeModel(fallback_model)
        
        # For each file, send it to Gemini for analysis
        for file_path, content in file_contents.items():
            # Skip files that are too large
            if len(content) > 30000:
                logger.warning(f"File {file_path} is too large for Gemini analysis (> 30KB), skipping")
                continue
                
            # Format prompt for security analysis with clearer instructions
            prompt = f"""
            You are a cybersecurity expert performing a code security scan. Your task is to thoroughly analyze the code for security vulnerabilities.
            
            CODE TO ANALYZE:
            File: {file_path}
            
            ```
            {content}
            ```
            
            DETAILED INSTRUCTIONS:
            1. Carefully analyze the code for ANY security vulnerabilities including but not limited to:
               - SQL injection vulnerabilities
               - Cross-site scripting (XSS)
               - Command injection
               - Path traversal and directory traversal
               - Authentication issues or weak authentication
               - Authorization flaws or privilege escalation
               - Insecure cryptography implementation
               - Hardcoded credentials or API keys
               - Cross-site request forgery (CSRF)
               - Memory safety issues like buffer overflows
               - Insecure file permissions
               - Race conditions
               - Insecure deserialization
               - Server-side request forgery (SSRF)
               - Sensitive data exposure

            2. Be thorough - look for ALL potential vulnerabilities, even subtle ones. DO NOT miss any security issues!
            
            3. For each vulnerability found, classify it as follows:
               - ERROR: High-severity issues that could lead to system compromise, data leakage, or security breaches
               - WARNING: Medium-severity issues that pose potential security risks but have limited impact
               - INFO: Low-severity issues or best practice violations
            
            4. For each vulnerability, assign a score from 1-10:
               - ERROR severity: scores 7-10 (7=least severe, 10=most severe)
               - WARNING severity: scores 4-6
               - INFO severity: scores 1-3
               - IMPORTANT: Score must be an integer between 1 and 10, never higher than 10!
            
            FORMAT YOUR RESPONSE AS A JSON ARRAY with objects containing EXACTLY these fields:
            - "check_id": A descriptive string for the vulnerability type (e.g., "sql-injection", "xss-vulnerability")
            - "path": The file path (use the value provided to you)
            - "line": The exact line number where the vulnerability occurs
            - "message": A clear description of the vulnerability
            - "severity": EXACTLY one of "ERROR", "WARNING", or "INFO"
            - "category": The category of vulnerability (e.g., "Injection", "XSS", "Authentication")
            - "snippet": The code snippet containing the vulnerability
            - "score": An integer from 1-10 representing severity (MUST be between 1 and 10)
            
            DO NOT INCLUDE any other text outside the JSON array. If no vulnerabilities are found, return an empty array [].
            """
            
            try:
                # Run the analysis - handle generation with proper error handling
                safety_settings = [
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_NONE",
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_NONE",
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "threshold": "BLOCK_NONE",
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "threshold": "BLOCK_NONE",
                    },
                ]
                
                generation_config = {
                    "temperature": 0.1,  # Lower temperature for more deterministic results
                    "top_p": 0.8,
                    "top_k": 40,
                    "max_output_tokens": 2048,
                }
                
                response = await model.generate_content_async(
                    prompt, 
                    safety_settings=safety_settings,
                    generation_config=generation_config
                )
                
                result_text = response.text
                
                # Extract JSON from the response
                try:
                    # Try to find JSON in the response (it may be wrapped in markdown code blocks)
                    if "```json" in result_text:
                        result_text = result_text.split("```json")[1].split("```")[0].strip()
                    elif "```" in result_text:
                        result_text = result_text.split("```")[1].split("```")[0].strip()
                    
                    # Parse the JSON output
                    file_vulnerabilities = json.loads(result_text)
                    
                    # Ensure it's a list
                    if not isinstance(file_vulnerabilities, list):
                        logger.warning(f"Unexpected response format for {file_path}, got: {type(file_vulnerabilities)}")
                        continue
                    
                    # Format vulnerabilities to match Semgrep format
                    for vuln in file_vulnerabilities:
                        # Strictly enforce score range
                        try:
                            # First try to convert to int if it's a string
                            if isinstance(vuln.get("score"), str):
                                raw_score = int(vuln.get("score", "5"))
                            else:
                                raw_score = int(vuln.get("score", 5))
                        except (ValueError, TypeError):
                            # Default scores based on severity if conversion fails
                            severity = vuln.get("severity", "INFO").upper()
                            if severity == "ERROR":
                                raw_score = 8  # Default high score
                            elif severity == "WARNING":
                                raw_score = 5  # Default medium score
                            else:
                                raw_score = 2  # Default low score
                                
                        # Force score within range 1-10 with a hard cap
                        floor_score = min(max(1, raw_score), 10)
                        
                        # Ensure severity matches score
                        severity = vuln.get("severity", "INFO").upper()
                        if floor_score >= 7 and severity != "ERROR":
                            severity = "ERROR"
                        elif 4 <= floor_score <= 6 and severity != "WARNING":
                            severity = "WARNING"
                        elif floor_score <= 3 and severity != "INFO":
                            severity = "INFO"
                                
                        # Add extra structure to match Semgrep output format
                        formatted_vuln = {
                            "check_id": vuln.get("check_id", "ai.security.generic"),
                            "path": file_path,
                            "start": {"line": vuln.get("line", 1), "col": 1},
                            "end": {"line": vuln.get("line", 1) + 1 if vuln.get("line") else 2, "col": 80},
                            "extra": {
                                "severity": severity,
                                "metadata": {
                                    "category": vuln.get("category", "Security"),
                                    "technology": ["AI", "Gemini"],
                                    "score": floor_score  # Add capped score
                                },
                                "message": vuln.get("message", "Potential security issue detected"),
                                "lines": vuln.get("snippet", ""),
                                "score": floor_score  # Also add to top level for easier access
                            },
                            "severity": severity.lower()  # Also add to top level for consistency
                        }
                        vulnerabilities.append(formatted_vuln)
                    
                    logger.info(f"Found {len(file_vulnerabilities)} vulnerabilities in {file_path}")
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse Gemini response for {file_path}: {str(e)}")
                    logger.debug(f"Raw response: {result_text}")
                    
                    # Try to extract JSON from malformed response
                    try:
                        # Look for anything between square brackets that might be JSON
                        import re
                        potential_json = re.search(r'\[(.*?)\]', result_text, re.DOTALL)
                        if potential_json:
                            fixed_json = "[" + potential_json.group(1) + "]"
                            file_vulnerabilities = json.loads(fixed_json)
                            logger.info(f"Successfully extracted JSON from malformed response")
                            
                            # Process vulnerabilities from extracted JSON
                            for vuln in file_vulnerabilities:
                                # Apply the same processing as above
                                try:
                                    raw_score = int(vuln.get("score", 5))
                                except (ValueError, TypeError):
                                    severity = vuln.get("severity", "INFO").upper()
                                    raw_score = 8 if severity == "ERROR" else 5 if severity == "WARNING" else 2
                                
                                floor_score = min(max(1, raw_score), 10)
                                severity = vuln.get("severity", "INFO").upper()
                                
                                # Map score to severity
                                if floor_score >= 7:
                                    severity = "ERROR"
                                elif floor_score >= 4:
                                    severity = "WARNING"
                                else:
                                    severity = "INFO"
                                
                                formatted_vuln = {
                                    "check_id": vuln.get("check_id", "ai.security.generic"),
                                    "path": file_path,
                                    "start": {"line": vuln.get("line", 1), "col": 1},
                                    "end": {"line": vuln.get("line", 1) + 1 if vuln.get("line") else 2, "col": 80},
                                    "extra": {
                                        "severity": severity,
                                        "metadata": {
                                            "category": vuln.get("category", "Security"),
                                            "technology": ["AI", "Gemini"],
                                            "score": floor_score
                                        },
                                        "message": vuln.get("message", "Potential security issue detected"),
                                        "lines": vuln.get("snippet", ""),
                                        "score": floor_score
                                    },
                                    "severity": severity.lower()
                                }
                                vulnerabilities.append(formatted_vuln)
                    except Exception as json_fix_error:
                        logger.warning(f"Failed to extract and parse JSON from response: {str(json_fix_error)}")
            except Exception as e:
                logger.warning(f"Failed to analyze {file_path}: {str(e)}")
                # Continue to next file instead of failing entirely
    
    except Exception as e:
        logger.error(f"Error in Gemini analysis: {str(e)}")
        raise Exception(f"Gemini analysis failed: {str(e)}")
    
    # If no vulnerabilities were found and there's content to analyze,
    # do a simpler analysis to find potential issues
    if not vulnerabilities and file_contents:
        try:
            # Select a smaller subset of files for simplified analysis
            sample_files = dict(list(file_contents.items())[:3])  # Analyze up to 3 files
            for file_path, content in sample_files.items():
                # Look for common vulnerability patterns
                vuln_patterns = [
                    ("exec(", "Command execution", "ERROR", 8),
                    ("eval(", "Arbitrary code execution", "ERROR", 9),
                    ("password =", "Potential hardcoded password", "WARNING", 6),
                    ("SELECT * FROM", "SQL query - check for injection", "WARNING", 5),
                    ("innerHTML", "Potential XSS vulnerability", "WARNING", 6),
                    ("http://", "Unsecured HTTP usage", "INFO", 3),
                    ("admin", "Potential privileged operation", "INFO", 2)
                ]
                
                lines = content.split("\n")
                for i, line in enumerate(lines):
                    for pattern, msg, severity, score in vuln_patterns:
                        if pattern in line:
                            vulnerabilities.append({
                                "check_id": f"ai.security.{pattern.replace('(', '').replace(' =', '').lower()}",
                                "path": file_path,
                                "start": {"line": i+1, "col": 1},
                                "end": {"line": i+2, "col": 1},
                                "extra": {
                                    "severity": severity,
                                    "metadata": {
                                        "category": "Security",
                                        "technology": ["AI", "Pattern Match"],
                                        "score": score
                                    },
                                    "message": f"{msg}: {line.strip()}",
                                    "lines": line.strip(),
                                    "score": score
                                },
                                "severity": severity.lower()
                            })
        except Exception as pattern_error:
            logger.warning(f"Error in pattern-based analysis: {str(pattern_error)}")
    
    # If still no vulnerabilities were found, add a generic "no issues found" entry
    if not vulnerabilities:
        first_file = next(iter(file_contents.keys())) if file_contents else "unknown"
        vulnerabilities.append({
            "check_id": "ai.security.no_issues",
            "path": first_file,
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 1},
            "extra": {
                "severity": "INFO",
                "message": "No security vulnerabilities detected",
                "metadata": {
                    "category": "Security",
                    "score": 10  # Perfect score for no vulnerabilities
                },
                "score": 10
            },
            "severity": "info"
        })
    
    return vulnerabilities

def count_vulnerabilities_by_severity(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count vulnerabilities by severity
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Dictionary mapping severity levels to counts
    """
    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("extra", {}).get("severity", "").upper()
        if severity in counts:
            counts[severity] += 1
    
    return counts

def calculate_security_score(vulnerabilities: List[Dict[str, Any]]) -> int:
    """
    Calculate a security score based on the number and severity of vulnerabilities
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Security score from 1-10 (higher is better)
    """
    # Count vulnerabilities by severity
    severity_counts = count_vulnerabilities_by_severity(vulnerabilities)
    
    # Use same penalty weights as the main security.py module for consistency
    base_score = 10.0
    high_penalty = 2.0    # Same as ERROR in security.py
    medium_penalty = 1.0  # Same as WARNING in security.py
    low_penalty = 0.4     # Same as INFO in security.py
    
    # Calculate deductions
    deductions = (
        severity_counts["ERROR"] * high_penalty +
        severity_counts["WARNING"] * medium_penalty +
        severity_counts["INFO"] * low_penalty
    )
    
    # Calculate final score (minimum 0)
    score = max(0, base_score - deductions)
    
    # Round to an integer and ensure it's at least 1
    score = max(1, int(round(score)))
    
    # Log the score calculation for debugging
    logger.info(f"AI Scan security score: {score}, vulnerabilities: ERROR={severity_counts['ERROR']}, WARNING={severity_counts['WARNING']}, INFO={severity_counts['INFO']}")
    
    return score
  