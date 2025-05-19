import subprocess
import json
import logging
import tempfile
import os
from typing import List, Dict, Optional
from fastapi import HTTPException, status
import yaml
import requests
from urllib.parse import quote
from app.core.scan_exclusions import EXCLUDED_PATTERNS

# Import our custom rules module
from app.resources.semgrep_rules.index import get_all_custom_rules, get_custom_rule_by_id

logger = logging.getLogger(__name__)

def fetch_semgrep_rules(query: Optional[str] = None, limit: int = 50, offset: int = 0, severity: Optional[str] = None, rule_type: Optional[str] = None) -> Dict:
    """Fetch rules from custom Semgrep rules with pagination support."""
    try:
        logger.info(f"Fetching custom semgrep rules with query: {query}, limit: {limit}, offset: {offset}, severity: {severity}, rule_type: {rule_type}")
        
        # Use our custom rules module instead of the Semgrep Registry
        result = get_all_custom_rules(query, limit, offset, severity, rule_type)
        
        logger.info(f"Retrieved {len(result['rules'])} custom rules, total={result['total']}, has_more={result['has_more']}")
        
        return result
    except Exception as e:
        logger.error(f"Unexpected error fetching custom semgrep rules: {str(e)}")
        raise ValueError(f"Unexpected error: {str(e)}")
        
# The following code is kept just for reference in case we need to revert
"""
def fetch_semgrep_rules_from_registry(query: Optional[str] = None, limit: int = 50, offset: int = 0, severity: Optional[str] = None, rule_type: Optional[str] = None) -> Dict:
    # Base URL for the Semgrep Registry API
    api_url = "https://semgrep.dev/api/registry/rules"
    
    # Prepare query parameters
    params = {
        "limit": limit,
        "offset": offset
    }
    
    if query:
        params["query"] = query
    
    if rule_type:
        # Currently the API doesn't support direct rule_type filtering
        # We'll apply it after we get the results
        logger.info(f"Will filter by rule_type: {rule_type} after retrieving results")
        
    # Make request to Semgrep Registry API
    logger.info(f"Making request to Semgrep Registry API: {api_url}")
    response = requests.get(api_url, params=params, timeout=30)
    
    # Check if request was successful
    if response.status_code != 200:
        logger.error(f"Semgrep Registry API returned error: {response.status_code} - {response.text}")
        raise ValueError(f"Failed to fetch rules from Semgrep Registry: {response.status_code}")
        
    # Parse response
    rules_data = response.json()
"""

def run_semgrep(file_path: str, custom_rule: Optional[str] = None) -> List[Dict]:
    """Run semgrep on a file or directory and return results."""
    try:
        # Check if it's a directory or file
        is_directory = os.path.isdir(file_path)
        logger.info(f"Running semgrep on {'directory' if is_directory else 'file'}: {file_path}")
        
        # Log file content for debugging (only for single files, not directories)
        if not is_directory:
            try:
                with open(file_path, 'r') as f:
                    file_content = f.read()
                    logger.info(f"File content:\n{file_content}")
            except Exception as e:
                logger.warning(f"Could not read file content: {str(e)}")
        else:
            # Log directory structure for debugging
            logger.info("Directory structure:")
            for root, dirs, files in os.walk(file_path):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), file_path)
                    logger.info(f"- {rel_path}")
        
        # Base command
        cmd = ["semgrep", "--json", "--verbose"]
        
        # Add exclusion patterns
        for pattern in EXCLUDED_PATTERNS:
            # Clean pattern for semgrep exclusion format
            clean_pattern = pattern.rstrip('/')
            cmd.extend(["--exclude", clean_pattern])
        
        # Handle custom rule
        if custom_rule:
            try:
                logger.info("Processing custom rule...")
                # Check if this is a custom rule ID (no JSON markers)
                if not custom_rule.startswith('{') and not custom_rule.endswith('}'):
                    rule_id = custom_rule.strip()
                    logger.info(f"Looking for custom rule with ID: '{rule_id}'")
                    
                    # Try to get the rule from our custom rules
                    rule_data = get_custom_rule_by_id(rule_id)
                    
                    if rule_data:
                        logger.info(f"Found custom rule with ID: {rule_id}")
                        
                        # Create temporary file for the rule
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_rule:
                            # Convert to YAML format that Semgrep expects
                            yaml.dump(rule_data, temp_rule)
                            temp_rule_path = temp_rule.name
                            logger.info(f"Created temporary rule file at: {temp_rule_path}")
                        
                        # Add rule file to command
                        cmd.extend(["--config", temp_rule_path])
                        logger.info(f"Using custom rule file: {temp_rule_path}")
                    elif rule_id == "auto":
                        # Special case for auto rules
                        logger.info("Using auto rules")
                        cmd.extend(["--config", "auto"])
                    else:
                        # If not found in custom rules, use auto rules as fallback
                        logger.warning(f"Custom rule ID {rule_id} not found. Using auto rules as fallback.")
                        cmd.extend(["--config", "auto"])
                else:
                    # Validate JSON format
                    rule_data = json.loads(custom_rule)
                    if not isinstance(rule_data, dict) or "rules" not in rule_data:
                        raise ValueError("Invalid rule format: must contain 'rules' array")
                    
                    # Log rule details
                    logger.info(f"Custom rule contains {len(rule_data['rules'])} rules")
                    for rule in rule_data["rules"]:
                        logger.info(f"Rule ID: {rule.get('id')}, Languages: {rule.get('languages')}")
                        logger.info(f"Patterns: {json.dumps(rule.get('patterns', []), indent=2)}")
                        
                        # Log pattern matching details
                        for pattern in rule.get("patterns", []):
                            pattern_text = pattern.get("pattern", pattern.get("pattern-inside", ""))
                            logger.info(f"Checking pattern: {pattern_text}")
                            if "..." in pattern_text:
                                logger.info("Pattern contains '...' for arbitrary code matching")
                            if "$" in pattern_text:
                                logger.info("Pattern contains metavariables for matching")
                    
                    # Validate each rule's structure
                    for rule in rule_data["rules"]:
                        if not isinstance(rule, dict):
                            raise ValueError("Each rule must be a JSON object")
                        if "id" not in rule:
                            raise ValueError("Each rule must have an 'id' field")
                        if "patterns" not in rule:
                            raise ValueError("Each rule must have a 'patterns' array")
                        if "message" not in rule:
                            raise ValueError("Each rule must have a 'message' field")
                        if "languages" not in rule:
                            raise ValueError("Each rule must have a 'languages' array")
                        if "severity" not in rule:
                            raise ValueError("Each rule must have a 'severity' field")
                        
                        # Validate pattern syntax
                        for pattern in rule.get("patterns", []):
                            if "pattern" not in pattern and "pattern-inside" not in pattern:
                                raise ValueError("Each pattern must have either 'pattern' or 'pattern-inside' field")
                            # Validate pattern syntax
                            pattern_text = pattern.get("pattern", pattern.get("pattern-inside", ""))
                            if not isinstance(pattern_text, str):
                                raise ValueError("Pattern must be a string")
                            if not pattern_text.strip():
                                raise ValueError("Pattern cannot be empty")
                    
                    # Create temporary file for the rule
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_rule:
                        # Convert JSON to YAML format that Semgrep expects
                        yaml.dump(rule_data, temp_rule)
                        temp_rule_path = temp_rule.name
                        logger.info(f"Created temporary rule file at: {temp_rule_path}")
                    
                    # Add rule file to command
                    cmd.extend(["--config", temp_rule_path])
                    logger.info(f"Using custom rule file: {temp_rule_path}")
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format in custom rule")
            except Exception as e:
                raise ValueError(f"Error processing custom rule: {str(e)}")
        else:
            # Use default auto config
            cmd.extend(["--config", "auto"])
            logger.info("Using default auto config")
        
        # Add target file or directory
        cmd.append(file_path)
        logger.info(f"Full semgrep command: {' '.join(cmd)}")
        
        # Run semgrep with a longer timeout for directories or larger files
        timeout = 300 if is_directory else 60
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        # Clean up temporary rule file if it exists
        if custom_rule and 'temp_rule_path' in locals():
            try:
                os.unlink(temp_rule_path)
                logger.info("Cleaned up temporary rule file")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary rule file: {str(e)}")
        
        if result.returncode != 0:
            # Try to parse the error output for more detailed information
            try:
                error_data = json.loads(result.stdout)
                if "errors" in error_data:
                    error_messages = [err.get("message", "") for err in error_data["errors"]]
                    raise Exception(f"Semgrep pattern error: {'; '.join(error_messages)}")
            except json.JSONDecodeError:
                pass
            
            logger.error(f"Semgrep error:\n{result.stdout}\n{result.stderr}")
            raise Exception(f"Semgrep failed: {result.stderr}")
            
        # Parse results
        try:
            results = json.loads(result.stdout)
            findings = results.get("results", [])
            logger.info(f"Found {len(findings)} vulnerabilities")
            if findings:
                logger.info("Vulnerability details:")
                for finding in findings:
                    logger.info(f"- Rule: {finding.get('check_id')}, Severity: {finding.get('extra', {}).get('severity')}")
                    logger.info(f"  Message: {finding.get('extra', {}).get('message')}")
                    logger.info(f"  Location: {finding.get('path')}:{finding.get('start', {}).get('line')}")
                    logger.info(f"  Code snippet: {finding.get('extra', {}).get('lines', '')}")
            else:
                logger.info("No vulnerabilities found. This could be because:")
                logger.info("1. The patterns don't match the code structure")
                logger.info("2. The code doesn't contain the expected patterns")
                logger.info("3. The rule syntax might need adjustment")
            return findings
        except json.JSONDecodeError:
            logger.error(f"Failed to parse Semgrep output: {result.stdout}")
            raise Exception("Failed to parse Semgrep output")
            
    except Exception as e:
        logger.error(f"Error running semgrep: {str(e)}")
        raise 

def fetch_semgrep_rule_by_id(rule_id: str) -> Dict:
    """Fetch details for a specific Semgrep rule by its ID."""
    try:
        logger.info(f"Fetching custom semgrep rule details for ID: {rule_id}")
        
        # Use our custom rules instead of the Semgrep Registry
        rule_data = get_custom_rule_by_id(rule_id)
        
        if not rule_data:
            logger.error(f"Custom rule with ID {rule_id} not found")
            raise ValueError(f"Custom rule with ID {rule_id} not found")
            
        logger.info(f"Retrieved custom rule details for {rule_id}")
        
        return rule_data
    except Exception as e:
        logger.error(f"Error fetching custom semgrep rule details for {rule_id}: {str(e)}")
        raise ValueError(f"Error fetching custom semgrep rule details: {str(e)}")
        
# The following code is kept just for reference in case we need to revert
"""
def fetch_semgrep_rule_by_id_from_registry(rule_id: str) -> Dict:
    # Base URL for the Semgrep Registry API - use the ID directly
    api_url = f"https://semgrep.dev/api/registry/rule/{rule_id}"
    
    # Make request to Semgrep Registry API
    logger.info(f"Making request to Semgrep Registry API: {api_url}")
    response = requests.get(api_url, timeout=30)
    
    # Check if request was successful
    if response.status_code != 200:
        logger.error(f"Semgrep Registry API returned error: {response.status_code} - {response.text}")
        raise ValueError(f"Failed to fetch rule details from Semgrep Registry: {response.status_code}")
        
    # Parse response
    rule_data = response.json()
    
    # Log detailed information about the response structure for debugging
    logger.info(f"Retrieved rule details for {rule_id}. Response keys: {list(rule_data.keys())}")
    
    # Check for important fields and log their presence
    if 'definition' in rule_data:
        logger.info("Rule has 'definition' field")
        if 'rules' in rule_data['definition']:
            logger.info(f"Rule definition has {len(rule_data['definition']['rules'])} rules")
            if rule_data['definition']['rules'] and len(rule_data['definition']['rules']) > 0:
                logger.info(f"First rule keys: {list(rule_data['definition']['rules'][0].keys())}")
                # Check if severity exists in rule definition
                if 'severity' in rule_data['definition']['rules'][0]:
                    logger.info(f"Rule has severity: {rule_data['definition']['rules'][0]['severity']}")
                else:
                    logger.warning("Rule is missing severity in definition.rules[0]")
    else:
        logger.warning("Response lacks 'definition' field")
        
    # Check if 'path' exists
    if 'path' in rule_data:
        logger.info(f"Rule has path: {rule_data['path']}")
    else:
        logger.warning("Rule is missing 'path' field")
        
    return rule_data
""" 