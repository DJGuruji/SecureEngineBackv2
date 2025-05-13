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

logger = logging.getLogger(__name__)

def fetch_semgrep_rules(query: Optional[str] = None, limit: int = 50, offset: int = 0, severity: Optional[str] = None) -> Dict:
    """Fetch rules from Semgrep Registry with pagination support."""
    try:
        logger.info(f"Fetching semgrep rules with query: {query}, limit: {limit}, offset: {offset}, severity: {severity}")
        
        # Base URL for the Semgrep Registry API
        api_url = "https://semgrep.dev/api/registry/rules"
        
        # Prepare query parameters
        params = {
            "limit": limit,
            "offset": offset
        }
        
        if query:
            params["query"] = query
            
        # Make request to Semgrep Registry API
        logger.info(f"Making request to Semgrep Registry API: {api_url}")
        response = requests.get(api_url, params=params, timeout=30)
        
        # Check if request was successful
        if response.status_code != 200:
            logger.error(f"Semgrep Registry API returned error: {response.status_code} - {response.text}")
            raise ValueError(f"Failed to fetch rules from Semgrep Registry: {response.status_code}")
            
        # Parse response
        rules_data = response.json()
        
        # API returns a list of rules
        if isinstance(rules_data, list):
            rules = []
            logger.info(f"Processing {len(rules_data)} rules from list response")
            
            # Add debug logging for the first few rules to understand structure
            for i, rule in enumerate(rules_data[:5]):  # Log first 5 rules
                logger.info(f"Rule {i+1} details:")
                logger.info(f"  ID: {rule.get('id', 'NOT PROVIDED')}")
                logger.info(f"  Name: {rule.get('name', 'NOT PROVIDED')}")
                logger.info(f"  Description length: {len(str(rule.get('description', '')))}")
                logger.info(f"  Path: {rule.get('path', 'NOT PROVIDED')}")
                
                # Log languages with special attention
                languages = rule.get('languages', [])
                if languages:
                    if isinstance(languages, list):
                        logger.info(f"  Languages: {', '.join(languages)}")
                        
                        # Check for specific languages of interest
                        language_checks = {
                            "python": "Python",
                            "javascript": "JavaScript", 
                            "typescript": "TypeScript",
                            "java": "Java", 
                            "go": "Go",
                            "ruby": "Ruby",
                            "c": "C",
                            "cpp": "C++",
                            "csharp": "C#"
                        }
                        
                        found_languages = []
                        for lang_key, lang_name in language_checks.items():
                            if lang_key in [l.lower() for l in languages]:
                                found_languages.append(lang_name)
                        
                        if found_languages:
                            logger.info(f"  Recognized languages: {', '.join(found_languages)}")
                        else:
                            logger.info("  No recognized mainstream languages found")
                    else:
                        logger.info(f"  Languages (non-list): {languages}")
                else:
                    logger.info("  Languages: NONE")
                
                # Log category info
                logger.info(f"  Category: {rule.get('category', 'NOT PROVIDED')}")
                logger.info(f"  Severity: {rule.get('severity', 'NOT PROVIDED')}")
                
                # Log all keys to see what other data might be available
                logger.info(f"  All keys: {', '.join(rule.keys())}")
            
            # Process each rule in the list
            for rule in rules_data:
                # Only skip rules with no ID - allow other fields to be missing
                if not rule.get("id"):
                    logger.warning("Skipping rule with missing ID")
                    continue
                    
                formatted_rule = {
                    "id": rule.get("id", ""),
                    "name": rule.get("name", "Unknown Rule"),
                    "description": rule.get("description", "No description available"),
                    "category": rule.get("category", "Security"),
                    "languages": rule.get("languages", []),
                    "severity": rule.get("severity", "WARNING"),
                    "patterns": rule.get("patterns", []),
                    "message": rule.get("message", ""),
                    "metadata": rule.get("metadata", {}),
                    "fix": rule.get("fix", ""),
                    "fix_regex": rule.get("fix-regex", ""),
                    "rule_id": rule.get("ruleid", ""),
                    "tags": rule.get("tags", []),
                    "mode": rule.get("mode", ""),
                    "path": rule.get("path", ""),
                    "source_uri": rule.get("source_uri", ""),
                    "visibility": rule.get("visibility", ""),
                    "meta": rule.get("meta", {})
                }
                rules.append(formatted_rule)
            
            # Filter by query if provided
            filtered_rules = rules
            if query:
                query_lower = query.lower()
                filtered_rules = [
                    rule for rule in rules 
                    if query_lower in rule["id"].lower() or 
                       query_lower in (rule["name"] or "").lower() or 
                       query_lower in (rule["description"] or "").lower() or
                       query_lower in (rule["path"] or "").lower() or  # Also search in the path
                       (rule.get("category") and query_lower in rule["category"].lower()) or
                       any(query_lower in lang.lower() for lang in rule.get("languages", []))
                ]
                logger.info(f"Filtered rules by query '{query}': {len(filtered_rules)} of {len(rules)} match")
            
            # Apply server-side filtering for severity if provided
            if severity:
                severity_lower = severity.lower()
                filtered_rules = [
                    rule for rule in filtered_rules
                    if rule.get("severity", "").lower() == severity_lower
                ]
                logger.info(f"Filtered rules by severity '{severity}': {len(filtered_rules)} of {len(rules)} match")
            
            # Apply pagination
            total_rules = len(filtered_rules)
            paginated_rules = filtered_rules[offset:offset + limit]
            has_more = (offset + limit) < total_rules
        else:
            # Handle the case where the API returns a dictionary with results field
            rules = []
            for rule in rules_data.get("results", []):
                # Only skip rules with no ID - allow other fields to be missing
                if not rule.get("id"):
                    logger.warning("Skipping rule with missing ID")
                    continue
                    
                formatted_rule = {
                    "id": rule.get("id", ""),
                    "name": rule.get("name", "Unknown Rule"),
                    "description": rule.get("description", "No description available"),
                    "category": rule.get("category", "Security"),
                    "languages": rule.get("languages", []),
                    "severity": rule.get("severity", "WARNING"),
                    "patterns": rule.get("patterns", []),
                    "message": rule.get("message", ""),
                    "metadata": rule.get("metadata", {}),
                    "fix": rule.get("fix", ""),
                    "fix_regex": rule.get("fix-regex", ""),
                    "rule_id": rule.get("ruleid", ""),
                    "tags": rule.get("tags", []),
                    "mode": rule.get("mode", ""),
                    "path": rule.get("path", ""),
                    "source_uri": rule.get("source_uri", ""),
                    "visibility": rule.get("visibility", ""),
                    "meta": rule.get("meta", {})
                }
                rules.append(formatted_rule)
            
            total_rules = rules_data.get("total", len(rules))
            has_more = rules_data.get("has_more", False)
            paginated_rules = rules
        
        logger.info(f"Retrieved {len(paginated_rules)} rules from Semgrep Registry, total={total_rules}, has_more={has_more}")
        
        # Don't filter out incomplete rules - just ensure they have an ID
        validRules = [rule for rule in paginated_rules if rule.get("id")]
        
        if len(validRules) < len(paginated_rules):
            logger.warning(f"Filtered out {len(paginated_rules) - len(validRules)} rules with missing IDs")
        
        return {
            "rules": validRules,
            "total": total_rules,
            "has_more": has_more,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"Unexpected error fetching semgrep rules: {str(e)}")
        raise ValueError(f"Unexpected error: {str(e)}")

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
        
        # Handle custom rule
        if custom_rule:
            try:
                logger.info("Processing custom rule...")
                # Check if this is a registry ID (no JSON markers)
                if not custom_rule.startswith('{') and not custom_rule.endswith('}'):
                    registry_id = custom_rule.strip()
                    
                    # Log registry ID details for debugging
                    logger.info(f"Registry ID details: '{registry_id}'")
                    parts = registry_id.split('/')
                    if len(parts) > 1:
                        logger.info(f"  Registry namespace: {parts[0]}")
                        logger.info(f"  Registry rule name: {'/'.join(parts[1:])}")
                    if registry_id.startswith('p/'):
                        logger.info("  This appears to be a ruleset pack")
                    elif registry_id.startswith('r/'):
                        logger.info("  This appears to be a rule reference")
                    else:
                        logger.info("  This appears to be a custom rule ID format")
                    
                    # Validate registry ID
                    if registry_id.startswith('p/') or registry_id.startswith('r/'):
                        # Standard pattern pack IDs, use as-is
                        logger.info(f"Using standard registry pack: {registry_id}")
                    elif registry_id == "auto":
                        # Special case for auto rules
                        logger.info("Using auto rules")
                    else:
                        # For other IDs, use p/default as a fallback
                        logger.warning(f"Non-standard rule ID format: {registry_id}. Using p/default as fallback.")
                        registry_id = "p/default"
                    
                    cmd.extend(["--config", registry_id])
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