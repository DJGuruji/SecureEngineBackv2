import subprocess
import json
import logging
import tempfile
import os
from typing import List, Dict, Optional
from fastapi import HTTPException, status
import yaml

logger = logging.getLogger(__name__)

def run_semgrep(file_path: str, custom_rule: Optional[str] = None) -> List[Dict]:
    """Run semgrep on a file or directory and return results."""
    try:
        logger.info(f"Running semgrep on {file_path}")
        
        # Log file content for debugging
        try:
            with open(file_path, 'r') as f:
                file_content = f.read()
                logger.info(f"File content:\n{file_content}")
        except Exception as e:
            logger.warning(f"Could not read file content: {str(e)}")
        
        # Base command
        cmd = ["semgrep", "--json", "--verbose"]
        
        # Handle custom rule
        if custom_rule:
            try:
                logger.info("Processing custom rule...")
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
        
        # Add target file
        cmd.append(file_path)
        logger.info(f"Full semgrep command: {' '.join(cmd)}")
        
        # Run semgrep
        result = subprocess.run(cmd, capture_output=True, text=True)
        
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