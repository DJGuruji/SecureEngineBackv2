import os
import yaml
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

RULES_DIR = os.path.dirname(os.path.abspath(__file__))
RULE_FILES = {
    "sec-hardcoded-credentials": "sec-hardcoded-credentials.yaml",
    "sec-sql-injection": "sec-sql-injection.yaml",
    "sec-command-injection": "sec-command-injection.yaml",
    "sec-no-ssl-verification": "sec-no-ssl-verification.yaml",
    "sec-open-redirect": "sec-open-redirect.yaml",
    "sec-xss-reflection": "sec-xss-reflection.yaml",
    "bug-null-dereference": "bug-null-dereference.yaml",
    "maint-dead-code": "maint-dead-code.yaml",
    "perf-expensive-loop": "perf-expensive-loop.yaml",
    "style-unused-imports": "style-unused-imports.yaml",
    "maint-long-function": "maint-long-function.yaml",
    "sec-insecure-hashing": "sec-insecure-hashing.yaml"
}


def get_custom_rule_by_id(rule_id: str) -> Optional[Dict]:
    """Get a specific custom semgrep rule by ID."""
    if rule_id not in RULE_FILES:
        logger.warning(f"Rule ID {rule_id} not found in custom rules")
        return None
    
    try:
        rule_path = os.path.join(RULES_DIR, RULE_FILES[rule_id])
        logger.info(f"Loading custom rule from {rule_path}")
        
        with open(rule_path, 'r') as f:
            rule_data = yaml.safe_load(f)
            
        # Return the rule definition
        return rule_data
    except Exception as e:
        logger.error(f"Error loading custom rule {rule_id}: {str(e)}")
        return None


def get_all_custom_rules(query: Optional[str] = None, 
                        limit: int = 50, 
                        offset: int = 0,
                        severity: Optional[str] = None,
                        rule_type: Optional[str] = None) -> Dict:
    """Get all custom semgrep rules with filtering and pagination."""
    try:
        rules = []
        
        # Load all rules from the files
        for rule_id, filename in RULE_FILES.items():
            try:
                rule_path = os.path.join(RULES_DIR, filename)
                with open(rule_path, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    
                if not rule_data or "rules" not in rule_data:
                    logger.warning(f"Invalid rule format in {filename}")
                    continue
                    
                # Process each rule in the file
                for rule in rule_data["rules"]:
                    # Skip rules without an ID
                    if not rule.get("id"):
                        continue
                        
                    # Extract rule type from metadata
                    category = rule.get("metadata", {}).get("category", "")
                    subcategory = rule.get("metadata", {}).get("subcategory", "")
                    
                    # Combine category and subcategory for rule_type
                    extracted_rule_type = f"{category}-{subcategory}" if subcategory else category
                    
                    # Format each rule
                    formatted_rule = {
                        "id": rule.get("id", ""),
                        "name": rule.get("id", "Unknown Rule"),
                        "description": rule.get("message", "No description available"),
                        "category": category,
                        "languages": rule.get("languages", []),
                        "severity": rule.get("severity", "WARNING"),
                        "patterns": rule.get("patterns", []),
                        "message": rule.get("message", ""),
                        "metadata": rule.get("metadata", {}),
                        "fix": rule.get("fix", ""),
                        "rule_type": extracted_rule_type
                    }
                    rules.append(formatted_rule)
            except Exception as e:
                logger.error(f"Error loading rule from {filename}: {str(e)}")
                continue
        
        # Filter by query if provided
        if query:
            query_lower = query.lower()
            rules = [
                rule for rule in rules
                if query_lower in rule["id"].lower() or
                   query_lower in (rule["name"] or "").lower() or
                   query_lower in (rule["description"] or "").lower() or
                   (rule.get("category") and query_lower in rule["category"].lower()) or
                   any(query_lower in lang.lower() for lang in rule.get("languages", []))
            ]
            
        # Filter by severity if provided
        if severity and severity.lower() != "all":
            severity_lower = severity.lower()
            rules = [
                rule for rule in rules
                if rule.get("severity", "").lower() == severity_lower
            ]
            
        # Filter by rule_type if provided
        if rule_type:
            rules = [
                rule for rule in rules
                if rule_type.lower() in rule.get("rule_type", "").lower()
            ]
            
        # Apply pagination
        total = len(rules)
        paged_rules = rules[offset:offset + limit]
        has_more = (offset + limit) < total
        
        return {
            "rules": paged_rules,
            "total": total,
            "has_more": has_more,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting custom rules: {str(e)}")
        return {
            "rules": [],
            "total": 0,
            "has_more": False,
            "limit": limit,
            "offset": offset
        } 