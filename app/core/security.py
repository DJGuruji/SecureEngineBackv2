from fastapi import HTTPException, status
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

def calculate_security_score(vulnerabilities: List[Dict[str, Any]]) -> float:
    """
    Calculate a security score from 0-10 based on vulnerabilities.
    Critical vulnerabilities like command injection and SQL injection will heavily impact the score.
    """
    if not vulnerabilities:
        return 10.0
        
    base_score = 10.0
    
    # Critical vulnerability patterns that should heavily impact score
    critical_patterns = {
        'command injection': 5.0,  # Deduct 5 points for command injection
        'sql injection': 4.0,      # Deduct 4 points for SQL injection
        'rce': 5.0,                # Deduct 5 points for RCE
        'remote code execution': 5.0,
        'cwe-78': 5.0,            # Command Injection
        'cwe-89': 4.0,            # SQL Injection
        'cwe-94': 5.0,            # Code Injection
        'cwe-77': 5.0,            # Command Injection
        'cwe-95': 4.5,            # Eval Injection
        'cwe-502': 4.0,           # Deserialization of Untrusted Data
    }
    
    # Severity multipliers
    severity_multipliers = {
        'critical': 1.0,
        'high': 0.8,
        'medium': 0.6,
        'low': 0.4,
        'info': 0.2,
        'ERROR': 1.0,
        'WARNING': 0.6,
        'INFO': 0.3
    }
    
    for vuln in vulnerabilities:
        deduction = 0.0
        
        # Check for critical patterns in various fields
        check_fields = [
            vuln.get('check_id', '').lower(),
            vuln.get('message', '').lower(),
            str(vuln.get('extra', {})).lower()
        ]
        
        for field in check_fields:
            for pattern, penalty in critical_patterns.items():
                if pattern in field:
                    deduction = max(deduction, penalty)  # Take highest penalty if multiple patterns match
        
        # Apply severity multiplier
        severity = vuln.get('severity', '').lower()
        if not severity:
            severity = vuln.get('extra', {}).get('severity', 'medium').lower()
            
        multiplier = severity_multipliers.get(severity, 0.5)
        
        # If it's a critical vulnerability type but marked as low severity, still apply high impact
        if deduction >= 4.0:  # Critical vuln types
            multiplier = max(multiplier, 0.8)  # Ensure at least high severity multiplier
            
        final_deduction = deduction * multiplier
        
        # Additional deductions for specific risk factors
        if vuln.get('exploitability', '').lower() == 'high':
            final_deduction *= 1.2
        if vuln.get('impact', '').lower() == 'high':
            final_deduction *= 1.2
            
        base_score -= final_deduction
    
    # Ensure score doesn't go below 0 or above 10
    return max(0.0, min(10.0, base_score))

def count_severities(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count vulnerabilities by severity level."""
    counts = {
        'ERROR': 0,
        'WARNING': 0,
        'INFO': 0
    }
    
    severity_mapping = {
        'critical': 'ERROR',
        'high': 'ERROR',
        'medium': 'WARNING',
        'low': 'INFO',
        'info': 'INFO'
    }
    
    for vuln in vulnerabilities:
        # Get severity from either direct severity field or extra.severity
        severity = vuln.get('severity', '').lower()
        if not severity:
            severity = vuln.get('extra', {}).get('severity', 'medium').lower()
            
        # Map the severity to our three-level system
        mapped_severity = severity_mapping.get(severity, 'WARNING')
        
        # Override for critical vulnerability types regardless of marked severity
        check_fields = [
            vuln.get('check_id', '').lower(),
            vuln.get('message', '').lower()
        ]
        
        for field in check_fields:
            if any(x in field for x in ['command injection', 'sql injection', 'rce', 'remote code execution', 
                                      'cwe-78', 'cwe-89', 'cwe-94', 'cwe-77']):
                mapped_severity = 'ERROR'
                break
                
        counts[mapped_severity] += 1
        
    return counts 