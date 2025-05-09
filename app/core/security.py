from fastapi import HTTPException, status
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

def calculate_security_score(vulnerabilities: List[Dict]) -> int:
    """Calculate security score based on vulnerabilities."""
    try:
        # Point deductions for each severity level
        point_deductions = {
            "ERROR": 2.0,    # Most severe: -2 points each
            "WARNING": 1.0,  # Medium severity: -1 point each
            "INFO": 0.4      # Least severe: -0.4 points each
        }
        
        if not vulnerabilities:
            return 10  # Perfect score if no vulnerabilities
            
        # Calculate base score (starts at 10)
        base_score = 10.0
        
        # Deduct points based on severity
        for vuln in vulnerabilities:
            # First check if the expected severity format is in extra.severity
            if 'extra' in vuln and 'severity' in vuln['extra']:
                severity = vuln['extra']['severity'].upper()
            else:
                # Fall back to the severity field and normalize it
                severity = vuln.get('severity', 'info').upper()
                # Handle different severity naming conventions
                if severity == 'ERROR' or severity == 'CRITICAL' or severity == 'HIGH':
                    severity = 'ERROR'
                elif severity == 'WARNING' or severity == 'MEDIUM':
                    severity = 'WARNING'
                else:
                    severity = 'INFO'
            
            deduction = point_deductions.get(severity, 0.4)  # Default to INFO deduction if unknown
            base_score -= deduction
            
        # Ensure score is between 0 and 10
        security_score = max(0, min(10, base_score))
        
        return int(round(security_score))
    except Exception as e:
        logger.error(f"Error calculating security score: {str(e)}")
        # Don't raise an exception, return a default score
        return 5

def count_severities(vulnerabilities):
    """Count the number of vulnerabilities by severity."""
    severity_counts = {
        "ERROR": 0,
        "WARNING": 0,
        "INFO": 0
    }
    
    for vuln in vulnerabilities:
        # First check if the expected severity format is in extra.severity
        if 'extra' in vuln and 'severity' in vuln['extra']:
            severity = vuln['extra']['severity'].upper()
        else:
            # Fall back to the severity field and normalize it
            severity = vuln.get('severity', 'info').upper()
            # Handle different severity naming conventions
            if severity == 'ERROR' or severity == 'CRITICAL' or severity == 'HIGH':
                severity = 'ERROR'
            elif severity == 'WARNING' or severity == 'MEDIUM':
                severity = 'WARNING'
            else:
                severity = 'INFO'
        
        # Update count
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            # Default to INFO if it's not a recognized severity
            severity_counts["INFO"] += 1
    
    return severity_counts 