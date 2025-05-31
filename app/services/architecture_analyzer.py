import os
from typing import Dict, List, Any
from app.config import settings

def analyze_architecture(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Analyze code for architectural issues like God Class and Long Method.
    """
    vulnerabilities = []
    
    for file_path, content in files.items():
        # Count total lines of code (excluding empty lines and comments)
        lines = [line.strip() for line in content.splitlines() 
                if line.strip() and not line.strip().startswith(('#', '//', '/*', '*', '*/')) ]
        total_lines = len(lines)
        
        # Check for God Class (over settings.god_class_threshold LOC)
        if total_lines > settings.god_class_threshold:
            vulnerabilities.append({
                "check_id": "ARCH-001",
                "path": file_path,
                "start": {"line": 1, "col": 1},
                "end": {"line": total_lines, "col": 1},
                "extra": {
                    "severity": "medium",
                    "metadata": {
                        "category": "Architecture",
                        "cwe": "",
                        "owasp": ""
                    },
                    "message": f"God Class detected: File has {total_lines} lines of code (threshold: {settings.god_class_threshold})",
                    "lines": f"Total lines: {total_lines}",
                    "score": 5
                },
                "severity": "warning"
            })
        
        # Check for Long Methods
        current_method_start = 0
        current_method_lines = 0
        in_method = False
        
        for i, line in enumerate(lines, 1):
            # Simple method detection - can be improved based on language
            if any(keyword in line for keyword in ['def ', 'function ', 'public ', 'private ', 'protected ']):
                if in_method and current_method_lines > settings.long_method_threshold:
                    vulnerabilities.append({
                        "check_id": "ARCH-002",
                        "path": file_path,
                        "start": {"line": current_method_start, "col": 1},
                        "end": {"line": i - 1, "col": 1},
                        "extra": {
                            "severity": "medium",
                            "metadata": {
                                "category": "Architecture",
                                "cwe": "",
                                "owasp": ""
                            },
                            "message": f"Long Method detected: Method has {current_method_lines} lines of code (threshold: {settings.long_method_threshold})",
                            "lines": f"Method length: {current_method_lines} lines",
                            "score": 5
                        },
                        "severity": "warning"
                    })
                
                current_method_start = i
                current_method_lines = 0
                in_method = True
            elif in_method:
                current_method_lines += 1
        
        # Check last method in file
        if in_method and current_method_lines > settings.long_method_threshold:
            vulnerabilities.append({
                "check_id": "ARCH-002",
                "path": file_path,
                "start": {"line": current_method_start, "col": 1},
                "end": {"line": len(lines), "col": 1},
                "extra": {
                    "severity": "medium",
                    "metadata": {
                        "category": "Architecture",
                        "cwe": "",
                        "owasp": ""
                    },
                    "message": f"Long Method detected: Method has {current_method_lines} lines of code (threshold: {settings.long_method_threshold})",
                    "lines": f"Method length: {current_method_lines} lines",
                    "score": 5
                },
                "severity": "warning"
            })
    
    return vulnerabilities 