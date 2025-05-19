"""
Scan exclusions configuration for security scanners.
"""
import fnmatch
import os
from typing import List, Set

# Common exclusion patterns for all scanners
EXCLUDED_PATTERNS = [
    # Node.js & Next.js
    "node_modules/",
    ".next/",
    "out/",
    "coverage/",
    "dist/",
    "build/",
    "*.log",
    ".vscode/",
    ".env*",
    ".env",
    "next.config.js",
    "tailwind.config.js",
    "tailwind.config.ts",
    "tsconfig.json",
    "package.json",
    "package-lock.json",
   
    
    
    # Python & FastAPI
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".venv/",
    "venv/",
    "env/",
    "*.egg-info/",
    ".mypy_cache/",
    ".pytest_cache/",
    ".coverage",
    "htmlcov/",
    "requirements.txt",  # Dependency specification file
    "supabase.py",  # Supabase configuration file
    
    # Frontend build artifacts & Supabase
    "public/",
    ".supabase/",
    ".supabase/functions/node_modules/",
    "supabase/.temp/",
    
    # Configuration files
    "nginx.conf",
    "env.example",
    
    # Git & OS files
    ".DS_Store",
    ".git/",
    ".gitignore",
    
    # Test data & snapshots
    "cypress/",
    "tests/",
    "__tests__/",
    "test/",
    "*.spec.js",
    "*.spec.ts",
    "*.test.js",
    "*.test.ts",
    "*.snap",
    
    # Docker and CI/CD
    "docker-compose.override.yml",
    "Dockerfile*",
    "*.dockerfile",
    "*.yaml",
    "*.yml",
    
    # IDE-specific
    ".idea/",
    "*.swp",
    "*.swo",
    
    # Specific to CodeQL
    "codeql-database/",
    "codeql-pack.yml",
    "codeql-workspace.yml"
]

def should_exclude_path(path: str) -> bool:
    """
    Check if a file or directory path should be excluded based on patterns.
    
    Args:
        path: The path to check, can be relative or absolute
    
    Returns:
        True if the path should be excluded, False otherwise
    """
    # Normalize path to use forward slashes
    normalized_path = path.replace('\\', '/')
    
    # Check if path matches any of the exclusion patterns
    for pattern in EXCLUDED_PATTERNS:
        if fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(os.path.basename(normalized_path), pattern):
            return True
            
        # Check if any part of the path matches the pattern
        parts = normalized_path.split('/')
        for part in parts:
            if fnmatch.fnmatch(part, pattern):
                return True
    
    return False

def filter_excluded_dirs(dirs: List[str]) -> None:
    """
    Filter a list of directories in-place to remove excluded directories.
    
    Args:
        dirs: List of directory names to filter (modified in-place)
    """
    i = 0
    while i < len(dirs):
        if should_exclude_path(dirs[i]):
            dirs.pop(i)
        else:
            i += 1 