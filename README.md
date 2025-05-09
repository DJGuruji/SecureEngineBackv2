# Fast API secure engine version 2

## add supabase credentias to .env

```
   SUPABASE_URL=
   SUPABASE_KEY=

```

## download codeql by
```
wget https://github.com/github/codeql-cli-binaries/releases/download/v2.16.5/codeql-linux64.zip
```

## ls and if you find codeql-linux64.zip, then unzip it by 
```
unzip codeql-linux64.zip
```

# SecureEngine Backend

This is the backend service for SecureEngine, a security scanning application that integrates multiple security scanning tools.

## Features

- Upload and scan files for security vulnerabilities
- Multiple scanning engines:
  - Semgrep for pattern-based vulnerability detection
  - CodeQL for deeper semantic security analysis
- Persistence of scan results using Supabase
- RESTful API for integration with the frontend

## Scanner Comparison

### Semgrep vs CodeQL

Both scanners provide valuable security insights but work differently:

**Semgrep:**
- Pattern-based detection
- Fast and lightweight
- Rule-based approach
- May find more results due to simpler pattern matching

**CodeQL:**
- Semantic code analysis
- Creates a database of code structure
- Query-based approach
- May find fewer but more precise vulnerabilities

### Output Format Differences

The output formats differ between tools:
- Semgrep outputs JSON in its own custom format
- CodeQL outputs SARIF format

The application normalizes both formats into a common structure for consistent frontend display.

### Known Issues

1. For the same file, Semgrep may show more vulnerabilities than CodeQL. This is expected behavior as:
   - Different detection engines have different sensitivity levels
   - Semgrep's pattern-matching may produce more false positives
   - CodeQL's database approach may miss some patterns but provides higher confidence

2. Severity classification:
   - The system normalizes severities (ERROR/WARNING/INFO) consistently
   - Message content is analyzed to determine severity when not explicitly provided

## Setup and Running

1. Install dependencies:
```
pip install -r requirements.txt
```

2. Set up environment variables for Supabase:
```
export SUPABASE_URL=your_supabase_url
export SUPABASE_KEY=your_supabase_key
```

3. Run the server:
```
uvicorn app.main:app --reload
```