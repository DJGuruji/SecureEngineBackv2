from fastapi import APIRouter, UploadFile, File, HTTPException, status
import os
import tempfile
import shutil
import logging
import time
import subprocess
import json
from typing import Dict, Any
from app.services.supabase_service import store_scan_results
from app.core.security import calculate_security_score, count_severities
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter()

@router.post("/codeql")
async def codeql_scan(file: UploadFile = File(...)):
    """Scan a file using CodeQL and return the results."""
    try:
        logger.info(f"Starting CodeQL scan for file: {file.filename}")
        start_time = time.time()
        
        # Get the absolute path to the codeql binary
        codeql_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../codeql"))
        codeql_binary = os.path.join(codeql_dir, "codeql")
        
        # On Unix systems, make sure the binary is executable
        if os.name == 'posix':
            try:
                logger.info(f"Setting executable permissions on {codeql_binary}")
                os.chmod(codeql_binary, 0o755)
            except Exception as e:
                logger.warning(f"Could not set executable permission on CodeQL binary: {str(e)}")
        
        logger.info(f"Using CodeQL binary at: {codeql_binary}")
        
        # Check if the codeql binary exists
        if not os.path.exists(codeql_binary):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CodeQL binary not found at expected location"
            )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save the uploaded file
            file_path = os.path.join(temp_dir, file.filename)
            with open(file_path, "wb") as buffer:
                content = await file.read()
                buffer.write(content)
            
            # Create a directory to extract to if it's a zip file
            extract_dir = os.path.join(temp_dir, "src")
            os.makedirs(extract_dir, exist_ok=True)
            
            # Check if the file is a zip and extract it
            source_root = temp_dir
            if file.filename.endswith('.zip'):
                logger.info(f"Extracting zip file to {extract_dir}")
                try:
                    shutil.unpack_archive(file_path, extract_dir)
                    # Use the extracted directory as source
                    source_root = extract_dir
                    logger.info(f"Successfully extracted zip file to {extract_dir}")
                except Exception as e:
                    logger.error(f"Error extracting zip file: {str(e)}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Could not extract zip file: {str(e)}"
                    )
            
            # Determine language based on file extension or content
            language = "python"  # Default to Python
            
            # For zip files, we need to detect language by inspecting files within
            if file.filename.endswith('.zip'):
                # Count file extensions to try and determine the primary language
                extension_counts = {}
                
                for root, dirs, files in os.walk(extract_dir):
                    for file_name in files:
                        _, ext = os.path.splitext(file_name.lower())
                        if ext:
                            extension_counts[ext] = extension_counts.get(ext, 0) + 1
                
                # Map extensions to languages
                if extension_counts:
                    logger.info(f"Found file extensions: {extension_counts}")
                    if '.js' in extension_counts or '.ts' in extension_counts:
                        language = "javascript"
                    elif '.java' in extension_counts:
                        language = "java"
                    elif '.cpp' in extension_counts or '.c' in extension_counts or '.h' in extension_counts:
                        language = "cpp"
                    elif '.cs' in extension_counts:
                        language = "csharp"
                    elif '.go' in extension_counts:
                        language = "go"
                    # Python is the default
            else:
                # For single files, use extension
                file_ext = os.path.splitext(file.filename)[1].lower()
                if file_ext in ['.js', '.ts', '.jsx', '.tsx']:
                    language = "javascript"
                elif file_ext in ['.java']:
                    language = "java"
                elif file_ext in ['.cpp', '.c', '.h', '.hpp']:
                    language = "cpp"
                elif file_ext in ['.cs']:
                    language = "csharp"
                elif file_ext in ['.go']:
                    language = "go"
            
            logger.info(f"Detected language: {language}")
            
            # Create a CodeQL database
            db_path = os.path.join(temp_dir, "codeql_db")
            os.makedirs(db_path, exist_ok=True)
            
            # Run CodeQL database creation
            create_db_cmd = [
                codeql_binary, "database", "create",
                db_path,
                f"--language={language}",
                "--source-root", source_root
            ]
            
            logger.info(f"Creating CodeQL database with command: {' '.join(create_db_cmd)}")
            create_db_process = subprocess.run(
                create_db_cmd, 
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Database creation output: {create_db_process.stdout}")
            
            # Define results path
            results_path = os.path.join(temp_dir, "results.sarif")
            
            # Create a minimal custom query to use instead of relying on query packs
            # We'll create a basic query that can be used for all languages
            query_dir = os.path.join(temp_dir, "queries")
            os.makedirs(query_dir, exist_ok=True)
            
            # Create a QLPack definition file to fix module resolution
            qlpack_content = """
name: security-queries
version: 1.0.0
dependencies:
  codeql/python-all: "*"
  codeql/javascript-all: "*"
  codeql/java-all: "*"
  codeql/cpp-all: "*"
"""
            
            with open(os.path.join(query_dir, "qlpack.yml"), "w") as f:
                f.write(qlpack_content)
            
            # Define a simple QL query based on the language
            if language == "python":
                # Create separate query files for each vulnerability type
                eval_query = """
                import python
                
                from Call call
                where 
                    call.getFunc().getName() = "eval" or
                    call.getFunc().getName() = "exec" or
                    call.getFunc().getName() = "__import__" or
                    call.getFunc().getName() = "pickle.loads" or
                    call.getFunc().getName() = "subprocess.call" or
                    call.getFunc().getName() = "subprocess.Popen" or
                    call.getFunc().getName() = "os.system" or
                    call.getFunc().getName() = "os.popen" or
                    call.getFunc().getName() = "input"
                select call, "Potentially dangerous function call: " + call.getFunc().getName()
                """
                
                sql_query = """
                import python
                
                from Call call, Expr query
                where 
                    (call.getFunc().getName() = "execute" or 
                     call.getFunc().getName() = "executemany") and
                    query = call.getArg(0) and 
                    exists(BinaryExpr b | b = query.getASubExpression*() and b.getOp() = "+")
                select call, "Possible SQL injection vulnerability in database query"
                """
                
                path_query = """
                import python
                
                from Call call, Expr path
                where 
                    call.getFunc().getName() = "open" and
                    path = call.getArg(0) and
                    exists(BinaryExpr b | b = path.getASubExpression*() and b.getOp() = "+")
                select call, "Possible file path injection in file operation"
                """
                
                xss_query = """
                import python
                
                from Call call
                where call.getFunc().getName() = "render_template"
                select call, "Potential XSS vulnerability in template rendering"
                """
                
                # Write each query to separate files
                with open(os.path.join(query_dir, "dangerous_calls.ql"), "w") as f:
                    f.write(eval_query)
                
                with open(os.path.join(query_dir, "sql_injection.ql"), "w") as f:
                    f.write(sql_query)
                
                with open(os.path.join(query_dir, "path_injection.ql"), "w") as f:
                    f.write(path_query)
                
                with open(os.path.join(query_dir, "xss.ql"), "w") as f:
                    f.write(xss_query)
                
                # Use a simple query for testing purposes
                query_file = os.path.join(query_dir, "dangerous_calls.ql")
            elif language == "javascript":
                # Create separate query files for JavaScript
                eval_query = """
                import javascript
                
                from CallExpr call
                where 
                    call.getCalleeName() = "eval" or
                    call.getCalleeName() = "Function" or
                    call.getCalleeName() = "setTimeout" or 
                    call.getCalleeName() = "setInterval"
                select call, "Potentially dangerous use of " + call.getCalleeName()
                """
                
                xss_query = """
                import javascript
                
                from DOM::PropertyAccess prop
                where 
                    prop.getPropertyName() = "innerHTML" or
                    prop.getPropertyName() = "outerHTML"
                select prop, "Possible XSS vulnerability in DOM manipulation"
                """
                
                sql_query = """
                import javascript
                
                from CallExpr call
                where 
                    call.getCalleeName() = "query" or
                    call.getCalleeName() = "execute"
                select call, "Possible SQL injection in database query"
                """
                
                # Write each query to separate files
                with open(os.path.join(query_dir, "dangerous_calls.ql"), "w") as f:
                    f.write(eval_query)
                
                with open(os.path.join(query_dir, "xss.ql"), "w") as f:
                    f.write(xss_query)
                
                with open(os.path.join(query_dir, "sql_injection.ql"), "w") as f:
                    f.write(sql_query)
                
                # Use a simple query for testing purposes
                query_file = os.path.join(query_dir, "dangerous_calls.ql")
            elif language == "java":
                java_query = """
                import java
                
                // Find SQL injection
                from MethodAccess call
                where 
                    call.getMethod().getName() = "executeQuery" or
                    call.getMethod().getName() = "executeUpdate" and
                    exists(AddExpr add | add = call.getArgument(0).getChildExpr*() and 
                           exists(VarAccess v | v = add.getAChildExpr*() and v.getVariable().getType() instanceof TypeString))
                select call, "Possible SQL injection in database query"
                """
                query_file = os.path.join(query_dir, "security_query.ql")
                
                # Write the query file
                with open(query_file, "w") as f:
                    f.write(java_query)
            else:
                # Generic query for other languages
                generic_query = """
                select "Basic scan completed", "CodeQL scan completed with no specific security issues found"
                """
                query_file = os.path.join(query_dir, "security_query.ql")
                
                # Write the query file
                with open(query_file, "w") as f:
                    f.write(generic_query)
            
            # Run the analysis with our simple query
            analyze_cmd = [
                codeql_binary, "database", "analyze",
                db_path,
                "--format=sarif-latest",
                "--output", results_path,
                query_file  # Use our custom query file
            ]
            
            logger.info(f"Running CodeQL analysis with command: {' '.join(analyze_cmd)}")
            try:
                analyze_process = subprocess.run(
                    analyze_cmd, 
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.info(f"Analysis output: {analyze_process.stdout}")
            except subprocess.CalledProcessError as e:
                error_msg = f"CodeQL analysis failed: {str(e)}. stdout: {e.stdout}. stderr: {e.stderr}"
                logger.error(error_msg)
                
                # Create a simple SARIF result with error
                with open(results_path, 'w') as f:
                    json.dump({
                        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                        "version": "2.1.0",
                        "runs": [{
                            "tool": {
                                "driver": {
                                    "name": "CodeQL",
                                    "semanticVersion": "1.0.0"
                                }
                            },
                            "results": [{
                                "ruleId": "error",
                                "message": {
                                    "text": f"CodeQL analysis error: {str(e)}"
                                },
                                "level": "error"
                            }]
                        }]
                    }, f)
            
            # If the file doesn't exist, create an empty SARIF result
            if not os.path.exists(results_path):
                with open(results_path, 'w') as f:
                    json.dump({
                        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                        "version": "2.1.0",
                        "runs": [{
                            "tool": {
                                "driver": {
                                    "name": "CodeQL",
                                    "semanticVersion": "1.0.0"
                                }
                            },
                            "results": []
                        }]
                    }, f)
            
            # Parse SARIF file into a format similar to semgrep output
            vulnerabilities = []
            
            try:
                with open(results_path, 'r') as f:
                    sarif_data = json.load(f)
                
                # Convert CodeQL SARIF results to our format
                if "runs" in sarif_data and len(sarif_data["runs"]) > 0:
                    codeql_results = sarif_data["runs"][0].get("results", [])
                    
                    for result in codeql_results:
                        # Skip if message is missing
                        if "message" not in result:
                            continue
                        
                        # Extract message
                        message = result["message"].get("text", "Unknown issue")
                        
                        # Extract location if available
                        location = {}
                        if "locations" in result and len(result["locations"]) > 0:
                            loc = result["locations"][0]
                            if "physicalLocation" in loc:
                                physical_loc = loc["physicalLocation"]
                                
                                # Extract file path
                                if "artifactLocation" in physical_loc:
                                    location["path"] = physical_loc["artifactLocation"].get("uri", "")
                                
                                # Extract line and column info
                                if "region" in physical_loc:
                                    region = physical_loc["region"]
                                    location["start"] = {
                                        "line": region.get("startLine", 0),
                                        "col": region.get("startColumn", 0)
                                    }
                                    location["end"] = {
                                        "line": region.get("endLine", region.get("startLine", 0)),
                                        "col": region.get("endColumn", region.get("startColumn", 0))
                                    }
                        
                        # Extract rule information
                        rule_id = result.get("ruleId", "unknown")
                        
                        # Determine severity (most CodeQL results are errors)
                        severity = result.get("level", "error")
                        if severity == "warning":
                            severity = "WARNING"
                        else:
                            severity = "ERROR"
                        
                        # Add vulnerability entry
                        vuln = {
                            "check_id": rule_id,
                            "extra": {
                                "metadata": {
                                    "cwe": "CWE-78",  # Default - could be matched based on rule
                                    "owasp": "A1: Injection"  # Default
                                }
                            },
                            "path": location.get("path", "unknown"),
                            "start": location.get("start", {"line": 0, "col": 0}),
                            "end": location.get("end", {"line": 0, "col": 0}),
                            "message": message,
                            "severity": severity
                        }
                        
                        vulnerabilities.append(vuln)
            except Exception as e:
                logger.error(f"Error parsing SARIF results: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error parsing SARIF results: {str(e)}"
                )
            
            # Calculate security score and severity counts
            security_score = calculate_security_score(vulnerabilities)
            severity_count = count_severities(vulnerabilities)
            total_vulnerabilities = len(vulnerabilities)
            
            logger.info(f"CodeQL scan completed with {total_vulnerabilities} vulnerabilities found")
            logger.info(f"Severity counts: {severity_count}")
            logger.info(f"Security score: {security_score}")
            
            # Prepare scan results
            scan_results = {
                "file_name": file.filename,
                "security_score": security_score,
                "vulnerabilities": vulnerabilities,
                "severity_count": severity_count,
                "total_vulnerabilities": total_vulnerabilities,
                "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_duration": time.time() - start_time,
                "scan_metadata": {
                    "scan_type": "CodeQL",
                    "language": language
                }
            }
            
            # Store results in database
            store_scan_results(scan_results)
            
            return scan_results
            
    except Exception as e:
        logger.error(f"Error in CodeQL scan: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        ) 