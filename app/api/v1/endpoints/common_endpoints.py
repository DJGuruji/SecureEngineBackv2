from fastapi import APIRouter, UploadFile, File, HTTPException, status, Form, Query, Path, Body
import os
import tempfile
import shutil
import logging
import time
from typing import Dict, Any, Optional, List
from app.services.semgrep_service import run_semgrep, fetch_semgrep_rules, fetch_semgrep_rule_by_id
from app.services.supabase_service import store_scan_results, get_scan_history, get_scan_by_id, delete_scan
from app.services.supabase_service import store_combined_scan_results, get_combined_scan_history, get_combined_scan_by_id, delete_combined_scan
from app.core.security import calculate_security_score, count_severities
import re

logger = logging.getLogger(__name__)
router = APIRouter()

def process_upload(file: UploadFile, custom_rule: Optional[str] = None) -> Dict[str, Any]:
    """Process the uploaded file and return vulnerability results."""
    try:
        logger.info(f"Processing file: {file.filename}")
        if custom_rule:
            logger.info("Custom rule provided")
            logger.debug(f"Custom rule content: {custom_rule}")
        else:
            logger.info("No custom rule provided, using default auto config")
            
        start_time = time.time()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save uploaded file to temp directory
            file_path = os.path.join(temp_dir, file.filename)
            extract_dir = os.path.join(temp_dir, "src")
            os.makedirs(extract_dir, exist_ok=True)
            
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # Determine the path to scan
            scan_path = file_path
            
            # Check if the file is a zip and extract it
            if file.filename.endswith('.zip'):
                logger.info(f"Extracting zip file: {file.filename}")
                try:
                    shutil.unpack_archive(file_path, extract_dir)
                    # Use the extracted directory as source for scanning
                    scan_path = extract_dir
                    logger.info(f"Successfully extracted zip file to {extract_dir}")
                except Exception as e:
                    logger.error(f"Error extracting zip file: {str(e)}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Could not extract zip file: {str(e)}"
                    )
            
            # Run semgrep scan on the appropriate path
            vulnerabilities = run_semgrep(scan_path, custom_rule)
            
            # Calculate security score and severity counts
            security_score = calculate_security_score(vulnerabilities)
            severity_count = count_severities(vulnerabilities)
            total_vulnerabilities = len(vulnerabilities)
            
            logger.info(f"Scan completed with {total_vulnerabilities} vulnerabilities found")
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
                    "scan_type": "SAST",
                    "scan_mode": "custom" if custom_rule else "auto"
                }
            }
            
            # Store results in database
            store_scan_results(scan_results)
            
            return scan_results
            
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    custom_rule: Optional[str] = Form(None)
):
    """Upload a file for scanning."""
    try:
        return process_upload(file, custom_rule)
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/history")
async def get_history(limit: int = 10, offset: int = 0):
    """Retrieve scan history with pagination."""
    try:
        return get_scan_history(limit, offset)
    except Exception as e:
        logger.error(f"Error retrieving scan history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Retrieve a specific scan by ID."""
    try:
        return get_scan_by_id(scan_id)
    except Exception as e:
        logger.error(f"Error retrieving scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.delete("/scan/{scan_id}")
async def delete_scan_record(scan_id: str):
    """Delete a scan record by ID."""
    try:
        # First check if the scan exists
        scan = get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
            
        # If scan exists, proceed with deletion
        await delete_scan(scan_id)
        return {"message": "Scan deleted successfully"}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error deleting scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting scan: {str(e)}"
        )

@router.post("/combined-results")
async def store_combined_results(combined_results: dict):
    """Store combined scan results from multiple scanners."""
    try:
        logger.info("Storing combined scan results")
        
        # Debug logging
        vuln_count = len(combined_results.get("vulnerabilities", []))
        logger.info(f"Received combined results with {vuln_count} vulnerabilities")
        logger.info(f"Severity count: {combined_results.get('severity_count', {})}")
        logger.info(f"Total vulnerabilities reported: {combined_results.get('total_vulnerabilities', 0)}")
        
        if vuln_count == 0 and combined_results.get('total_vulnerabilities', 0) > 0:
            logger.warning("Vulnerability count mismatch: total_vulnerabilities > 0 but vulnerabilities array is empty")
            
            # Check if vulnerabilities data might be in a different format or lost in transmission
            for key, value in combined_results.items():
                logger.debug(f"Combined results key: {key}, type: {type(value)}")
        
        # Log the first vulnerability if available
        if vuln_count > 0:
            logger.info(f"First vulnerability sample: {combined_results['vulnerabilities'][0]}")
        
        # Store in database
        result_id = store_scan_results(combined_results)
        
        logger.info(f"Combined scan results stored with ID: {result_id}")
        
        return {"success": True, "scan_id": result_id}
    except Exception as e:
        logger.error(f"Error storing combined scan results: {str(e)}")
        logger.exception("Exception details:")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error storing combined scan results: {str(e)}"
        )

@router.get("/semgrep-rules")
async def get_semgrep_rules(
    query: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    rule_type: Optional[str] = Query(None)
):
    """Fetch Semgrep rules from the registry."""
    try:
        rules = fetch_semgrep_rules(query, limit, offset, severity, rule_type)
        return rules
    except ValueError as e:
        logger.error(f"Error fetching semgrep rules: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/semgrep-rule/{rule_id}")
async def get_semgrep_rule_by_id(rule_id: str):
    """Get details for a specific semgrep rule by ID."""
    try:
        return fetch_semgrep_rule_by_id(rule_id)
    except Exception as e:
        logger.error(f"Error fetching semgrep rule by id: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/combined-results/{sast_scan_id}/{ai_scan_id}")
async def combine_scan_results(
    sast_scan_id: str = Path(..., description="ID of the SAST scan"),
    ai_scan_id: str = Path(..., description="ID of the AI scan"),
    project_name: str = Query(None, description="Optional project name for the combined scan")
) -> Dict[str, Any]:
    """
    Combine results from a SAST scan and an AI scan into a single record.
    
    Args:
        sast_scan_id: ID of the SAST scan
        ai_scan_id: ID of the AI scan
        project_name: Optional project name
        
    Returns:
        The combined scan record
    """
    try:
        logger.info(f"Combining SAST scan {sast_scan_id} with AI scan {ai_scan_id}")
        
        combined_scan = store_combined_scan_results(
            sast_scan_id=sast_scan_id,
            ai_scan_id=ai_scan_id,
            project_name=project_name
        )
        
        logger.info(f"Successfully created combined scan with ID: {combined_scan.get('id')}")
        return combined_scan
    except Exception as e:
        logger.error(f"Error combining scan results: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error combining scan results: {str(e)}"
        )

@router.get("/combined-scans")
async def get_combined_scans(
    limit: int = Query(10, description="Maximum number of scan results to return"),
    offset: int = Query(0, description="Number of scan results to skip")
) -> List[Dict[str, Any]]:
    """
    Get list of combined scan results with pagination.
    
    Args:
        limit: Maximum number of scan results to return
        offset: Number of scan results to skip
        
    Returns:
        List of combined scan records
    """
    try:
        logger.info(f"Getting combined scan history: limit={limit}, offset={offset}")
        return get_combined_scan_history(limit=limit, offset=offset)
    except Exception as e:
        logger.error(f"Error getting combined scan history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting combined scan history: {str(e)}"
        )

@router.get("/combined-scan/{scan_id}")
async def get_combined_scan(
    scan_id: str = Path(..., description="ID of the combined scan to retrieve")
) -> Dict[str, Any]:
    """
    Get a specific combined scan by ID.
    
    Args:
        scan_id: ID of the combined scan to retrieve
        
    Returns:
        The combined scan record
    """
    try:
        logger.info(f"Getting combined scan with ID: {scan_id}")
        scan = get_combined_scan_by_id(scan_id)
        
        if not scan:
            logger.warning(f"Combined scan with ID {scan_id} not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Combined scan with ID {scan_id} not found"
            )
            
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting combined scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting combined scan: {str(e)}"
        )

@router.delete("/combined-scan/{scan_id}")
async def remove_combined_scan(
    scan_id: str = Path(..., description="ID of the combined scan to delete")
) -> Dict[str, Any]:
    """
    Delete a combined scan by ID.
    
    Args:
        scan_id: ID of the combined scan to delete
        
    Returns:
        Success message
    """
    try:
        logger.info(f"Deleting combined scan with ID: {scan_id}")
        await delete_combined_scan(scan_id)
        
        return {"message": f"Successfully deleted combined scan {scan_id}"}
    except Exception as e:
        logger.error(f"Error deleting combined scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting combined scan: {str(e)}"
        )

def extract_cve_id(filename: str, file_content: str = None) -> str:
    """Extract CVE ID from filename and file content if present."""
    # Common CVE ID patterns
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    
    # First check filename
    match = re.search(cve_pattern, filename, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    
    # Then check file content if provided
    if file_content:
        matches = re.findall(cve_pattern, file_content, re.IGNORECASE)
        if matches:
            return matches[0].upper()  # Return the first CVE ID found
            
    return None

@router.get("/combined-scan-compare/{scan_id}")
async def compare_combined_scan_with_exploitdb(
    scan_id: str = Path(..., description="ID of the combined scan to compare with ExploitDB")
) -> Dict[str, Any]:
    try:
        logger.info(f"Comparing combined scan {scan_id} with ExploitDB")
        
        # First get the combined scan data
        scan = get_combined_scan_by_id(scan_id)
        
        if not scan:
            logger.warning(f"Combined scan with ID {scan_id} not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Combined scan with ID {scan_id} not found"
            )
        
        file_name = scan.get("file_name", "Unknown")
        vulnerabilities = scan.get("vulnerabilities", [])
        
        # Get file content from vulnerabilities if available
        file_content = ""
        for vuln in vulnerabilities:
            if "extra" in vuln and "code_snippet" in vuln["extra"]:
                file_content += vuln["extra"]["code_snippet"] + "\n"
        
        # Extract CVE ID from both filename and content
        cve_id = extract_cve_id(file_name, file_content)
        
        has_vulnerabilities = len(vulnerabilities) > 0
        
        # Create mock matched patterns from vulnerability data
        matched_patterns = []
        if has_vulnerabilities:
            for vuln in vulnerabilities[:5]:
                check_id = vuln.get("check_id", "")
                if check_id and check_id not in matched_patterns:
                    matched_patterns.append(check_id)
        
        # Generate mock ExploitDB results if there are vulnerabilities
        mock_exploitdb_results = [
            {
                "title": "View File in ExploitDB " + file_name,
                "description": "",
                "date": time.strftime("%Y-%m-%d"),
                "type": "webapps",
                "link": "https://www.exploit-db.com/exploits/" + os.path.splitext(file_name)[0].replace(" ", "-").lower(),
                "vulnerabilities": [
                    {
                        "type": "Injection",
                        "description": "This vulnerability allows attackers to inject malicious code."
                    },
                    {
                        "type": "Authentication Bypass",
                        "description": "Authentication mechanisms can be bypassed."
                    }
                ],
                "cve": cve_id,
                "cve_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}" if cve_id else None,
                "verified": True
            }
        ]
        
        # Create the response
        mock_result = {
            "scan_id": scan_id,
            "file_name": file_name,
            "vulnerability_count": scan.get("total_vulnerabilities", 0),
            "matched_patterns": matched_patterns,
            "file_in_exploitdb": has_vulnerabilities,  # Pretend it's in the DB if it has vulnerabilities
            "exploitdb_results": mock_exploitdb_results,
            "comparison_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": vulnerabilities
        }
        
        return mock_result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error comparing combined scan with ExploitDB: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error comparing combined scan with ExploitDB: {str(e)}"
        ) 