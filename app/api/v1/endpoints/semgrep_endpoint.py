from fastapi import APIRouter, UploadFile, File, HTTPException, status, Form, Query
import os
import tempfile
import shutil
import logging
import time
from typing import Dict, Any, Optional, List
from app.services.semgrep_service import run_semgrep, fetch_semgrep_rules
from app.services.supabase_service import store_scan_results, get_scan_history, get_scan_by_id, delete_scan
from app.core.security import calculate_security_score, count_severities
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

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

@router.get("/semgrep-rules")
async def get_semgrep_rules(
    query: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None)
):
    """Fetch Semgrep rules from the registry."""
    try:
        rules = fetch_semgrep_rules(query, limit, offset, severity)
        return rules
    except ValueError as e:
        logger.error(f"Error fetching semgrep rules: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        ) 