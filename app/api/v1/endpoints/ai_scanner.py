from fastapi import APIRouter, UploadFile, File, HTTPException, status, Form, Query
import os
import tempfile
import shutil
import logging
import time
from typing import Dict, Any, Optional
from app.services.supabase_service import store_scan_results, use_credits_for_ai_scan, get_user_credits
from app.services.gemini_service import scan_code_with_gemini

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/ai-scan")
async def ai_scan(file: UploadFile = File(...), user_id: str = Query("default")):
    """Scan a file using Gemini AI and return the results."""
    try:
        logger.info(f"Starting Gemini AI scan for file: {file.filename}")
        start_time = time.time()
        
        # Check and use credits (2 credits per AI scan)
        
        # First get current credit status
        credit_info = get_user_credits(user_id)
        logger.info(f"User {user_id} has {credit_info['remaining_credits']} credits remaining")
        
        # Check if user has enough credits
        if credit_info['remaining_credits'] < 2:
            logger.warning(f"User {user_id} has insufficient credits for AI scan")
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="Insufficient credits for AI scan. Please add more credits."
            )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save uploaded file to temp directory
            file_path = os.path.join(temp_dir, file.filename)
            
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
                
            # Run the Gemini AI scan
            scan_results = await scan_code_with_gemini(file_path)
            
            # Add scan duration
            scan_results["scan_duration"] = time.time() - start_time
            
            # Add explicit logging for debugging vulnerability counts
            logger.info(f"AI Scan vulnerability counts: {scan_results['severity_count']}")
            logger.info(f"AI Scan security score: {scan_results['security_score']}")
            logger.info(f"AI Scan total vulnerabilities: {scan_results['total_vulnerabilities']}")
            
            # Store results in database
            result_id = store_scan_results(scan_results)
            logger.info(f"AI Scan results stored with ID: {result_id}")
            
            # Deduct the credit for this scan AFTER successful completion
            used_credit = use_credits_for_ai_scan(user_id, 2)
            logger.info(f"Used 2 credits for AI scan. User {user_id} now has {used_credit['remaining_credits']} credits remaining")
            
            # Add credit info to response
            scan_results["credit_info"] = {
                "used_credits": used_credit["used_credits"],
                "remaining_credits": used_credit["remaining_credits"]
            }
            
            logger.info(f"Gemini AI scan completed in {time.time() - start_time:.2f} seconds")
            return scan_results
            
    except HTTPException:
        # Re-raise HTTP exceptions (like 402 Payment Required)
        raise
    except Exception as e:
        logger.error(f"Error in Gemini AI scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        ) 