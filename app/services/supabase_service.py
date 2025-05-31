from supabase import create_client
from typing import Dict, Any, List, Optional
import logging
from fastapi import HTTPException, status
from app.core.config import get_settings
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
settings = get_settings()

# Initialize Supabase client
try:
    supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
    logger.info("Successfully connected to Supabase")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {str(e)}")
    raise

def enhance_vulnerability_data(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """Enhance vulnerability data with risk severity and exploitability context."""
    # Get severity from Semgrep results
    severity = vulnerability.get("extra", {}).get("severity", "INFO")
    
    # Normalize severity to uppercase
    severity = severity.upper()
    
    # Risk severity calculation based on multiple factors
    risk_factors = {
        "ERROR": {
            "severity_weight": 1.0,
            "exploitability": "High",
            "impact": "Critical"
        },
        "WARNING": {
            "severity_weight": 0.7,
            "exploitability": "Medium",
            "impact": "Moderate"
        },
        "INFO": {
            "severity_weight": 0.3,
            "exploitability": "Low",
            "impact": "Low"
        }
    }
    
    # Get risk context, default to INFO if severity not found
    risk_context = risk_factors.get(severity, risk_factors["INFO"])
    
    # Ensure the severity is properly set in the vulnerability data
    if "extra" not in vulnerability:
        vulnerability["extra"] = {}
    vulnerability["extra"]["severity"] = severity
    
    return {
        **vulnerability,
        "risk_severity": risk_context["severity_weight"],
        "exploitability": risk_context["exploitability"],
        "impact": risk_context["impact"],
        "detection_timestamp": datetime.utcnow().isoformat()
    }

def store_scan_results(data: Dict[str, Any]) -> Dict[str, Any]:
    """Store scan results in Supabase and return the inserted record."""
    try:
        logger.info("Storing results in Supabase")
        
        # Debug logging for incoming vulnerabilities
        raw_vulnerabilities = data.get("vulnerabilities", [])
        logger.info(f"Received {len(raw_vulnerabilities)} vulnerabilities to enhance")
        
        if len(raw_vulnerabilities) > 0:
            logger.debug(f"First vulnerability before enhancement: {raw_vulnerabilities[0]}")
        
        # Check for common issues that might cause vulnerabilities to be empty
        if len(raw_vulnerabilities) == 0 and data.get("total_vulnerabilities", 0) > 0:
            logger.warning("Mismatch between total_vulnerabilities and actual vulnerabilities array")
            logger.debug(f"Data keys received: {list(data.keys())}")
            
            # Try to find if vulnerabilities are stored in a different key or format
            for key, value in data.items():
                if isinstance(value, list) and len(value) > 0:
                    logger.debug(f"Potential list found in key '{key}' with {len(value)} items")
                    if len(value) > 0:
                        logger.debug(f"Sample item from '{key}': {value[0]}")
        
        # Enhance vulnerability data
        enhanced_vulnerabilities = [
            enhance_vulnerability_data(vuln) 
            for vuln in raw_vulnerabilities
        ]
        
        logger.info(f"Enhanced {len(enhanced_vulnerabilities)} vulnerabilities")
        
        # Prepare scan history data
        scan_data = {
            "file_name": data["file_name"],
            "scan_timestamp": data.get("scan_timestamp", datetime.utcnow().isoformat()),
            "vulnerabilities": enhanced_vulnerabilities,
            "severity_count": data["severity_count"],
            "total_vulnerabilities": data["total_vulnerabilities"],
            "security_score": data["security_score"],
            "scan_status": "completed",
            "scan_duration": data.get("scan_duration", 0),
            "scan_metadata": data.get("scan_metadata", {
                "scan_type": "SAST",
                "scan_mode": "auto"
            })
        }
        
        # Store in scan_history table
        result = supabase.table("scan_history").insert(scan_data).execute()
        
        if not result.data:
            logger.error("Failed to store results in Supabase: No data returned")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store results in database"
            )
        
        scan_record = result.data[0]
        logger.info("Successfully stored results in Supabase")
        
        # Check if this is a "Combined SAST" or "AI" scan to also store in combined_scans
        scan_type = scan_data.get("scan_metadata", {}).get("scan_type")
        if scan_type in ["Combined SAST", "AI"]:
            logger.info(f"Detected {scan_type} scan, also storing in combined_scans table")
            
            # Store in project-record format
            project_name = f"Project-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            
            if scan_type == "Combined SAST":
                # If it's a SAST scan, store it with empty AI fields
                combined_data = {
                    "project_name": project_name,
                    "scan_timestamp": scan_data.get("scan_timestamp"),
                    "sast_scan_id": scan_record["id"],
                    "file_name": scan_data.get("file_name"),
                    "vulnerabilities": scan_data.get("vulnerabilities", []),
                    "severity_count": scan_data.get("severity_count", {}),
                    "total_vulnerabilities": scan_data.get("total_vulnerabilities", 0),
                    "security_score": scan_data.get("security_score", 5),
                    "scan_status": "completed",
                    "scan_duration": scan_data.get("scan_duration", 0),
                    "scan_metadata": {
                        "scan_type": "combined sast",
                        "sast_metadata": scan_data.get("scan_metadata", {}),
                        "source": "auto_combined"
                    }
                }
            elif scan_type == "AI":
                # If it's an AI scan, store it with empty SAST fields
                combined_data = {
                    "project_name": project_name,
                    "scan_timestamp": scan_data.get("scan_timestamp"),
                    "ai_scan_id": scan_record["id"],
                    "file_name": scan_data.get("file_name"),
                    "vulnerabilities": scan_data.get("vulnerabilities", []),
                    "severity_count": scan_data.get("severity_count", {}),
                    "total_vulnerabilities": scan_data.get("total_vulnerabilities", 0),
                    "security_score": scan_data.get("security_score", 5),
                    "scan_status": "completed",
                    "scan_duration": scan_data.get("scan_duration", 0),
                    "scan_metadata": {
                        "scan_type": "AI",
                        "ai_metadata": scan_data.get("scan_metadata", {}),
                        "source": "auto_combined"
                    }
                }
            
            try:
                combined_result = supabase.table("combined_scans").insert(combined_data).execute()
                if combined_result.data:
                    logger.info(f"Successfully stored {scan_type} scan in combined_scans table")
            except Exception as e:
                logger.error(f"Error storing in combined_scans table: {str(e)}")
                # Don't raise an exception here - we've already successfully stored in scan_history
        
        return scan_record
        
    except Exception as e:
        logger.error(f"Error storing results in Supabase: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

def get_scan_history(limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
    """Retrieve scan history with pagination."""
    try:
        result = supabase.table("scan_history") \
            .select("*") \
            .order("scan_timestamp", desc=True) \
            .limit(limit) \
            .offset(offset) \
            .execute()
        return result.data
    except Exception as e:
        logger.error(f"Error retrieving scan history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving scan history: {str(e)}"
        )

def get_scan_by_id(scan_id: str) -> Dict[str, Any]:
    """Retrieve a specific scan by ID."""
    try:
        result = supabase.table("scan_history") \
            .select("*") \
            .eq("id", scan_id) \
            .execute()
            
        if not result.data or len(result.data) == 0:
            return None
            
        return result.data[0]
    except Exception as e:
        logger.error(f"Error retrieving scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving scan: {str(e)}"
        )

async def delete_scan(scan_id: str) -> None:
    """Delete a scan record from Supabase."""
    try:
        # Delete the scan record
        response = supabase.table("scan_history").delete().eq("id", scan_id).execute()
        
        # Check if any records were deleted
        if not response.data or len(response.data) == 0:
            raise Exception(f"No scan found with ID: {scan_id}")
            
        logger.info(f"Successfully deleted scan {scan_id}")
    except Exception as e:
        logger.error(f"Error deleting scan from Supabase: {str(e)}")
        raise 

# Credit management functions
def get_user_credits(user_id: str = "default") -> Dict[str, Any]:
    """Get the current credit balance for a user."""
    try:
        result = supabase.table("user_credits") \
            .select("*") \
            .eq("user_id", user_id) \
            .execute()
        
        if not result.data or len(result.data) == 0:
            # Create default credits if they don't exist
            logger.info(f"No credits found for user {user_id}, creating default credits")
            return create_default_user_credits(user_id)
        
        return result.data[0]
    except Exception as e:
        logger.error(f"Error retrieving user credits: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving user credits: {str(e)}"
        )

def create_default_user_credits(user_id: str = "default") -> Dict[str, Any]:
    """Create default credits for a new user."""
    try:
        default_credits = {
            "user_id": user_id,
            "total_credits": 10,  # Starting credits
            "used_credits": 0,
            "remaining_credits": 10,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        result = supabase.table("user_credits").insert(default_credits).execute()
        
        if not result.data:
            logger.error("Failed to create default credits: No data returned")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create default credits"
            )
        
        logger.info(f"Created default credits for user {user_id}")
        return result.data[0]
    except Exception as e:
        logger.error(f"Error creating default credits: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating default credits: {str(e)}"
        )

def use_credits_for_ai_scan(user_id: str = "default", credits_to_use: int = 1) -> Dict[str, Any]:
    """Use credits for an AI scan and return updated credit info."""
    try:
        # Get current credits
        current_credits = get_user_credits(user_id)
        
        # Check if user has enough credits
        if current_credits["remaining_credits"] < credits_to_use:
            logger.error(f"User {user_id} does not have enough credits for AI scan")
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="Insufficient credits for AI scan"
            )
        
        # Calculate new values
        used_credits = current_credits["used_credits"] + credits_to_use
        remaining_credits = current_credits["remaining_credits"] - credits_to_use
        
        # Update credit record
        updated_credits = {
            "used_credits": used_credits,
            "remaining_credits": remaining_credits,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        result = supabase.table("user_credits") \
            .update(updated_credits) \
            .eq("user_id", user_id) \
            .execute()
        
        if not result.data:
            logger.error("Failed to update credits: No data returned")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update credits"
            )
        
        logger.info(f"Used {credits_to_use} credits for user {user_id}, remaining: {remaining_credits}")
        return result.data[0]
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Error using credits: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error using credits: {str(e)}"
        )

def add_credits(user_id: str = "default", credits_to_add: int = 10) -> Dict[str, Any]:
    """Add more credits to a user's account."""
    try:
        # Get current credits
        current_credits = get_user_credits(user_id)
        
        # Calculate new values
        total_credits = current_credits["total_credits"] + credits_to_add
        remaining_credits = current_credits["remaining_credits"] + credits_to_add
        
        # Update credit record
        updated_credits = {
            "total_credits": total_credits,
            "remaining_credits": remaining_credits,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        result = supabase.table("user_credits") \
            .update(updated_credits) \
            .eq("user_id", user_id) \
            .execute()
        
        if not result.data:
            logger.error("Failed to add credits: No data returned")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add credits"
            )
        
        logger.info(f"Added {credits_to_add} credits for user {user_id}, new total: {total_credits}")
        return result.data[0]
    except Exception as e:
        logger.error(f"Error adding credits: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error adding credits: {str(e)}"
        )

def store_combined_scan_results(sast_scan_id: str = None, ai_scan_id: str = None, project_name: str = None) -> Dict[str, Any]:
    """Store combined scan results from SAST and AI scans."""
    try:
        logger.info(f"Storing combined scan results - SAST ID: {sast_scan_id}, AI ID: {ai_scan_id}")
        
        # Initialize combined results with default severity counts
        combined_results = {
            "file_name": None,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": [],
            "severity_count": {"ERROR": 0, "WARNING": 0, "INFO": 0},
            "total_vulnerabilities": 0,
            "security_score": 10,
            "scan_status": "completed",
            "scan_duration": 0,
            "scan_metadata": {
                "scan_type": None,
                "isCombinedScan": True,
                "sast_scan_id": sast_scan_id,
                "ai_scan_id": ai_scan_id
            }
        }
        
        all_vulnerabilities = []
        severity_count = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        
        # Process SAST scan if available
        if sast_scan_id:
            sast_results = get_scan_by_id(sast_scan_id)
            if sast_results:
                logger.info(f"Processing SAST scan {sast_scan_id}")
                combined_results["file_name"] = sast_results.get("file_name")
                combined_results["scan_duration"] += sast_results.get("scan_duration", 0)
                
                # Process SAST vulnerabilities and update counts
                sast_vulns = sast_results.get("vulnerabilities", [])
                for vuln in sast_vulns:
                    processed_vuln = {
                        "check_id": vuln.get("check_id", "SAST-UNKNOWN"),
                        "path": vuln.get("path", combined_results["file_name"]),
                        "start": vuln.get("start", {"line": 1, "col": 1}),
                        "end": vuln.get("end", {"line": 1, "col": 1}),
                        "message": vuln.get("message", "SAST detected vulnerability"),
                        "severity": vuln.get("severity", "INFO").upper(),
                        "extra": vuln.get("extra", {
                            "severity": vuln.get("severity", "INFO").upper(),
                            "metadata": {
                                "category": "Security"
                            }
                        })
                    }
                    all_vulnerabilities.append(processed_vuln)
                    
                    # Update severity count
                    sev = processed_vuln["severity"].upper()
                    if sev in severity_count:
                        severity_count[sev] += 1
                
                combined_results["scan_metadata"]["sast_metadata"] = sast_results.get("scan_metadata", {})
            else:
                logger.warning(f"SAST scan {sast_scan_id} not found")
        
        # Process AI scan if available
        if ai_scan_id:
            ai_results = get_scan_by_id(ai_scan_id)
            if ai_results:
                logger.info(f"Processing AI scan {ai_scan_id}")
                if not combined_results["file_name"]:
                    combined_results["file_name"] = ai_results.get("file_name")
                combined_results["scan_duration"] += ai_results.get("scan_duration", 0)
                
                # Process AI vulnerabilities and update counts
                ai_vulns = ai_results.get("vulnerabilities", [])
                for vuln in ai_vulns:
                    processed_vuln = {
                        "check_id": vuln.get("check_id", "AI-UNKNOWN"),
                        "path": vuln.get("path", combined_results["file_name"]),
                        "start": vuln.get("start", {"line": 1, "col": 1}),
                        "end": vuln.get("end", {"line": 1, "col": 1}),
                        "message": vuln.get("message", "AI detected vulnerability"),
                        "severity": vuln.get("severity", "INFO").upper(),
                        "extra": vuln.get("extra", {
                            "severity": vuln.get("severity", "INFO").upper(),
                            "metadata": {
                                "category": "Security"
                            }
                        })
                    }
                    all_vulnerabilities.append(processed_vuln)
                    
                    # Update severity count
                    sev = processed_vuln["severity"].upper()
                    if sev in severity_count:
                        severity_count[sev] += 1
                
                combined_results["scan_metadata"]["ai_metadata"] = ai_results.get("scan_metadata", {})
            else:
                logger.warning(f"AI scan {ai_scan_id} not found")
        
        # Set scan type based on available results
        combined_results["scan_metadata"]["scan_type"] = (
            "Combined SAST & AI" if sast_scan_id and ai_scan_id
            else "SAST" if sast_scan_id
            else "AI" if ai_scan_id
            else "Unknown"
        )
        
        # Set file name if not set
        if not combined_results["file_name"]:
            combined_results["file_name"] = project_name or "Unknown"
        
        # Update final results
        combined_results["vulnerabilities"] = all_vulnerabilities
        combined_results["total_vulnerabilities"] = len(all_vulnerabilities)
        combined_results["severity_count"] = severity_count
        
        # Calculate security score based on all vulnerabilities
        combined_results["security_score"] = calculate_security_score(all_vulnerabilities)
        
        # Log final metrics
        logger.info(f"Combined scan metrics: "
                   f"Score={combined_results['security_score']}, "
                   f"Total Vulns={combined_results['total_vulnerabilities']}, "
                   f"Severity Counts={severity_count}")
        
        # Validate severity count structure before storing
        assert all(k in combined_results["severity_count"] for k in ["ERROR", "WARNING", "INFO"]), \
            "Missing severity levels in count"
        assert isinstance(combined_results["severity_count"], dict), \
            "Severity count must be a dictionary"
        
        # Store in Supabase
        logger.info("Storing combined results in Supabase")
        logger.debug(f"Combined results structure: {combined_results}")
        
        response = supabase.table("combined_scans").insert(combined_results).execute()
        
        if not response.data:
            raise Exception("No data returned from Supabase insert")
            
        stored_scan = response.data[0]
        logger.info(f"Successfully stored combined scan with ID: {stored_scan.get('id')}")
        logger.info(f"Final severity counts stored: {stored_scan.get('severity_count')}")
        
        return stored_scan
        
    except Exception as e:
        logger.error(f"Error storing combined scan results: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error storing combined scan results: {str(e)}"
        )

def get_combined_scan_history(limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
    """Retrieve combined scan history with pagination."""
    try:
        result = supabase.table("combined_scans") \
            .select("*") \
            .order("scan_timestamp", desc=True) \
            .limit(limit) \
            .offset(offset) \
            .execute()
        return result.data
    except Exception as e:
        logger.error(f"Error retrieving combined scan history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving combined scan history: {str(e)}"
        )

def get_combined_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a specific combined scan by ID."""
    try:
        result = supabase.table("combined_scans") \
            .select("*") \
            .eq("id", scan_id) \
            .execute()
            
        if not result.data or len(result.data) == 0:
            return None
            
        return result.data[0]
    except Exception as e:
        logger.error(f"Error retrieving combined scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving combined scan: {str(e)}"
        )

async def delete_combined_scan(scan_id: str) -> None:
    """Delete a combined scan record from Supabase."""
    try:
        # Delete the scan record
        response = supabase.table("combined_scans").delete().eq("id", scan_id).execute()
        
        # Log success - we don't need to check if anything was deleted since
        # the API already returns 200 OK for successful operations even if no records matched
        logger.info(f"Successfully executed deletion for combined scan {scan_id}")
    except Exception as e:
        logger.error(f"Error deleting combined scan from Supabase: {str(e)}")
        raise 