from supabase import create_client
from typing import Dict, Any, List, Optional
import logging
from fastapi import HTTPException, status
from app.core.config import get_settings
from datetime import datetime

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

def store_combined_scan_results(
    sast_scan_id: str, 
    ai_scan_id: str, 
    project_name: str = None
) -> Dict[str, Any]:
    """
    Store combined SAST and AI scan results in a new combined_scans table.
    
    Args:
        sast_scan_id: ID of the SAST scan in scan_history
        ai_scan_id: ID of the AI scan in scan_history
        project_name: Optional project name for grouping scans
        
    Returns:
        The newly created combined scan record
    """
    try:
        logger.info(f"Storing combined scan results for SAST scan {sast_scan_id} and AI scan {ai_scan_id}")
        
        # Fetch the individual scan records
        sast_scan = get_scan_by_id(sast_scan_id)
        ai_scan = get_scan_by_id(ai_scan_id)
        
        if not sast_scan:
            raise ValueError(f"SAST scan with ID {sast_scan_id} not found")
        
        if not ai_scan:
            raise ValueError(f"AI scan with ID {ai_scan_id} not found")
        
        # Calculate combined stats
        total_vulnerabilities = (
            sast_scan.get("total_vulnerabilities", 0) + 
            ai_scan.get("total_vulnerabilities", 0)
        )
        
        # Merge severity counts
        sast_severity = sast_scan.get("severity_count", {})
        ai_severity = ai_scan.get("severity_count", {})
        
        combined_severity = {
            "ERROR": (sast_severity.get("ERROR", 0) + ai_severity.get("ERROR", 0)),
            "WARNING": (sast_severity.get("WARNING", 0) + ai_severity.get("WARNING", 0)),
            "INFO": (sast_severity.get("INFO", 0) + ai_severity.get("INFO", 0))
        }
        
        # Calculate weighted security score (average of both scores)
        sast_score = sast_scan.get("security_score", 5)
        ai_score = ai_scan.get("security_score", 5)
        combined_score = (sast_score + ai_score) / 2
        
        # Combine all vulnerabilities
        all_vulnerabilities = (
            sast_scan.get("vulnerabilities", []) + 
            ai_scan.get("vulnerabilities", [])
        )
        
        # Create combined scan record
        combined_scan = {
            "project_name": project_name or f"Project-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "scan_timestamp": datetime.utcnow().isoformat(),
            "sast_scan_id": sast_scan_id,
            "ai_scan_id": ai_scan_id,
            "file_name": sast_scan.get("file_name"),
            "vulnerabilities": all_vulnerabilities,
            "severity_count": combined_severity,
            "total_vulnerabilities": total_vulnerabilities,
            "security_score": round(combined_score, 1),
            "scan_status": "completed",
            "scan_duration": (
                sast_scan.get("scan_duration", 0) + 
                ai_scan.get("scan_duration", 0)
            ),
            "scan_metadata": {
                "scan_type": "SAST & AI",
                "sast_metadata": sast_scan.get("scan_metadata", {}),
                "ai_metadata": ai_scan.get("scan_metadata", {})
            }
        }
        
        # Store in combined_scans table
        result = supabase.table("combined_scans").insert(combined_scan).execute()
        
        if not result.data:
            logger.error("Failed to store combined scan results: No data returned")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store combined scan results in database"
            )
            
        logger.info("Successfully stored combined scan results")
        return result.data[0]
        
    except ValueError as ve:
        logger.error(f"Error storing combined scan results: {str(ve)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(ve)
        )
    except Exception as e:
        logger.error(f"Error storing combined scan results: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
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