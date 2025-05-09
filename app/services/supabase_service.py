from supabase import create_client
from typing import Dict, Any, List
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
        
        # Enhance vulnerability data
        enhanced_vulnerabilities = [
            enhance_vulnerability_data(vuln) 
            for vuln in data.get("vulnerabilities", [])
        ]
        
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
            
        logger.info("Successfully stored results in Supabase")
        return result.data[0]
        
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