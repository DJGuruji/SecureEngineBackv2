from fastapi import APIRouter, HTTPException, status, Query
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)
router = APIRouter()

# Credit management endpoints
@router.get("/credits")
async def get_credits(user_id: str = Query("default")):
    """Get the current credit balance for a user."""
    try:
        from app.services.supabase_service import get_user_credits
        credit_info = get_user_credits(user_id)
        return {
            "user_id": credit_info["user_id"],
            "total_credits": credit_info["total_credits"],
            "used_credits": credit_info["used_credits"],
            "remaining_credits": credit_info["remaining_credits"],
            "last_updated": credit_info["last_updated"]
        }
    except Exception as e:
        logger.error(f"Error getting credits: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting credits: {str(e)}"
        )

@router.post("/credits/add")
async def add_user_credits(user_id: str = Query("default"), amount: int = Query(10, ge=1, le=100)):
    """Add more credits to a user's account."""
    try:
        from app.services.supabase_service import add_credits
        credit_info = add_credits(user_id, amount)
        return {
            "status": "success",
            "message": f"Added {amount} credits to user {user_id}",
            "user_id": credit_info["user_id"],
            "total_credits": credit_info["total_credits"],
            "used_credits": credit_info["used_credits"],
            "remaining_credits": credit_info["remaining_credits"],
            "last_updated": credit_info["last_updated"]
        }
    except Exception as e:
        logger.error(f"Error adding credits: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error adding credits: {str(e)}"
        ) 