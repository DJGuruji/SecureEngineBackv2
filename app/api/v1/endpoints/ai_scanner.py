from fastapi import APIRouter, UploadFile, File, HTTPException, status, Query
import os
import tempfile
import shutil
import logging
import time
from typing import Dict, Any
from app.services.supabase_service import (
    store_scan_results,
    use_credits_for_ai_scan,
    get_user_credits,
)
# ⬇️  new import – ChatGPT service
from app.services.chatgpt_service import scan_code_with_chatgpt

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/ai-scan")
async def ai_scan(
    file: UploadFile = File(...),               # file to analyse
    user_id: str = Query("default")             # id comes from caller / token
) -> Dict[str, Any]:
    """
    Scan a source-code archive or single file with ChatGPT and
    return structured vulnerability data.
    """
    start_time = time.time()
    logger.info(f"Starting ChatGPT AI scan for file: {file.filename}")

    # ----- credit check -----------------------------------------------------
    credit_info = get_user_credits(user_id)
    if credit_info["remaining_credits"] < 24:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Insufficient credits for AI scan. Please add more credits.",
        )
    # -----------------------------------------------------------------------

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Persist upload to disk
            file_path = os.path.join(temp_dir, file.filename)
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # 🔍 Run the ChatGPT security scan
            scan_results = await scan_code_with_chatgpt(file_path)
            scan_results["scan_duration"] = time.time() - start_time

            # Persist + credit bookkeeping
            result_id = store_scan_results(scan_results)
            credit_after = use_credits_for_ai_scan(user_id, 24)

            scan_results["credit_info"] = {
                "used_credits": credit_after["used_credits"],
                "remaining_credits": credit_after["remaining_credits"],
            }
            logger.info(
                f"ChatGPT scan stored as {result_id} – "
                f"duration {scan_results['scan_duration']:.2f}s, "
                f"remaining credits {credit_after['remaining_credits']}"
            )
            return scan_results

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("ChatGPT AI scan failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
