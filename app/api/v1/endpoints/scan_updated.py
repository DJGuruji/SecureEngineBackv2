from fastapi import APIRouter
import logging
from app.core.config import get_settings
from .common_endpoints import router as common_router
from .codeql_scanner import router as codeql_router
from .ai_scanner import router as ai_router
from .credit_endpoints import router as credit_router
from .semgrep_endpoint import router as semgrep_router

logger = logging.getLogger(__name__)
settings = get_settings()

# Create the main router
router = APIRouter()

# Include all the modular routers
router.include_router(common_router, tags=["common"])
router.include_router(codeql_router, tags=["codeql"])
router.include_router(ai_router, tags=["ai"])
router.include_router(credit_router, tags=["credits"])
router.include_router(semgrep_router, tags=["semgrep"]) 