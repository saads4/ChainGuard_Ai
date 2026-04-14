"""
Main entry point for ChainGuardAI API.
This file provides the standard FastAPI entry point that uvicorn expects.
"""

from .app import app

# This allows uvicorn to import from api.main:app
__all__ = ["app"]
