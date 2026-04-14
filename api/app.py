"""
FastAPI Application - Main application setup

Creates and configures the FastAPI application for ChainGuardAI:
- Application factory pattern
- Middleware configuration
- Route registration
- Error handling setup
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import time
import logging
from typing import Dict, Any

from .middleware.security_middleware import SecurityMiddleware
from .middleware.audit_middleware import AuditMiddleware
from .routes.agent_routes import router as agent_router
from .routes.security_routes import router as security_router
from .routes.audit_routes import router as audit_router


def create_app(config: Dict[str, Any] = None) -> FastAPI:
    """
    Create and configure FastAPI application.
    
    Args:
        config: Application configuration dictionary
        
    Returns:
        Configured FastAPI application
    """
    # Initialize FastAPI app
    app_config = {
        "title": "ChainGuardAI API",
        "description": "Security framework for AI agents",
        "version": "1.0.0",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }
    
    if config:
        app_config.update(config.get("app", {}))
    
    app = FastAPI(**app_config)
    
    # Configure CORS
    cors_config = config.get("cors", {}) if config else {}
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_config.get("allow_origins", ["*"]),
        allow_credentials=cors_config.get("allow_credentials", True),
        allow_methods=cors_config.get("allow_methods", ["*"]),
        allow_headers=cors_config.get("allow_headers", ["*"]),
    )
    
    # Add trusted host middleware
    trusted_hosts = config.get("trusted_hosts", ["localhost", "127.0.0.1"]) if config else ["localhost", "127.0.0.1"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
    
    # Add custom middleware
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(AuditMiddleware)
    
    # Add request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response
    
    # Register routes
    app.include_router(agent_router, prefix="/api/v1/agents", tags=["agents"])
    app.include_router(security_router, prefix="/api/v1/security", tags=["security"])
    app.include_router(audit_router, prefix="/api/v1/audit", tags=["audit"])
    
    # Health check endpoint
    @app.get("/health", tags=["health"])
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "timestamp": time.time(),
            "service": "ChainGuardAI API",
            "version": "1.0.0"
        }
    
    # Root endpoint
    @app.get("/", tags=["root"])
    async def root():
        """Root endpoint with API information."""
        return {
            "name": "ChainGuardAI API",
            "version": "1.0.0",
            "description": "Security framework for AI agents",
            "docs": "/docs",
            "health": "/health"
        }
    
    # Global exception handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "type": "http_exception",
                    "message": exc.detail,
                    "status_code": exc.status_code,
                    "path": str(request.url)
                }
            }
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle general exceptions."""
        logging.error(f"Unhandled exception: {str(exc)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "type": "internal_server_error",
                    "message": "An internal server error occurred",
                    "status_code": 500,
                    "path": str(request.url)
                }
            }
        )
    
    # Application startup and shutdown events
    @app.on_event("startup")
    async def startup_event():
        """Application startup event."""
        logging.info("ChainGuardAI API starting up...")
        # Initialize any required services here
        
    @app.on_event("shutdown")
    async def shutdown_event():
        """Application shutdown event."""
        logging.info("ChainGuardAI API shutting down...")
        # Cleanup any resources here
    
    return app


# Create default app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    # Run the application
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
