"""
API Module - FastAPI routes and middleware

Provides REST API interface for ChainGuardAI:
- Agent management endpoints
- Security monitoring endpoints
- Audit log access
- Administrative functions
"""

from .app import create_app
from .routes.agent_routes import router as agent_router
from .routes.security_routes import router as security_router
from .routes.audit_routes import router as audit_router
from .middleware.security_middleware import SecurityMiddleware
from .middleware.audit_middleware import AuditMiddleware

__all__ = [
    "create_app",
    "agent_router",
    "security_router", 
    "audit_router",
    "SecurityMiddleware",
    "AuditMiddleware",
]
