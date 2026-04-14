"""
Security Middleware - Request validation and protection

Provides security middleware for ChainGuardAI API:
- Request validation and sanitization
- Rate limiting
- IP filtering
- Request size limits
- Security headers
"""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import time
import hashlib
import re
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for API request validation and protection."""
    
    def __init__(self, app, config: Dict[str, Any] = None):
        """
        Initialize SecurityMiddleware.
        
        Args:
            app: FastAPI application
            config: Security configuration
        """
        super().__init__(app)
        
        self.config = config or {}
        
        # Rate limiting
        self.rate_limit_enabled = self.config.get("rate_limit_enabled", True)
        self.rate_limit_requests = self.config.get("rate_limit_requests", 100)
        self.rate_limit_window = self.config.get("rate_limit_window", 60)  # seconds
        self.rate_limits = defaultdict(lambda: deque())
        
        # IP filtering
        self.ip_filter_enabled = self.config.get("ip_filter_enabled", False)
        self.allowed_ips = set(self.config.get("allowed_ips", []))
        self.blocked_ips = set(self.config.get("blocked_ips", []))
        
        # Request validation
        self.max_request_size = self.config.get("max_request_size", 10 * 1024 * 1024)  # 10MB
        self.validate_content_type = self.config.get("validate_content_type", True)
        self.allowed_content_types = self.config.get("allowed_content_types", 
                                                   ["application/json", "application/x-www-form-urlencoded"])
        
        # Input validation
        self.validate_input = self.config.get("validate_input", True)
        self.blocked_patterns = self.config.get("blocked_patterns", [
            r'<script[^>]*>.*?</script>',  # Script tags
            r'javascript:',                  # JavaScript protocol
            r'on\w+\s*=',                  # Event handlers
            r'eval\s*\(',                  # Eval functions
        ])
        
        # Security headers
        self.add_security_headers = self.config.get("add_security_headers", True)
        
        logger.info("SecurityMiddleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request through security middleware.
        
        Args:
            request: Incoming request
            call_next: Next middleware in chain
            
        Returns:
            Response from next middleware
        """
        try:
            # Skip security checks for docs and static assets
            if request.url.path in ["/docs", "/redoc", "/openapi.json"] or request.url.path.startswith("/static/"):
                return await call_next(request)
            
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # IP filtering
            if self.ip_filter_enabled:
                ip_result = self._check_ip_filtering(client_ip)
                if not ip_result["allowed"]:
                    return self._create_error_response(
                        403, 
                        "IP address not allowed",
                        {"ip": client_ip, "reason": ip_result["reason"]}
                    )
            
            # Rate limiting
            if self.rate_limit_enabled:
                rate_limit_result = self._check_rate_limit(client_ip)
                if not rate_limit_result["allowed"]:
                    return self._create_error_response(
                        429,
                        "Rate limit exceeded",
                        {
                            "ip": client_ip,
                            "limit": self.rate_limit_requests,
                            "window": self.rate_limit_window,
                            "retry_after": rate_limit_result["retry_after"]
                        }
                    )
            
            # Request size validation
            size_result = self._validate_request_size(request)
            if not size_result["valid"]:
                return self._create_error_response(
                    413,
                    "Request too large",
                    {"max_size": self.max_request_size}
                )
            
            # Content type validation
            if self.validate_content_type:
                content_result = self._validate_content_type(request)
                if not content_result["valid"]:
                    return self._create_error_response(
                        415,
                        "Unsupported media type",
                        {"allowed_types": self.allowed_content_types}
                    )
            
            # Input validation
            if self.validate_input:
                input_result = await self._validate_input(request)
                if not input_result["valid"]:
                    return self._create_error_response(
                        400,
                        "Invalid input detected",
                        {"reason": input_result["reason"]}
                    )
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            if self.add_security_headers:
                response = self._add_security_headers(response)
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {str(e)}")
            return self._create_error_response(
                500,
                "Internal security error",
                {"error": "Security validation failed"}
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the list
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to client host
        return request.client.host if request.client else "unknown"
    
    def _check_ip_filtering(self, ip: str) -> Dict[str, Any]:
        """Check if IP is allowed or blocked."""
        result = {"allowed": True, "reason": ""}
        
        if ip in self.blocked_ips:
            result["allowed"] = False
            result["reason"] = "IP is blocked"
        elif self.allowed_ips and ip not in self.allowed_ips:
            result["allowed"] = False
            result["reason"] = "IP not in allowed list"
        
        return result
    
    def _check_rate_limit(self, ip: str) -> Dict[str, Any]:
        """Check if IP has exceeded rate limit."""
        result = {"allowed": True, "retry_after": 0}
        
        current_time = time.time()
        window_start = current_time - self.rate_limit_window
        
        # Clean old requests from the deque
        ip_requests = self.rate_limits[ip]
        while ip_requests and ip_requests[0] < window_start:
            ip_requests.popleft()
        
        # Check current request count
        if len(ip_requests) >= self.rate_limit_requests:
            result["allowed"] = False
            # Calculate retry after (when the oldest request expires)
            if ip_requests:
                result["retry_after"] = int(ip_requests[0] + self.rate_limit_window - current_time)
            else:
                result["retry_after"] = self.rate_limit_window
        
        # Add current request
        ip_requests.append(current_time)
        
        return result
    
    def _validate_request_size(self, request: Request) -> Dict[str, Any]:
        """Validate request size."""
        result = {"valid": True}
        
        # Check content-length header
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > self.max_request_size:
                    result["valid"] = False
            except ValueError:
                pass
        
        return result
    
    def _validate_content_type(self, request: Request) -> Dict[str, Any]:
        """Validate request content type."""
        result = {"valid": True}
        
        content_type = request.headers.get("content-type", "").split(";")[0].strip()
        
        if content_type and content_type not in self.allowed_content_types:
            result["valid"] = False
        
        return result
    
    async def _validate_input(self, request: Request) -> Dict[str, Any]:
        """Validate input for malicious patterns."""
        result = {"valid": True, "reason": ""}
        
        try:
            # Check URL parameters
            for param_name, param_value in request.query_params.items():
                if self._contains_blocked_content(str(param_value)):
                    result["valid"] = False
                    result["reason"] = f"Blocked content in URL parameter: {param_name}"
                    return result
            
            # Check headers (skip common legitimate headers)
            legitimate_headers = {'cookie', 'authorization', 'content-type', 'accept', 'user-agent', 'host'}
            for header_name, header_value in request.headers.items():
                if header_name.lower() not in legitimate_headers and self._contains_blocked_content(str(header_value)):
                    result["valid"] = False
                    result["reason"] = f"Blocked content in header: {header_name}"
                    return result
            
            # Check body (for POST/PUT requests)
            if request.method in ["POST", "PUT", "PATCH"]:
                try:
                    body = await request.body()
                    if body and self._contains_blocked_content(body.decode('utf-8', errors='ignore')):
                        result["valid"] = False
                        result["reason"] = "Blocked content in request body"
                        return result
                except Exception:
                    # If we can't read the body, allow it (other middleware will handle it)
                    pass
            
        except Exception as e:
            logger.error(f"Input validation error: {str(e)}")
            # On validation error, fail safe
            result["valid"] = False
            result["reason"] = "Input validation error"
        
        return result
    
    def _contains_blocked_content(self, content: str) -> bool:
        """Check if content contains blocked patterns."""
        try:
            content_lower = content.lower()
            
            for pattern in self.blocked_patterns:
                if re.search(pattern, content_lower, re.IGNORECASE | re.DOTALL):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _add_security_headers(self, response: Response) -> Response:
        """Add security headers to response."""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response
    
    def _create_error_response(self, status_code: int, message: str, details: Dict[str, Any] = None) -> JSONResponse:
        """Create standardized error response."""
        error_response = {
            "error": {
                "type": "security_error",
                "message": message,
                "status_code": status_code,
                "timestamp": time.time()
            }
        }
        
        if details:
            error_response["error"]["details"] = details
        
        return JSONResponse(
            status_code=status_code,
            content=error_response
        )
    
    def get_rate_limit_status(self, ip: str) -> Dict[str, Any]:
        """Get current rate limit status for an IP."""
        if ip not in self.rate_limits:
            return {
                "current_requests": 0,
                "limit": self.rate_limit_requests,
                "window": self.rate_limit_window,
                "reset_time": None
            }
        
        current_time = time.time()
        window_start = current_time - self.rate_limit_window
        
        # Clean old requests
        ip_requests = self.rate_limits[ip]
        while ip_requests and ip_requests[0] < window_start:
            ip_requests.popleft()
        
        # Calculate reset time
        reset_time = None
        if ip_requests:
            reset_time = ip_requests[0] + self.rate_limit_window
        
        return {
            "current_requests": len(ip_requests),
            "limit": self.rate_limit_requests,
            "window": self.rate_limit_window,
            "reset_time": reset_time
        }
    
    def add_blocked_ip(self, ip: str) -> None:
        """Add IP to blocked list."""
        self.blocked_ips.add(ip)
        logger.info(f"Added IP to blocked list: {ip}")
    
    def remove_blocked_ip(self, ip: str) -> None:
        """Remove IP from blocked list."""
        self.blocked_ips.discard(ip)
        logger.info(f"Removed IP from blocked list: {ip}")
    
    def add_allowed_ip(self, ip: str) -> None:
        """Add IP to allowed list."""
        self.allowed_ips.add(ip)
        logger.info(f"Added IP to allowed list: {ip}")
    
    def remove_allowed_ip(self, ip: str) -> None:
        """Remove IP from allowed list."""
        self.allowed_ips.discard(ip)
        logger.info(f"Removed IP from allowed list: {ip}")
    
    def clear_rate_limits(self) -> None:
        """Clear all rate limit data."""
        self.rate_limits.clear()
        logger.info("Cleared all rate limit data")
    
    def get_middleware_status(self) -> Dict[str, Any]:
        """Get middleware status and configuration."""
        return {
            "rate_limiting": {
                "enabled": self.rate_limit_enabled,
                "requests": self.rate_limit_requests,
                "window": self.rate_limit_window,
                "active_ips": len(self.rate_limits)
            },
            "ip_filtering": {
                "enabled": self.ip_filter_enabled,
                "allowed_ips": len(self.allowed_ips),
                "blocked_ips": len(self.blocked_ips)
            },
            "validation": {
                "max_request_size": self.max_request_size,
                "content_type_validation": self.validate_content_type,
                "input_validation": self.validate_input
            },
            "security_headers": {
                "enabled": self.add_security_headers
            }
        }
