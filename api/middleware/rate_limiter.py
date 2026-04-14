"""
Rate limiting middleware for ChainGuardAI API.
Implements token bucket algorithm for API rate limiting.
"""

import time
import logging
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

class RateLimiterMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using token bucket algorithm."""
    
    def __init__(self, app, requests_per_minute: int = 60, burst_size: int = 10):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.token_buckets: Dict[str, Dict[str, Any]] = {}
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting."""
        client_ip = self._get_client_ip(request)
        
        # Clean up old entries periodically
        self._cleanup_old_entries()
        
        # Check rate limit
        if not self._allow_request(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please try again later.",
                headers={
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": str(0),
                    "X-RateLimit-Reset": str(int(time.time() + 60))
                }
            )
        
        # Get token bucket info for response headers
        bucket = self.token_buckets.get(client_ip, {})
        tokens_remaining = bucket.get("tokens", self.burst_size)
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, int(tokens_remaining)))
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + 60))
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded IP first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fall back to direct connection IP
        return request.client.host if request.client else "unknown"
    
    def _allow_request(self, client_ip: str) -> bool:
        """Check if request is allowed based on rate limit."""
        current_time = time.time()
        
        # Initialize bucket for new client
        if client_ip not in self.token_buckets:
            self.token_buckets[client_ip] = {
                "tokens": self.burst_size,
                "last_refill": current_time,
                "last_request": current_time
            }
            return True
        
        bucket = self.token_buckets[client_ip]
        
        # Refill tokens based on time elapsed
        time_elapsed = current_time - bucket["last_refill"]
        tokens_to_add = time_elapsed * (self.requests_per_minute / 60.0)
        
        bucket["tokens"] = min(self.burst_size, bucket["tokens"] + tokens_to_add)
        bucket["last_refill"] = current_time
        
        # Check if request can be processed
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            bucket["last_request"] = current_time
            return True
        
        return False
    
    def _cleanup_old_entries(self):
        """Remove inactive client entries to prevent memory leaks."""
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        # Remove entries inactive for more than 1 hour
        cutoff_time = current_time - 3600
        inactive_clients = [
            ip for ip, bucket in self.token_buckets.items()
            if bucket["last_request"] < cutoff_time
        ]
        
        for client_ip in inactive_clients:
            del self.token_buckets[client_ip]
        
        self.last_cleanup = current_time
        
        if inactive_clients:
            logger.info(f"Cleaned up {len(inactive_clients)} inactive rate limit entries")

class AdvancedRateLimiter(RateLimiterMiddleware):
    """Advanced rate limiter with multiple tiers and custom limits."""
    
    def __init__(self, app, default_limits: Dict[str, int] = None):
        limits = default_limits or {
            "default": {"requests_per_minute": 60, "burst_size": 10},
            "authenticated": {"requests_per_minute": 120, "burst_size": 20},
            "premium": {"requests_per_minute": 300, "burst_size": 50},
            "admin": {"requests_per_minute": 600, "burst_size": 100}
        }
        super().__init__(app, limits["default"]["requests_per_minute"], limits["default"]["burst_size"])
        self.tier_limits = limits
    
    async def dispatch(self, request: Request, call_next):
        """Process request with tier-based rate limiting."""
        client_ip = self._get_client_ip(request)
        user_tier = self._get_user_tier(request)
        
        # Apply tier-specific limits
        tier_config = self.tier_limits.get(user_tier, self.tier_limits["default"])
        self.requests_per_minute = tier_config["requests_per_minute"]
        self.burst_size = tier_config["burst_size"]
        
        return await super().dispatch(request, call_next)
    
    def _get_user_tier(self, request: Request) -> str:
        """Determine user tier based on authentication or API key."""
        # Check for API key in headers
        api_key = request.headers.get("X-API-Key")
        if api_key:
            if api_key.startswith("premium_"):
                return "premium"
            elif api_key.startswith("admin_"):
                return "admin"
            else:
                return "authenticated"
        
        # Check for authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return "authenticated"
        
        return "default"

class EndpointRateLimiter(RateLimiterMiddleware):
    """Rate limiter with endpoint-specific limits."""
    
    def __init__(self, app, endpoint_limits: Dict[str, Dict[str, int]] = None):
        default_limits = {"requests_per_minute": 60, "burst_size": 10}
        super().__init__(app, default_limits["requests_per_minute"], default_limits["burst_size"])
        self.endpoint_limits = endpoint_limits or {
            "/api/v1/agents/register": {"requests_per_minute": 10, "burst_size": 5},
            "/api/v1/messages/send": {"requests_per_minute": 30, "burst_size": 10},
            "/api/v1/audit/query": {"requests_per_minute": 20, "burst_size": 5},
            "/api/v1/security/verify": {"requests_per_minute": 15, "burst_size": 3}
        }
    
    async def dispatch(self, request: Request, call_next):
        """Process request with endpoint-specific limits."""
        endpoint = request.url.path
        
        # Apply endpoint-specific limits if configured
        if endpoint in self.endpoint_limits:
            limit_config = self.endpoint_limits[endpoint]
            self.requests_per_minute = limit_config["requests_per_minute"]
            self.burst_size = limit_config["burst_size"]
        
        return await super().dispatch(request, call_next)

# Utility functions for rate limit management
def get_rate_limit_status(client_ip: str, rate_limiter: RateLimiterMiddleware) -> Dict[str, Any]:
    """Get current rate limit status for a client."""
    bucket = rate_limiter.token_buckets.get(client_ip, {})
    
    return {
        "client_ip": client_ip,
        "tokens_remaining": bucket.get("tokens", rate_limiter.burst_size),
        "requests_per_minute": rate_limiter.requests_per_minute,
        "burst_size": rate_limiter.burst_size,
        "last_request": bucket.get("last_request"),
        "last_refill": bucket.get("last_refill")
    }

def reset_rate_limit(client_ip: str, rate_limiter: RateLimiterMiddleware):
    """Reset rate limit for a specific client."""
    if client_ip in rate_limiter.token_buckets:
        del rate_limiter.token_buckets[client_ip]
        logger.info(f"Rate limit reset for IP: {client_ip}")

def get_rate_limit_stats(rate_limiter: RateLimiterMiddleware) -> Dict[str, Any]:
    """Get overall rate limit statistics."""
    total_clients = len(rate_limiter.token_buckets)
    active_clients = len([
        bucket for bucket in rate_limiter.token_buckets.values()
        if time.time() - bucket["last_request"] < 300  # Active in last 5 minutes
    ])
    
    return {
        "total_clients": total_clients,
        "active_clients": active_clients,
        "requests_per_minute": rate_limiter.requests_per_minute,
        "burst_size": rate_limiter.burst_size,
        "memory_usage_kb": total_clients * 200  # Approximate memory usage
    }
