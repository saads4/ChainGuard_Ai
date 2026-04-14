"""
Audit Middleware - Request/response logging for audit trail

Provides audit middleware for ChainGuardAI API:
- Request and response logging
- User activity tracking
- Security event logging
- Performance monitoring
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import time
import json
import hashlib
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """Audit middleware for logging API requests and responses."""
    
    def __init__(self, app, config: Dict[str, Any] = None):
        """
        Initialize AuditMiddleware.
        
        Args:
            app: FastAPI application
            config: Audit configuration
        """
        super().__init__(app)
        
        self.config = config or {}
        
        # Logging configuration
        self.log_requests = self.config.get("log_requests", True)
        self.log_responses = self.config.get("log_responses", True)
        self.log_headers = self.config.get("log_headers", False)
        self.log_body = self.config.get("log_body", False)
        self.max_body_size = self.config.get("max_body_size", 1024)  # 1KB
        
        # Performance monitoring
        self.track_performance = self.config.get("track_performance", True)
        self.slow_request_threshold = self.config.get("slow_request_threshold", 1.0)  # seconds
        
        # Security monitoring
        self.track_security_events = self.config.get("track_security_events", True)
        self.security_status_codes = self.config.get("security_status_codes", [401, 403, 429])
        
        # Data storage (in production, use database)
        self.audit_log = []
        self.max_log_entries = self.config.get("max_log_entries", 10000)
        
        logger.info("AuditMiddleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request through audit middleware.
        
        Args:
            request: Incoming request
            call_next: Next middleware in chain
            
        Returns:
            Response from next middleware
        """
        start_time = time.time()
        request_id = self._generate_request_id(request)
        
        # Log request
        if self.log_requests:
            await self._log_request(request, request_id, start_time)
        
        # Process request
        response = await call_next(request)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Log response
        if self.log_responses:
            await self._log_response(response, request_id, processing_time)
        
        # Track performance
        if self.track_performance:
            self._track_performance(request, response, processing_time)
        
        # Track security events
        if self.track_security_events:
            self._track_security_events(request, response)
        
        # Add audit headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(processing_time)
        
        return response
    
    def _generate_request_id(self, request: Request) -> str:
        """Generate unique request ID."""
        # Create hash from request details
        hash_input = f"{request.method}:{request.url}:{time.time()}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]
    
    async def _log_request(self, request: Request, request_id: str, start_time: float) -> None:
        """Log incoming request."""
        try:
            log_entry = {
                "type": "request",
                "request_id": request_id,
                "timestamp": start_time,
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "client_ip": self._get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
            }
            
            # Add headers if enabled
            if self.log_headers:
                log_entry["headers"] = dict(request.headers)
            
            # Add body if enabled and applicable
            if self.log_body and request.method in ["POST", "PUT", "PATCH"]:
                try:
                    body = await request.body()
                    if body:
                        body_str = body.decode('utf-8', errors='ignore')
                        if len(body_str) > self.max_body_size:
                            body_str = body_str[:self.max_body_size] + "...[truncated]"
                        log_entry["body"] = body_str
                except Exception:
                    log_entry["body"] = "[Unable to read body]"
            
            # Store in audit log
            self._store_audit_entry(log_entry)
            
            # Log to system logger
            logger.info(f"Request: {request.method} {request.url} (ID: {request_id})")
            
        except Exception as e:
            logger.error(f"Failed to log request: {str(e)}")
    
    async def _log_response(self, response: Response, request_id: str, processing_time: float) -> None:
        """Log outgoing response."""
        try:
            log_entry = {
                "type": "response",
                "request_id": request_id,
                "timestamp": time.time(),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "content_length": response.headers.get("content-length", ""),
                "processing_time": processing_time,
            }
            
            # Add response headers if enabled
            if self.log_headers:
                log_entry["headers"] = dict(response.headers)
            
            # Store in audit log
            self._store_audit_entry(log_entry)
            
            # Log to system logger
            logger.info(f"Response: {response.status_code} (ID: {request_id}, Time: {processing_time:.3f}s)")
            
        except Exception as e:
            logger.error(f"Failed to log response: {str(e)}")
    
    def _track_performance(self, request: Request, response: Response, processing_time: float) -> None:
        """Track request performance."""
        try:
            if processing_time > self.slow_request_threshold:
                performance_entry = {
                    "type": "performance",
                    "timestamp": time.time(),
                    "method": request.method,
                    "path": request.url.path,
                    "processing_time": processing_time,
                    "status_code": response.status_code,
                    "threshold": self.slow_request_threshold,
                    "client_ip": self._get_client_ip(request),
                }
                
                self._store_audit_entry(performance_entry)
                logger.warning(f"Slow request detected: {request.method} {request.url.path} ({processing_time:.3f}s)")
                
        except Exception as e:
            logger.error(f"Failed to track performance: {str(e)}")
    
    def _track_security_events(self, request: Request, response: Response) -> None:
        """Track security-related events."""
        try:
            if response.status_code in self.security_status_codes:
                security_entry = {
                    "type": "security",
                    "timestamp": time.time(),
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "client_ip": self._get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "query_params": dict(request.query_params),
                }
                
                self._store_audit_entry(security_entry)
                logger.warning(f"Security event: {response.status_code} for {request.method} {request.url.path}")
                
        except Exception as e:
            logger.error(f"Failed to track security event: {str(e)}")
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _store_audit_entry(self, entry: Dict[str, Any]) -> None:
        """Store audit entry."""
        try:
            self.audit_log.append(entry)
            
            # Maintain log size
            if len(self.audit_log) > self.max_log_entries:
                # Remove oldest entries
                excess = len(self.audit_log) - self.max_log_entries
                self.audit_log = self.audit_log[excess:]
                
        except Exception as e:
            logger.error(f"Failed to store audit entry: {str(e)}")
    
    def get_audit_log(self, limit: int = 100, entry_type: str = None, 
                     start_time: float = None, end_time: float = None) -> List[Dict[str, Any]]:
        """Get audit log entries."""
        try:
            filtered_log = self.audit_log
            
            # Filter by type
            if entry_type:
                filtered_log = [entry for entry in filtered_log if entry.get("type") == entry_type]
            
            # Filter by time range
            if start_time:
                filtered_log = [entry for entry in filtered_log if entry.get("timestamp", 0) >= start_time]
            
            if end_time:
                filtered_log = [entry for entry in filtered_log if entry.get("timestamp", 0) <= end_time]
            
            # Sort by timestamp (newest first)
            filtered_log.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            
            # Limit results
            return filtered_log[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get audit log: {str(e)}")
            return []
    
    def get_request_by_id(self, request_id: str) -> Dict[str, Any]:
        """Get all audit entries for a specific request."""
        try:
            request_entries = [entry for entry in self.audit_log if entry.get("request_id") == request_id]
            
            # Sort by timestamp
            request_entries.sort(key=lambda x: x.get("timestamp", 0))
            
            return {
                "request_id": request_id,
                "entries": request_entries,
                "count": len(request_entries)
            }
            
        except Exception as e:
            logger.error(f"Failed to get request by ID: {str(e)}")
            return {}
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        try:
            performance_entries = [entry for entry in self.audit_log if entry.get("type") == "performance"]
            
            if not performance_entries:
                return {"message": "No performance data available"}
            
            # Calculate statistics
            processing_times = [entry["processing_time"] for entry in performance_entries]
            
            stats = {
                "total_requests": len(processing_times),
                "avg_processing_time": sum(processing_times) / len(processing_times),
                "min_processing_time": min(processing_times),
                "max_processing_time": max(processing_times),
                "slow_requests": len([t for t in processing_times if t > self.slow_request_threshold]),
                "threshold": self.slow_request_threshold,
                "slow_request_rate": len([t for t in processing_times if t > self.slow_request_threshold]) / len(processing_times) * 100
            }
            
            # Add slowest requests
            performance_entries.sort(key=lambda x: x["processing_time"], reverse=True)
            stats["slowest_requests"] = performance_entries[:10]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get performance stats: {str(e)}")
            return {"error": str(e)}
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        try:
            security_entries = [entry for entry in self.audit_log if entry.get("type") == "security"]
            
            if not security_entries:
                return {"message": "No security events recorded"}
            
            # Group by status code
            status_counts = {}
            for entry in security_entries:
                status_code = entry.get("status_code", "unknown")
                status_counts[status_code] = status_counts.get(status_code, 0) + 1
            
            # Group by IP
            ip_counts = {}
            for entry in security_entries:
                ip = entry.get("client_ip", "unknown")
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            stats = {
                "total_security_events": len(security_entries),
                "status_code_distribution": status_counts,
                "top_ips": sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                "recent_events": security_entries[-10:]  # Last 10 events
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get security stats: {str(e)}")
            return {"error": str(e)}
    
    def clear_audit_log(self, older_than: float = None) -> int:
        """Clear audit log entries."""
        try:
            if older_than:
                # Remove entries older than specified time
                original_count = len(self.audit_log)
                self.audit_log = [entry for entry in self.audit_log if entry.get("timestamp", 0) >= older_than]
                removed_count = original_count - len(self.audit_log)
            else:
                # Clear all entries
                removed_count = len(self.audit_log)
                self.audit_log.clear()
            
            logger.info(f"Cleared {removed_count} audit log entries")
            return removed_count
            
        except Exception as e:
            logger.error(f"Failed to clear audit log: {str(e)}")
            return 0
    
    def get_middleware_status(self) -> Dict[str, Any]:
        """Get middleware status and configuration."""
        return {
            "logging": {
                "log_requests": self.log_requests,
                "log_responses": self.log_responses,
                "log_headers": self.log_headers,
                "log_body": self.log_body,
                "max_body_size": self.max_body_size
            },
            "monitoring": {
                "track_performance": self.track_performance,
                "slow_request_threshold": self.slow_request_threshold,
                "track_security_events": self.track_security_events,
                "security_status_codes": self.security_status_codes
            },
            "storage": {
                "current_entries": len(self.audit_log),
                "max_entries": self.max_log_entries
            }
        }
