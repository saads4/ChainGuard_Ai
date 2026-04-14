"""
Base Agent - Abstract base class all agents must extend

Provides the foundation for ChainGuardAI-protected agents:
- Abstract base class with common functionality
- ChainGuardAI integration interface
- Standard agent lifecycle methods
- Error handling and logging
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from loguru import logger
from core import ChainGuardAI


class BaseAgent(ABC):
    """Abstract base class for all ChainGuardAI-protected agents."""
    
    def __init__(self, agent_id: str, agent_type: str, config: Dict[str, Any] = None):
        """
        Initialize BaseAgent.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_type: Type of agent (e.g., "finance_agent", "marketing_agent")
            config: Agent configuration dictionary
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.config = config or {}
        
        # ChainGuardAI protection
        self.shield = None
        self.protected = False
        
        # Agent state
        self.is_active = False
        self.session_id = None
        self.context = {
            "agent_id": agent_id,
            "agent_type": agent_type,
            "capabilities": self.get_capabilities(),
            "trust_score": 1.0,
            "transaction_count": 0
        }
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "blocked_requests": 0,
            "escalated_requests": 0,
            "avg_processing_time": 0.0
        }
        
        logger.info(f"Initialized {agent_type} agent: {agent_id}")
    
    def initialize_shield(self, shield_config: Dict[str, Any] = None) -> bool:
        """
        Initialize ChainGuardAI protection.
        
        Args:
            shield_config: Configuration for ChainGuardAI
            
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Create ChainGuardAI instance
            self.shield = ChainGuardAI(shield_config or {})
            
            # Register this agent
            success = self.shield.register_agent(
                self.agent_id,
                self.agent_type,
                self.get_capabilities(),
                self.context
            )
            
            if success:
                self.protected = True
                logger.info(f"ChainGuardAI protection enabled for {self.agent_id}")
            else:
                logger.error(f"Failed to enable ChainGuardAI protection for {self.agent_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to initialize ChainGuardAI: {str(e)}")
            return False
    
    def start_session(self) -> str:
        """
        Start a new agent session.
        
        Returns:
            Session ID
        """
        try:
            import uuid
            self.session_id = str(uuid.uuid4())
            self.is_active = True
            self.context["session_id"] = self.session_id
            
            logger.info(f"Started session for {self.agent_id}: {self.session_id}")
            return self.session_id
            
        except Exception as e:
            logger.error(f"Failed to start session: {str(e)}")
            return ""
    
    def end_session(self) -> None:
        """End the current agent session."""
        try:
            self.is_active = False
            if self.session_id:
                logger.info(f"Ended session for {self.agent_id}: {self.session_id}")
                self.session_id = None
            
        except Exception as e:
            logger.error(f"Failed to end session: {str(e)}")
    
    def process_request(self, request: str) -> Dict[str, Any]:
        """
        Process a user request with ChainGuardAI protection.
        
        Args:
            request: User request string
            
        Returns:
            Response dictionary
        """
        try:
            import time
            start_time = time.time()
            
            self.stats["total_requests"] += 1
            
            # Check if ChainGuardAI is active
            if not self.protected or not self.shield:
                logger.warning(f"Processing without ChainGuardAI protection: {self.agent_id}")
                return self._process_unprotected(request, start_time)
            
            # Process through ChainGuardAI
            result = self.shield.process_request(
                request,
                self.agent_id,
                self.context
            )
            
            # Update statistics
            processing_time = time.time() - start_time
            self._update_stats(result, processing_time)
            
            # Log the result
            self._log_request_result(request, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to process request: {str(e)}")
            return {
                "success": False,
                "response": "Error processing request",
                "error": str(e),
                "agent_id": self.agent_id,
                "session_id": self.session_id
            }
    
    def _process_unprotected(self, request: str, start_time: float) -> Dict[str, Any]:
        """Process request without ChainGuardAI protection (fallback)."""
        try:
            # Direct processing without protection
            response = self.handle_request(request)
            
            processing_time = time.time() - start_time
            
            return {
                "success": True,
                "response": response,
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "processing_time": processing_time,
                "shield_protection": False,
                "risk_level": "UNKNOWN"
            }
            
        except Exception as e:
            return {
                "success": False,
                "response": "Error processing request",
                "error": str(e),
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "shield_protection": False
            }
    
    @abstractmethod
    def handle_request(self, request: str) -> str:
        """
        Handle a request (to be implemented by subclasses).
        
        Args:
            request: User request string
            
        Returns:
            Response string
        """
        pass
    
    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """
        Get list of agent capabilities.
        
        Returns:
            List of capability strings
        """
        pass
    
    def get_agent_info(self) -> Dict[str, Any]:
        """Get information about this agent."""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "is_active": self.is_active,
            "session_id": self.session_id,
            "protected": self.protected,
            "capabilities": self.get_capabilities(),
            "context": self.context.copy(),
            "statistics": self.stats.copy(),
            "config": self.config.copy()
        }
    
    def update_context(self, updates: Dict[str, Any]) -> None:
        """Update agent context."""
        try:
            self.context.update(updates)
            logger.debug(f"Updated context for {self.agent_id}: {list(updates.keys())}")
        except Exception as e:
            logger.error(f"Failed to update context: {str(e)}")
    
    def update_trust_score(self, new_score: float) -> None:
        """Update agent trust score."""
        try:
            if 0.0 <= new_score <= 1.0:
                old_score = self.context.get("trust_score", 1.0)
                self.context["trust_score"] = new_score
                logger.info(f"Trust score updated for {self.agent_id}: {old_score} -> {new_score}")
            else:
                logger.warning(f"Invalid trust score: {new_score}")
        except Exception as e:
            logger.error(f"Failed to update trust score: {str(e)}")
    
    def increment_transaction_count(self) -> None:
        """Increment transaction count."""
        try:
            self.context["transaction_count"] = self.context.get("transaction_count", 0) + 1
        except Exception as e:
            logger.error(f"Failed to increment transaction count: {str(e)}")
    
    def _update_stats(self, result: Dict[str, Any], processing_time: float) -> None:
        """Update agent statistics."""
        try:
            # Update average processing time
            current_avg = self.stats["avg_processing_time"]
            count = self.stats["total_requests"]
            self.stats["avg_processing_time"] = ((current_avg * (count - 1)) + processing_time) / count
            
            # Update success/failure counts
            if result.get("success", False):
                self.stats["successful_requests"] += 1
            else:
                self.stats["blocked_requests"] += 1
                
                # Check if request was escalated
                if result.get("escalated", False):
                    self.stats["escalated_requests"] += 1
            
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")
    
    def _log_request_result(self, request: str, result: Dict[str, Any]) -> None:
        """Log request processing result."""
        try:
            success = result.get("success", False)
            risk_level = result.get("risk_level", "UNKNOWN")
            
            if success:
                logger.info(f"Request processed successfully: {self.agent_id} (risk: {risk_level})")
            else:
                logger.warning(f"Request blocked: {self.agent_id} (risk: {risk_level})")
                
        except Exception as e:
            logger.error(f"Failed to log request result: {str(e)}")
    
    def reset_statistics(self) -> None:
        """Reset agent statistics."""
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "blocked_requests": 0,
            "escalated_requests": 0,
            "avg_processing_time": 0.0
        }
        logger.info(f"Reset statistics for {self.agent_id}")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get agent health status."""
        try:
            health = {
                "status": "healthy",
                "agent_id": self.agent_id,
                "agent_type": self.agent_type,
                "is_active": self.is_active,
                "shield_protected": self.protected,
                "session_active": self.session_id is not None,
                "trust_score": self.context.get("trust_score", 1.0),
                "statistics": self.stats.copy()
            }
            
            # Determine health status
            issues = []
            
            if not self.protected:
                issues.append("ChainGuardAI protection not active")
                health["status"] = "degraded"
            
            if self.context.get("trust_score", 1.0) < 0.5:
                issues.append("Low trust score")
                health["status"] = "degraded"
            
            if self.stats["total_requests"] > 0:
                success_rate = self.stats["successful_requests"] / self.stats["total_requests"]
                if success_rate < 0.8:
                    issues.append(f"Low success rate: {success_rate:.2%}")
                    health["status"] = "unhealthy"
            
            if issues:
                health["issues"] = issues
            
            return health
            
        except Exception as e:
            logger.error(f"Failed to get health status: {str(e)}")
            return {
                "status": "error",
                "agent_id": self.agent_id,
                "error": str(e)
            }
    
    def shutdown(self) -> None:
        """Shutdown the agent."""
        try:
            logger.info(f"Shutting down agent: {self.agent_id}")
            
            # End session if active
            if self.is_active:
                self.end_session()
            
            # Cleanup resources
            if self.shield:
                self.shield.cleanup()
            
            logger.info(f"Agent shutdown complete: {self.agent_id}")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {str(e)}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
