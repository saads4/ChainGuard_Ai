"""
Escalation Handler - Handles denied actions: human-in-loop or hard block

Manages escalation workflows for ChainGuardAI:
- Human-in-loop escalation
- Automatic approval workflows
- Escalation tracking and resolution
- Notification and alerting
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from enum import Enum
from loguru import logger


class EscalationStatus(Enum):
    """Escalation status enumeration."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class EscalationHandler:
    """Handles escalation of denied or risky actions."""
    
    def __init__(self):
        """Initialize EscalationHandler."""
        # Escalation configuration
        self.config = {
            "auto_approve_threshold": 0.95,  # Auto-approve if confidence > threshold
            "escalation_timeout": 3600,      # 1 hour timeout
            "max_escalations_per_hour": 10,  # Rate limiting
            "require_human_approval": True,   # Require human for high-risk actions
            "enable_notifications": True,
            "notification_channels": ["email", "slack"]
        }
        
        # Escalation storage
        self.escalations = {}  # In-memory storage (in production, use database)
        self.escalation_queue = []
        
        # Statistics
        self.stats = {
            "total_escalations": 0,
            "auto_approved": 0,
            "human_approved": 0,
            "denied": 0,
            "expired": 0,
            "avg_resolution_time": 0.0,
            "escalations_per_hour": 0
        }
        
        # Rate limiting
        self.escalation_timestamps = []
        
        logger.info("Initialized EscalationHandler")
    
    def handle_escalation(self, action: Dict[str, Any], agent_context: Dict[str, Any],
                         gate_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle escalation of a denied action.
        
        Args:
            action: The action being escalated
            agent_context: Context about the agent
            gate_result: Result from the gate controller
            
        Returns:
            Escalation handling result
        """
        try:
            # Check rate limiting
            if not self._check_rate_limit():
                return self._create_rate_limit_result()
            
            # Create escalation record
            escalation_id = str(uuid.uuid4())
            escalation = {
                "id": escalation_id,
                "action": action,
                "agent_context": agent_context,
                "gate_result": gate_result,
                "status": EscalationStatus.PENDING.value,
                "created_at": time.time(),
                "updated_at": time.time(),
                "expires_at": time.time() + self.config["escalation_timeout"],
                "escalation_reason": self._determine_escalation_reason(gate_result),
                "priority": self._calculate_priority(action, gate_result),
                "auto_approve": self._should_auto_approve(action, gate_result),
                "resolution": None,
                "reviewer": None,
                "review_comments": None
            }
            
            # Store escalation
            self.escalations[escalation_id] = escalation
            self.escalation_queue.append(escalation_id)
            
            # Update statistics
            self.stats["total_escalations"] += 1
            self.escalation_timestamps.append(time.time())
            
            # Handle auto-approval
            if escalation["auto_approve"]:
                return self._auto_approve_escalation(escalation_id)
            
            # Send notifications
            if self.config["enable_notifications"]:
                self._send_notifications(escalation)
            
            # Create result
            result = {
                "escalation_id": escalation_id,
                "status": escalation["status"],
                "requires_human_review": not escalation["auto_approve"],
                "priority": escalation["priority"],
                "escalation_reason": escalation["escalation_reason"],
                "expires_at": escalation["expires_at"],
                "estimated_resolution_time": self._estimate_resolution_time(escalation),
                "next_steps": self._get_next_steps(escalation)
            }
            
            logger.info(f"Created escalation {escalation_id} for action {action.get('type', 'unknown')}")
            return result
            
        except Exception as e:
            logger.error(f"Escalation handling failed: {str(e)}")
            return {
                "escalation_id": None,
                "status": "error",
                "error": str(e),
                "requires_human_review": True
            }
    
    def resolve_escalation(self, escalation_id: str, resolution: Dict[str, Any],
                         reviewer: str = "system") -> Dict[str, Any]:
        """
        Resolve an escalation.
        
        Args:
            escalation_id: ID of escalation to resolve
            resolution: Resolution details (approved/denied, comments, etc.)
            reviewer: Person or system resolving the escalation
            
        Returns:
            Resolution result
        """
        try:
            if escalation_id not in self.escalations:
                return {"error": f"Escalation {escalation_id} not found"}
            
            escalation = self.escalations[escalation_id]
            
            # Check if escalation is still pending
            if escalation["status"] != EscalationStatus.PENDING.value:
                return {"error": f"Escalation {escalation_id} already resolved"}
            
            # Update escalation
            escalation["status"] = resolution.get("decision", "denied")
            escalation["resolution"] = resolution
            escalation["reviewer"] = reviewer
            escalation["review_comments"] = resolution.get("comments", "")
            escalation["updated_at"] = time.time()
            
            # Update statistics
            resolution_time = escalation["updated_at"] - escalation["created_at"]
            self._update_resolution_stats(resolution_time, escalation["status"])
            
            # Remove from queue
            if escalation_id in self.escalation_queue:
                self.escalation_queue.remove(escalation_id)
            
            # Send resolution notifications
            if self.config["enable_notifications"]:
                self._send_resolution_notifications(escalation)
            
            result = {
                "escalation_id": escalation_id,
                "resolution": escalation["status"],
                "reviewer": reviewer,
                "review_comments": escalation["review_comments"],
                "resolution_time": resolution_time,
                "action_permitted": escalation["status"] == EscalationStatus.APPROVED.value
            }
            
            logger.info(f"Resolved escalation {escalation_id}: {escalation['status']} by {reviewer}")
            return result
            
        except Exception as e:
            logger.error(f"Escalation resolution failed: {str(e)}")
            return {"error": str(e)}
    
    def get_escalation(self, escalation_id: str) -> Optional[Dict[str, Any]]:
        """Get escalation details."""
        return self.escalations.get(escalation_id)
    
    def get_pending_escalations(self, priority_filter: str = None) -> List[Dict[str, Any]]:
        """Get list of pending escalations."""
        try:
            pending_escalations = []
            
            for escalation_id in self.escalation_queue:
                escalation = self.escalations[escalation_id]
                
                # Check if still pending and not expired
                if (escalation["status"] == EscalationStatus.PENDING.value and
                    time.time() < escalation["expires_at"]):
                    
                    # Apply priority filter if specified
                    if priority_filter is None or escalation["priority"] == priority_filter:
                        pending_escalations.append(escalation.copy())
            
            # Sort by priority and creation time
            priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            pending_escalations.sort(key=lambda x: (
                priority_order.get(x["priority"], 4),
                x["created_at"]
            ))
            
            return pending_escalations
            
        except Exception as e:
            logger.error(f"Failed to get pending escalations: {str(e)}")
            return []
    
    def check_expired_escalations(self) -> int:
        """Check and expire overdue escalations."""
        try:
            current_time = time.time()
            expired_count = 0
            
            for escalation_id, escalation in list(self.escalations.items()):
                if (escalation["status"] == EscalationStatus.PENDING.value and
                    current_time > escalation["expires_at"]):
                    
                    # Mark as expired
                    escalation["status"] = EscalationStatus.EXPIRED.value
                    escalation["updated_at"] = current_time
                    
                    # Remove from queue
                    if escalation_id in self.escalation_queue:
                        self.escalation_queue.remove(escalation_id)
                    
                    expired_count += 1
                    self.stats["expired"] += 1
                    
                    # Send expiration notifications
                    if self.config["enable_notifications"]:
                        self._send_expiration_notifications(escalation)
            
            if expired_count > 0:
                logger.info(f"Expired {expired_count} overdue escalations")
            
            return expired_count
            
        except Exception as e:
            logger.error(f"Failed to check expired escalations: {str(e)}")
            return 0
    
    def _check_rate_limit(self) -> bool:
        """Check if escalation rate limit is exceeded."""
        try:
            current_time = time.time()
            one_hour_ago = current_time - 3600
            
            # Remove old timestamps
            self.escalation_timestamps = [
                ts for ts in self.escalation_timestamps if ts > one_hour_ago
            ]
            
            # Check rate limit
            return len(self.escalation_timestamps) < self.config["max_escalations_per_hour"]
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {str(e)}")
            return False
    
    def _determine_escalation_reason(self, gate_result: Dict[str, Any]) -> str:
        """Determine the reason for escalation."""
        try:
            reasons = []
            
            # Check scope check failures
            scope_check = gate_result.get("checks", {}).get("scope", {})
            if not scope_check.get("passed", False):
                reasons.append("scope_violation")
            
            # Check safety check failures
            safety_check = gate_result.get("checks", {}).get("safety", {})
            if not safety_check.get("passed", False):
                reasons.append("safety_concern")
            
            # Check confidence
            confidence = gate_result.get("confidence", 0.0)
            if confidence < 0.5:
                reasons.append("low_confidence")
            
            return ";".join(reasons) if reasons else "general_review"
            
        except Exception as e:
            logger.error(f"Failed to determine escalation reason: {str(e)}")
            return "unknown"
    
    def _calculate_priority(self, action: Dict[str, Any], gate_result: Dict[str, Any]) -> str:
        """Calculate escalation priority."""
        try:
            # High-risk actions get higher priority
            risk_factors = gate_result.get("risk_factors", [])
            if any(factor in risk_factors for factor in ["dangerous", "system", "critical"]):
                return "critical"
            
            # Financial actions get high priority
            if action.get("type") in ["payment", "transfer", "financial"]:
                amount = action.get("parameters", {}).get("amount", 0)
                if amount > 1000:
                    return "high"
                elif amount > 100:
                    return "medium"
            
            # System actions get high priority
            if action.get("type") in ["delete", "execute", "system_change"]:
                return "high"
            
            # Default priority based on confidence
            confidence = gate_result.get("confidence", 0.0)
            if confidence < 0.3:
                return "high"
            elif confidence < 0.6:
                return "medium"
            
            return "low"
            
        except Exception as e:
            logger.error(f"Failed to calculate priority: {str(e)}")
            return "medium"
    
    def _should_auto_approve(self, action: Dict[str, Any], gate_result: Dict[str, Any]) -> bool:
        """Determine if escalation should be auto-approved."""
        try:
            # Check confidence threshold
            confidence = gate_result.get("confidence", 0.0)
            if confidence >= self.config["auto_approve_threshold"]:
                return True
            
            # Check for low-risk actions
            risk_level = gate_result.get("risk_level", "MEDIUM")
            if risk_level == "LOW" and confidence > 0.8:
                return True
            
            # Check agent trust level
            agent_context = gate_result.get("agent_context", {})
            trust_score = agent_context.get("trust_score", 0.0)
            if trust_score > 0.9 and confidence > 0.7:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Auto-approval check failed: {str(e)}")
            return False
    
    def _auto_approve_escalation(self, escalation_id: str) -> Dict[str, Any]:
        """Auto-approve an escalation."""
        try:
            resolution = {
                "decision": "approved",
                "comments": "Auto-approved due to high confidence and low risk",
                "auto_approved": True
            }
            
            return self.resolve_escalation(escalation_id, resolution, "system")
            
        except Exception as e:
            logger.error(f"Auto-approval failed: {str(e)}")
            return {"error": str(e)}
    
    def _estimate_resolution_time(self, escalation: Dict[str, Any]) -> int:
        """Estimate resolution time in minutes."""
        try:
            priority = escalation["priority"]
            
            # Base times by priority (in minutes)
            base_times = {
                "critical": 15,  # 15 minutes
                "high": 30,      # 30 minutes
                "medium": 60,    # 1 hour
                "low": 120       # 2 hours
            }
            
            return base_times.get(priority, 60)
            
        except Exception:
            return 60
    
    def _get_next_steps(self, escalation: Dict[str, Any]) -> List[str]:
        """Get next steps for escalation."""
        steps = []
        
        if escalation["auto_approve"]:
            steps.append("Auto-approval in progress")
            steps.append("Action will be permitted automatically")
        else:
            steps.append("Waiting for human review")
            steps.append("Reviewer will assess action safety and scope")
            
            if escalation["priority"] == "critical":
                steps.append("Urgent review requested")
            
        steps.append(f"Expires at {time.ctime(escalation['expires_at'])}")
        
        return steps
    
    def _send_notifications(self, escalation: Dict[str, Any]) -> None:
        """Send escalation notifications."""
        try:
            # In production, implement actual notification sending
            logger.info(f"Sending notifications for escalation {escalation['id']}")
            
            # Log notification details
            notification_data = {
                "escalation_id": escalation["id"],
                "priority": escalation["priority"],
                "reason": escalation["escalation_reason"],
                "channels": self.config["notification_channels"]
            }
            
            logger.debug(f"Notification data: {notification_data}")
            
        except Exception as e:
            logger.error(f"Failed to send notifications: {str(e)}")
    
    def _send_resolution_notifications(self, escalation: Dict[str, Any]) -> None:
        """Send resolution notifications."""
        try:
            logger.info(f"Sending resolution notifications for escalation {escalation['id']}")
            
        except Exception as e:
            logger.error(f"Failed to send resolution notifications: {str(e)}")
    
    def _send_expiration_notifications(self, escalation: Dict[str, Any]) -> None:
        """Send expiration notifications."""
        try:
            logger.info(f"Sending expiration notifications for escalation {escalation['id']}")
            
        except Exception as e:
            logger.error(f"Failed to send expiration notifications: {str(e)}")
    
    def _update_resolution_stats(self, resolution_time: float, status: str) -> None:
        """Update resolution statistics."""
        try:
            # Update average resolution time
            total_resolved = self.stats["auto_approved"] + self.stats["human_approved"] + self.stats["denied"]
            if total_resolved > 0:
                current_avg = self.stats["avg_resolution_time"]
                self.stats["avg_resolution_time"] = ((current_avg * (total_resolved - 1)) + resolution_time) / total_resolved
            
            # Update status counts
            if status == EscalationStatus.APPROVED.value:
                self.stats["human_approved"] += 1
            elif status == EscalationStatus.DENIED.value:
                self.stats["denied"] += 1
            
        except Exception as e:
            logger.error(f"Failed to update resolution stats: {str(e)}")
    
    def _create_rate_limit_result(self) -> Dict[str, Any]:
        """Create rate limit result."""
        return {
            "escalation_id": None,
            "status": "rate_limited",
            "error": "Too many escalations. Please try again later.",
            "retry_after": 3600,  # 1 hour
            "requires_human_review": True
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get escalation handler statistics."""
        try:
            total = self.stats["total_escalations"]
            
            if total > 0:
                auto_approval_rate = (self.stats["auto_approved"] / total) * 100
                human_approval_rate = (self.stats["human_approved"] / total) * 100
                denial_rate = (self.stats["denied"] / total) * 100
                expiration_rate = (self.stats["expired"] / total) * 100
            else:
                auto_approval_rate = human_approval_rate = denial_rate = expiration_rate = 0.0
            
            return {
                "total_escalations": total,
                "auto_approved": self.stats["auto_approved"],
                "human_approved": self.stats["human_approved"],
                "denied": self.stats["denied"],
                "expired": self.stats["expired"],
                "auto_approval_rate": auto_approval_rate,
                "human_approval_rate": human_approval_rate,
                "denial_rate": denial_rate,
                "expiration_rate": expiration_rate,
                "avg_resolution_time": self.stats["avg_resolution_time"],
                "pending_count": len(self.escalation_queue),
                "configuration": self.config.copy()
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {str(e)}")
            return {"error": str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get escalation handler status."""
        return {
            "status": "active",
            "configuration": self.config.copy(),
            "statistics": self.get_statistics(),
            "pending_escalations": len(self.escalation_queue),
            "rate_limit_status": len(self.escalation_timestamps)
        }
    
    def reset_statistics(self) -> None:
        """Reset escalation statistics."""
        self.stats = {
            "total_escalations": 0,
            "auto_approved": 0,
            "human_approved": 0,
            "denied": 0,
            "expired": 0,
            "avg_resolution_time": 0.0,
            "escalations_per_hour": 0
        }
        logger.info("Escalation handler statistics reset")
    
    def cleanup_expired_escalations(self) -> int:
        """Clean up expired escalations and return count cleaned."""
        return self.check_expired_escalations()
