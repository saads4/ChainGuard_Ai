"""
Gate Controller - Main entry point: intercepts planned action, runs both checks

Orchestrates the dual-check system for ChainGuardAI:
- Coordinates scope and safety checks
- Manages action approval/denial
- Handles escalation for blocked actions
- Provides comprehensive audit trail
"""

import time
from typing import Dict, Any, List, Optional, Tuple
from loguru import logger
from .model_a_scope_check import ScopeCheck
from .model_b_safety_check import SafetyCheck
from .escalation_handler import EscalationHandler
from .policy_engine import PolicyEngine


class GateController:
    """Main controller for the dual-check action gate system."""
    
    def __init__(self, policy_engine: PolicyEngine = None):
        """
        Initialize GateController.
        
        Args:
            policy_engine: Policy engine for role-based policies
        """
        self.policy_engine = policy_engine or PolicyEngine()
        
        # Initialize check components
        self.scope_check = ScopeCheck(self.policy_engine)
        self.safety_check = SafetyCheck(self.policy_engine)
        self.escalation_handler = EscalationHandler()
        
        # Gate configuration
        self.config = {
            "require_both_checks": True,  # Both checks must pass
            "allow_partial_approval": False,  # Allow if one check passes
            "auto_approve_threshold": 0.95,  # Auto-approve if confidence > threshold
            "escalation_enabled": True,
            "audit_all_actions": True
        }
        
        # Statistics
        self.stats = {
            "total_actions": 0,
            "approved_actions": 0,
            "denied_actions": 0,
            "escalated_actions": 0,
            "scope_check_failures": 0,
            "safety_check_failures": 0,
            "avg_processing_time": 0.0
        }
        
        logger.info("Initialized GateController with dual-check system")
    
    def evaluate_action(self, action: Dict[str, Any], agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an action through the dual-check system.
        
        Args:
            action: Action to evaluate
            agent_context: Context about the agent performing the action
            
        Returns:
            Evaluation result with approval decision and details
        """
        try:
            start_time = time.time()
            
            # Initialize result structure
            result = {
                "action_id": action.get("id", f"action_{int(time.time() * 1000)}"),
                "approved": False,
                "denied": False,
                "escalated": False,
                "requires_escalation": False,
                "confidence": 0.0,
                "checks": {},
                "recommendations": [],
                "processing_time": 0.0,
                "audit_info": {
                    "timestamp": time.time(),
                    "agent_id": agent_context.get("agent_id"),
                    "agent_role": agent_context.get("role"),
                    "action_type": action.get("type")
                }
            }
            
            # Run Model A: Scope Check
            scope_result = self.scope_check.check_scope(action, agent_context)
            result["checks"]["scope"] = scope_result
            
            # Run Model B: Safety Check
            safety_result = self.safety_check.check_safety(action, agent_context)
            result["checks"]["safety"] = safety_result
            
            # Evaluate results
            approval_decision = self._evaluate_check_results(scope_result, safety_result)
            result.update(approval_decision)
            
            # Handle escalation if needed
            if result["requires_escalation"] and self.config["escalation_enabled"]:
                escalation_result = self.escalation_handler.handle_escalation(
                    action, agent_context, result
                )
                result["escalation"] = escalation_result
                result["escalated"] = True
            
            # Generate recommendations
            result["recommendations"] = self._generate_recommendations(result)
            
            # Calculate overall confidence
            result["confidence"] = self._calculate_confidence(scope_result, safety_result)
            
            # Update statistics
            processing_time = time.time() - start_time
            result["processing_time"] = processing_time
            self._update_statistics(result)
            
            # Log result
            self._log_evaluation_result(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Action evaluation failed: {str(e)}")
            return self._create_error_result(action, agent_context, str(e))
    
    def _evaluate_check_results(self, scope_result: Dict[str, Any], 
                               safety_result: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate results from both checks and make approval decision."""
        try:
            decision = {
                "approved": False,
                "denied": False,
                "requires_escalation": False,
                "decision_reason": "",
                "check_summary": {
                    "scope_passed": scope_result.get("passed", False),
                    "safety_passed": safety_result.get("passed", False),
                    "scope_confidence": scope_result.get("confidence", 0.0),
                    "safety_confidence": safety_result.get("confidence", 0.0)
                }
            }
            
            scope_passed = scope_result.get("passed", False)
            safety_passed = safety_result.get("passed", False)
            
            # Both checks must pass (default behavior)
            if self.config["require_both_checks"]:
                if scope_passed and safety_passed:
                    decision["approved"] = True
                    decision["decision_reason"] = "Both scope and safety checks passed"
                elif not scope_passed and not safety_passed:
                    decision["denied"] = True
                    decision["decision_reason"] = "Both scope and safety checks failed"
                elif not scope_passed:
                    decision["denied"] = True
                    decision["decision_reason"] = "Scope check failed"
                elif not safety_passed:
                    decision["denied"] = True
                    decision["decision_reason"] = "Safety check failed"
            
            # Allow partial approval (if enabled)
            elif self.config["allow_partial_approval"]:
                if scope_passed or safety_passed:
                    decision["approved"] = True
                    decision["decision_reason"] = f"{'Scope' if scope_passed else 'Safety'} check passed"
                else:
                    decision["denied"] = True
                    decision["decision_reason"] = "Both checks failed"
            
            # Check for escalation requirements
            if (not decision["approved"] and 
                (scope_result.get("requires_escalation", False) or 
                 safety_result.get("requires_escalation", False))):
                decision["requires_escalation"] = True
                decision["decision_reason"] += " - requires escalation"
            
            # Auto-approval for high confidence
            overall_confidence = self._calculate_confidence(scope_result, safety_result)
            if (overall_confidence >= self.config["auto_approve_threshold"] and
                scope_passed and safety_passed):
                decision["approved"] = True
                decision["decision_reason"] = "Auto-approved due to high confidence"
            
            return decision
            
        except Exception as e:
            logger.error(f"Check result evaluation failed: {str(e)}")
            return {
                "approved": False,
                "denied": True,
                "requires_escalation": True,
                "decision_reason": f"Evaluation error: {str(e)}"
            }
    
    def _calculate_confidence(self, scope_result: Dict[str, Any], 
                             safety_result: Dict[str, Any]) -> float:
        """Calculate overall confidence in the decision."""
        try:
            scope_confidence = scope_result.get("confidence", 0.0)
            safety_confidence = safety_result.get("confidence", 0.0)
            
            # Weighted average (can be adjusted based on requirements)
            overall_confidence = (scope_confidence + safety_confidence) / 2.0
            
            # Consider check results
            if not scope_result.get("passed", False):
                overall_confidence *= 0.5
            if not safety_result.get("passed", False):
                overall_confidence *= 0.5
            
            return float(overall_confidence)
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {str(e)}")
            return 0.0
    
    def _generate_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on evaluation results."""
        recommendations = []
        
        if result["approved"]:
            recommendations.append("Action approved - proceed with execution")
            
            # Add confidence-based recommendations
            if result["confidence"] > 0.9:
                recommendations.append("High confidence approval - minimal monitoring needed")
            elif result["confidence"] > 0.7:
                recommendations.append("Moderate confidence - standard monitoring recommended")
            else:
                recommendations.append("Low confidence approval - enhanced monitoring recommended")
        
        elif result["denied"]:
            recommendations.append("Action denied - do not execute")
            
            # Add specific recommendations based on failed checks
            scope_check = result["checks"].get("scope", {})
            safety_check = result["checks"].get("safety", {})
            
            if not scope_check.get("passed", False):
                recommendations.append("Review action scope - exceeds agent permissions")
                if scope_check.get("suggestions"):
                    recommendations.extend(scope_check["suggestions"])
            
            if not safety_check.get("passed", False):
                recommendations.append("Review action safety - potential risks detected")
                if safety_check.get("suggestions"):
                    recommendations.extend(safety_check["suggestions"])
        
        if result["escalated"]:
            recommendations.append("Action escalated - waiting for human review")
            recommendations.append("Monitor escalation status")
        
        # Add general recommendations
        if result["confidence"] < 0.5:
            recommendations.append("Consider additional verification steps")
        
        return recommendations
    
    def _update_statistics(self, result: Dict[str, Any]) -> None:
        """Update gate controller statistics."""
        try:
            self.stats["total_actions"] += 1
            
            if result["approved"]:
                self.stats["approved_actions"] += 1
            elif result["denied"]:
                self.stats["denied_actions"] += 1
            
            if result["escalated"]:
                self.stats["escalated_actions"] += 1
            
            # Update check failure statistics
            scope_check = result["checks"].get("scope", {})
            safety_check = result["checks"].get("safety", {})
            
            if not scope_check.get("passed", False):
                self.stats["scope_check_failures"] += 1
            
            if not safety_check.get("passed", False):
                self.stats["safety_check_failures"] += 1
            
            # Update average processing time
            current_avg = self.stats["avg_processing_time"]
            count = self.stats["total_actions"]
            new_time = result["processing_time"]
            self.stats["avg_processing_time"] = ((current_avg * (count - 1)) + new_time) / count
            
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")
    
    def _log_evaluation_result(self, result: Dict[str, Any]) -> None:
        """Log evaluation result for audit purposes."""
        try:
            action_id = result["action_id"]
            decision = "APPROVED" if result["approved"] else "DENIED"
            confidence = result["confidence"]
            processing_time = result["processing_time"]
            
            logger.info(
                f"Gate evaluation: {action_id} -> {decision} "
                f"(confidence: {confidence:.3f}, time: {processing_time:.3f}s)"
            )
            
            # Log detailed check results if denied
            if result["denied"]:
                scope_passed = result["checks"]["scope"].get("passed", False)
                safety_passed = result["checks"]["safety"].get("passed", False)
                logger.warning(
                    f"Action denied - Scope: {scope_passed}, Safety: {safety_passed}"
                )
                
        except Exception as e:
            logger.error(f"Failed to log evaluation result: {str(e)}")
    
    def _create_error_result(self, action: Dict[str, Any], agent_context: Dict[str, Any], 
                            error: str) -> Dict[str, Any]:
        """Create error result when evaluation fails."""
        return {
            "action_id": action.get("id", "unknown"),
            "approved": False,
            "denied": True,
            "escalated": False,
            "requires_escalation": True,
            "confidence": 0.0,
            "checks": {
                "scope": {"error": error},
                "safety": {"error": error}
            },
            "recommendations": ["BLOCK: Evaluation error - treat as high risk"],
            "processing_time": 0.0,
            "error": error
        }
    
    def update_configuration(self, new_config: Dict[str, Any]) -> bool:
        """Update gate controller configuration."""
        try:
            valid_keys = [
                "require_both_checks", "allow_partial_approval", 
                "auto_approve_threshold", "escalation_enabled", "audit_all_actions"
            ]
            
            for key, value in new_config.items():
                if key in valid_keys:
                    self.config[key] = value
                    logger.info(f"Updated configuration: {key} = {value}")
                else:
                    logger.warning(f"Unknown configuration key: {key}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update configuration: {str(e)}")
            return False
    
    def batch_evaluate_actions(self, actions: List[Dict[str, Any]], 
                             agent_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate multiple actions in batch."""
        try:
            results = []
            
            for action in actions:
                result = self.evaluate_action(action, agent_context)
                results.append(result)
            
            logger.info(f"Batch evaluation completed: {len(results)} actions processed")
            return results
            
        except Exception as e:
            logger.error(f"Batch evaluation failed: {str(e)}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get gate controller statistics."""
        try:
            total = self.stats["total_actions"]
            
            if total > 0:
                approval_rate = (self.stats["approved_actions"] / total) * 100
                denial_rate = (self.stats["denied_actions"] / total) * 100
                escalation_rate = (self.stats["escalated_actions"] / total) * 100
            else:
                approval_rate = denial_rate = escalation_rate = 0.0
            
            return {
                "total_actions": total,
                "approved_actions": self.stats["approved_actions"],
                "denied_actions": self.stats["denied_actions"],
                "escalated_actions": self.stats["escalated_actions"],
                "approval_rate": approval_rate,
                "denial_rate": denial_rate,
                "escalation_rate": escalation_rate,
                "scope_check_failures": self.stats["scope_check_failures"],
                "safety_check_failures": self.stats["safety_check_failures"],
                "avg_processing_time": self.stats["avg_processing_time"],
                "configuration": self.config.copy()
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {str(e)}")
            return {"error": str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get gate controller status."""
        return {
            "status": "active",
            "configuration": self.config.copy(),
            "components": {
                "scope_check": self.scope_check.get_status(),
                "safety_check": self.safety_check.get_status(),
                "escalation_handler": self.escalation_handler.get_status(),
                "policy_engine": self.policy_engine.get_status()
            },
            "statistics": self.get_statistics()
        }
    
    def reset_statistics(self) -> None:
        """Reset gate controller statistics."""
        self.stats = {
            "total_actions": 0,
            "approved_actions": 0,
            "denied_actions": 0,
            "escalated_actions": 0,
            "scope_check_failures": 0,
            "safety_check_failures": 0,
            "avg_processing_time": 0.0
        }
        logger.info("Gate controller statistics reset")
    
    def test_action(self, action: Dict[str, Any], agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """Test an action without affecting statistics."""
        try:
            # Temporarily disable statistics updates
            original_stats = self.stats.copy()
            
            # Evaluate action
            result = self.evaluate_action(action, agent_context)
            
            # Restore original statistics
            self.stats = original_stats
            
            # Add test flag
            result["test_mode"] = True
            
            return result
            
        except Exception as e:
            logger.error(f"Action test failed: {str(e)}")
            return {"error": str(e), "test_mode": True}
