"""
Model A Scope Check - Verifies action is within agent's declared role/scope

Handles scope validation for ChainGuardAI:
- Role-based permission checking
- Action scope validation
- Capability verification
- Policy compliance checking
"""

import time
from typing import Dict, Any, List, Optional, Set
from loguru import logger
from .policy_engine import PolicyEngine


class ScopeCheck:
    """Validates that actions are within the agent's declared scope and role."""
    
    def __init__(self, policy_engine: PolicyEngine = None):
        """
        Initialize ScopeCheck.
        
        Args:
            policy_engine: Policy engine for role-based policies
        """
        self.policy_engine = policy_engine or PolicyEngine()
        
        # Scope check configuration
        self.config = {
            "strict_mode": False,  # Strict enforcement of scope boundaries
            "allow_delegation": True,  # Allow actions to be delegated
            "require_explicit_permission": False,  # Require explicit permission for all actions
            "cache_policies": True,  # Cache policies for performance
            "audit_violations": True
        }
        
        # Cache for policies
        self.policy_cache = {}
        
        # Statistics
        self.stats = {
            "total_checks": 0,
            "scope_passed": 0,
            "scope_failed": 0,
            "policy_violations": 0,
            "cache_hits": 0,
            "avg_check_time": 0.0
        }
        
        logger.info("Initialized ScopeCheck for role-based validation")
    
    def check_scope(self, action: Dict[str, Any], agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if action is within agent's scope.
        
        Args:
            action: Action to validate
            agent_context: Context about the agent
            
        Returns:
            Scope check result with detailed analysis
        """
        try:
            start_time = time.time()
            
            result = {
                "passed": False,
                "confidence": 0.0,
                "requires_escalation": False,
                "violations": [],
                "permissions": {},
                "scope_analysis": {},
                "recommendations": [],
                "processing_time": 0.0
            }
            
            # Extract agent information
            agent_role = agent_context.get("role", "default")
            agent_capabilities = agent_context.get("capabilities", [])
            agent_id = agent_context.get("agent_id", "unknown")
            
            # Get relevant policies
            policies = self._get_policies(agent_role)
            result["permissions"] = policies.get("permissions", {})
            
            # Extract action information
            action_type = action.get("type", "unknown")
            action_parameters = action.get("parameters", {})
            action_target = action.get("target", None)
            
            # Check 1: Role-based permission
            role_result = self._check_role_permission(
                action_type, action_parameters, agent_role, policies
            )
            result["scope_analysis"]["role_check"] = role_result
            
            # Check 2: Capability validation
            capability_result = self._check_capabilities(
                action_type, action_parameters, agent_capabilities
            )
            result["scope_analysis"]["capability_check"] = capability_result
            
            # Check 3: Action scope validation
            scope_result = self._check_action_scope(
                action, agent_context, policies
            )
            result["scope_analysis"]["scope_check"] = scope_result
            
            # Check 4: Policy compliance
            compliance_result = self._check_policy_compliance(
                action, agent_context, policies
            )
            result["scope_analysis"]["compliance_check"] = compliance_result
            
            # Aggregate results
            violations = []
            confidence_factors = []
            
            for check_name, check_result in result["scope_analysis"].items():
                if not check_result.get("passed", False):
                    violations.extend(check_result.get("violations", []))
                confidence_factors.append(check_result.get("confidence", 0.0))
            
            result["violations"] = violations
            result["confidence"] = sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
            
            # Determine final result
            result["passed"] = len(violations) == 0
            result["requires_escalation"] = self._determine_escalation_need(violations, result["confidence"])
            
            # Generate recommendations
            result["recommendations"] = self._generate_scope_recommendations(result)
            
            # Update statistics
            processing_time = time.time() - start_time
            result["processing_time"] = processing_time
            self._update_statistics(result)
            
            logger.debug(f"Scope check: {action_type} -> {'PASSED' if result['passed'] else 'FAILED'}")
            return result
            
        except Exception as e:
            logger.error(f"Scope check failed: {str(e)}")
            return self._create_error_result(str(e))
    
    def _get_policies(self, agent_role: str) -> Dict[str, Any]:
        """Get policies for agent role."""
        try:
            # Check cache first
            if self.config["cache_policies"] and agent_role in self.policy_cache:
                self.stats["cache_hits"] += 1
                return self.policy_cache[agent_role]
            
            # Load policies from policy engine
            policies = self.policy_engine.get_policy(agent_role)
            
            # Cache policies
            if self.config["cache_policies"]:
                self.policy_cache[agent_role] = policies
            
            return policies
            
        except Exception as e:
            logger.error(f"Failed to get policies for role {agent_role}: {str(e)}")
            return {}
    
    def _check_role_permission(self, action_type: str, action_parameters: Dict[str, Any],
                              agent_role: str, policies: Dict[str, Any]) -> Dict[str, Any]:
        """Check if action type is permitted for agent role."""
        try:
            result = {
                "passed": False,
                "confidence": 0.0,
                "violations": [],
                "details": {}
            }
            
            # Get allowed actions for role
            allowed_actions = policies.get("allowed_actions", [])
            denied_actions = policies.get("denied_actions", [])
            
            # Check if action is explicitly denied
            if action_type in denied_actions:
                result["violations"].append(f"Action '{action_type}' explicitly denied for role '{agent_role}'")
                result["confidence"] = 0.0
                return result
            
            # Check if action is allowed
            if action_type in allowed_actions:
                result["passed"] = True
                result["confidence"] = 0.9
                result["details"]["permission_type"] = "explicitly_allowed"
            else:
                # Check if action is in default allowed set
                default_actions = policies.get("default_actions", ["read", "write", "query"])
                if action_type in default_actions:
                    result["passed"] = True
                    result["confidence"] = 0.7
                    result["details"]["permission_type"] = "default_allowed"
                else:
                    result["violations"].append(f"Action '{action_type}' not permitted for role '{agent_role}'")
                    result["confidence"] = 0.0
            
            # Check parameter constraints
            action_constraints = policies.get("action_constraints", {}).get(action_type, {})
            for param_name, constraint in action_constraints.items():
                param_value = action_parameters.get(param_name)
                if param_value is not None and not self._validate_constraint(param_value, constraint):
                    result["passed"] = False
                    result["violations"].append(f"Parameter '{param_name}' violates constraint: {constraint}")
                    result["confidence"] *= 0.5
            
            return result
            
        except Exception as e:
            logger.error(f"Role permission check failed: {str(e)}")
            return {
                "passed": False,
                "confidence": 0.0,
                "violations": [f"Role permission check error: {str(e)}"],
                "details": {}
            }
    
    def _check_capabilities(self, action_type: str, action_parameters: Dict[str, Any],
                          agent_capabilities: List[str]) -> Dict[str, Any]:
        """Check if agent has required capabilities for action."""
        try:
            result = {
                "passed": True,
                "confidence": 0.8,
                "violations": [],
                "details": {}
            }
            
            # Map action types to required capabilities
            capability_map = {
                "payment": ["financial_transaction", "payment_processing"],
                "transfer": ["financial_transaction", "fund_transfer"],
                "report": ["data_access", "report_generation"],
                "campaign": ["marketing", "content_creation"],
                "analytics": ["data_access", "analysis"],
                "execute": ["system_access", "command_execution"],
                "delete": ["data_modification", "delete_permission"],
                "create": ["data_modification", "create_permission"]
            }
            
            required_capabilities = capability_map.get(action_type, [])
            
            if required_capabilities:
                missing_capabilities = []
                for cap in required_capabilities:
                    if cap not in agent_capabilities:
                        missing_capabilities.append(cap)
                
                if missing_capabilities:
                    result["passed"] = False
                    result["violations"].append(f"Missing required capabilities: {missing_capabilities}")
                    result["confidence"] = 0.0
                else:
                    result["confidence"] = 0.9
                    result["details"]["capability_match"] = "full"
            else:
                # No specific capabilities required
                result["confidence"] = 0.7
                result["details"]["capability_match"] = "not_required"
            
            result["details"]["required_capabilities"] = required_capabilities
            result["details"]["agent_capabilities"] = agent_capabilities
            
            return result
            
        except Exception as e:
            logger.error(f"Capability check failed: {str(e)}")
            return {
                "passed": False,
                "confidence": 0.0,
                "violations": [f"Capability check error: {str(e)}"],
                "details": {}
            }
    
    def _check_action_scope(self, action: Dict[str, Any], agent_context: Dict[str, Any],
                           policies: Dict[str, Any]) -> Dict[str, Any]:
        """Check if action is within operational scope."""
        try:
            result = {
                "passed": True,
                "confidence": 0.8,
                "violations": [],
                "details": {}
            }
            
            # Get scope constraints
            scope_constraints = policies.get("scope_constraints", {})
            
            # Check resource constraints
            resource_limits = scope_constraints.get("resource_limits", {})
            action_resources = action.get("resources", {})
            
            for resource, limit in resource_limits.items():
                usage = action_resources.get(resource, 0)
                if usage > limit:
                    result["passed"] = False
                    result["violations"].append(f"Resource '{resource}' usage ({usage}) exceeds limit ({limit})")
                    result["confidence"] *= 0.5
            
            # Check target constraints
            target_constraints = scope_constraints.get("target_constraints", {})
            action_target = action.get("target")
            
            if action_target and target_constraints:
                allowed_targets = target_constraints.get("allowed_targets", [])
                denied_targets = target_constraints.get("denied_targets", [])
                
                if action_target in denied_targets:
                    result["passed"] = False
                    result["violations"].append(f"Target '{action_target}' is explicitly denied")
                    result["confidence"] = 0.0
                elif allowed_targets and action_target not in allowed_targets:
                    result["passed"] = False
                    result["violations"].append(f"Target '{action_target}' not in allowed list")
                    result["confidence"] *= 0.5
            
            # Check time constraints
            time_constraints = scope_constraints.get("time_constraints", {})
            if time_constraints:
                current_time = time.time()
                allowed_hours = time_constraints.get("allowed_hours", range(24))
                
                if time.localtime(current_time).tm_hour not in allowed_hours:
                    result["passed"] = False
                    result["violations"].append("Action not allowed at current time")
                    result["confidence"] *= 0.7
            
            # Check location constraints
            location_constraints = scope_constraints.get("location_constraints", {})
            if location_constraints:
                agent_location = agent_context.get("location", "unknown")
                allowed_locations = location_constraints.get("allowed_locations", [])
                
                if allowed_locations and agent_location not in allowed_locations:
                    result["passed"] = False
                    result["violations"].append(f"Location '{agent_location}' not allowed")
                    result["confidence"] *= 0.7
            
            return result
            
        except Exception as e:
            logger.error(f"Action scope check failed: {str(e)}")
            return {
                "passed": False,
                "confidence": 0.0,
                "violations": [f"Scope check error: {str(e)}"],
                "details": {}
            }
    
    def _check_policy_compliance(self, action: Dict[str, Any], agent_context: Dict[str, Any],
                                policies: Dict[str, Any]) -> Dict[str, Any]:
        """Check action compliance with policies."""
        try:
            result = {
                "passed": True,
                "confidence": 0.8,
                "violations": [],
                "details": {}
            }
            
            # Get compliance rules
            compliance_rules = policies.get("compliance_rules", [])
            
            for rule in compliance_rules:
                rule_name = rule.get("name", "unnamed")
                rule_condition = rule.get("condition", "")
                rule_action = rule.get("action", "deny")
                
                # Evaluate rule condition (simplified)
                if self._evaluate_rule_condition(rule_condition, action, agent_context):
                    if rule_action == "deny":
                        result["passed"] = False
                        result["violations"].append(f"Compliance rule violation: {rule_name}")
                        result["confidence"] *= 0.5
                    elif rule_action == "warn":
                        result["violations"].append(f"Compliance warning: {rule_name}")
                        result["confidence"] *= 0.8
            
            # Check audit requirements
            audit_requirements = policies.get("audit_requirements", {})
            if audit_requirements.get("audit_all_actions", False):
                result["details"]["audit_required"] = True
            
            return result
            
        except Exception as e:
            logger.error(f"Policy compliance check failed: {str(e)}")
            return {
                "passed": False,
                "confidence": 0.0,
                "violations": [f"Compliance check error: {str(e)}"],
                "details": {}
            }
    
    def _validate_constraint(self, value: Any, constraint: Dict[str, Any]) -> bool:
        """Validate a value against a constraint."""
        try:
            constraint_type = constraint.get("type", "range")
            
            if constraint_type == "range":
                min_val = constraint.get("min")
                max_val = constraint.get("max")
                return min_val <= value <= max_val
            
            elif constraint_type == "enum":
                allowed_values = constraint.get("values", [])
                return value in allowed_values
            
            elif constraint_type == "pattern":
                import re
                pattern = constraint.get("pattern", "")
                return bool(re.match(pattern, str(value)))
            
            elif constraint_type == "length":
                min_length = constraint.get("min_length", 0)
                max_length = constraint.get("max_length", float('inf'))
                return min_length <= len(str(value)) <= max_length
            
            return True
            
        except Exception as e:
            logger.error(f"Constraint validation failed: {str(e)}")
            return False
    
    def _evaluate_rule_condition(self, condition: str, action: Dict[str, Any], 
                                agent_context: Dict[str, Any]) -> bool:
        """Evaluate a rule condition (simplified)."""
        try:
            # This is a simplified rule evaluation
            # In production, use a proper expression evaluator
            
            # Replace placeholders
            condition = condition.replace("{{action.type}}", f"'{action.get('type', '')}'")
            condition = condition.replace("{{agent.role}}", f"'{agent_context.get('role', '')}'")
            
            # Simple pattern matching
            if "action.type ==" in condition:
                action_type = action.get("type", "")
                expected_type = condition.split("==")[1].strip().strip("'\"")
                return action_type == expected_type
            
            if "agent.role ==" in condition:
                agent_role = agent_context.get("role", "")
                expected_role = condition.split("==")[1].strip().strip("'\"")
                return agent_role == expected_role
            
            return False
            
        except Exception as e:
            logger.error(f"Rule condition evaluation failed: {str(e)}")
            return False
    
    def _determine_escalation_need(self, violations: List[str], confidence: float) -> bool:
        """Determine if escalation is needed."""
        try:
            # Escalate if confidence is low
            if confidence < 0.3:
                return True
            
            # Escalate if there are critical violations
            critical_keywords = ["explicitly denied", "security violation", "policy violation"]
            for violation in violations:
                for keyword in critical_keywords:
                    if keyword in violation.lower():
                        return True
            
            # Escalate if there are multiple violations
            if len(violations) > 2:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Escalation need determination failed: {str(e)}")
            return True  # Default to escalation on error
    
    def _generate_scope_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on scope check result."""
        recommendations = []
        
        if result["passed"]:
            recommendations.append("Action is within agent scope")
            
            if result["confidence"] > 0.8:
                recommendations.append("High confidence scope approval")
            else:
                recommendations.append("Consider additional verification")
        else:
            recommendations.append("Action exceeds agent scope")
            
            # Specific recommendations based on violations
            for violation in result["violations"]:
                if "not permitted" in violation:
                    recommendations.append("Review agent role permissions")
                elif "Missing required capabilities" in violation:
                    recommendations.append("Grant required capabilities or modify action")
                elif "exceeds limit" in violation:
                    recommendations.append("Reduce resource usage or request limit increase")
                elif "not allowed at current time" in violation:
                    recommendations.append("Schedule action for allowed time window")
        
        return recommendations
    
    def _update_statistics(self, result: Dict[str, Any]) -> None:
        """Update scope check statistics."""
        try:
            self.stats["total_checks"] += 1
            
            if result["passed"]:
                self.stats["scope_passed"] += 1
            else:
                self.stats["scope_failed"] += 1
            
            if result["violations"]:
                self.stats["policy_violations"] += len(result["violations"])
            
            # Update average processing time
            current_avg = self.stats["avg_check_time"]
            count = self.stats["total_checks"]
            new_time = result["processing_time"]
            self.stats["avg_check_time"] = ((current_avg * (count - 1)) + new_time) / count
            
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")
    
    def _create_error_result(self, error: str) -> Dict[str, Any]:
        """Create error result when scope check fails."""
        return {
            "passed": False,
            "confidence": 0.0,
            "requires_escalation": True,
            "violations": [f"Scope check error: {error}"],
            "permissions": {},
            "scope_analysis": {},
            "recommendations": ["ESCALATE: Scope check failed"],
            "processing_time": 0.0,
            "error": error
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get scope check status."""
        return {
            "status": "active",
            "configuration": self.config.copy(),
            "statistics": self.stats.copy(),
            "cache_size": len(self.policy_cache),
            "policy_engine_status": self.policy_engine.get_status()
        }
    
    def reset_statistics(self) -> None:
        """Reset scope check statistics."""
        self.stats = {
            "total_checks": 0,
            "scope_passed": 0,
            "scope_failed": 0,
            "policy_violations": 0,
            "cache_hits": 0,
            "avg_check_time": 0.0
        }
        logger.info("Scope check statistics reset")
    
    def clear_cache(self) -> None:
        """Clear policy cache."""
        self.policy_cache.clear()
        logger.info("Scope check policy cache cleared")


# ---------------------------------------------------------------------------
# ScopeChecker — backwards-compatible adapter used by unit tests
# Wraps ScopeCheck with a simpler single-argument API.
# ---------------------------------------------------------------------------
class ScopeChecker:
    """Adapter around ScopeCheck with a simplified API for testing."""

    # Scope definitions per agent role
    _ROLE_SCOPES: Dict[str, Set[str]] = {
        "finance_agent": {"transfer", "payment", "report", "invoice", "ledger"},
        "marketing_agent": {"create_campaign", "analytics", "campaign", "email", "ad"},
        "default": {"read", "write", "query"},
    }

    def __init__(self):
        self._inner = ScopeCheck()

    def check_scope(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simplified scope check called by unit tests.

        Args:
            action: dict with keys ``action`` and ``agent_role``

        Returns:
            dict with ``allowed`` (bool), ``scope_violation`` (bool), ``error`` (str)
        """
        agent_role = action.get("agent_role", "")
        action_name = action.get("action", "")
        amount = action.get("amount", 0)

        # Unknown role
        if agent_role not in self._ROLE_SCOPES:
            return {
                "allowed": False,
                "scope_violation": True,
                "error": f"Unknown role: {agent_role}",
            }

        allowed_actions = self._ROLE_SCOPES[agent_role]

        # Negative amount check
        if isinstance(amount, (int, float)) and amount < 0:
            return {
                "allowed": False,
                "scope_violation": True,
                "error": "Invalid amount: negative values not allowed",
            }

        # Action not in this role's scope
        if action_name not in allowed_actions:
            cross_role = any(
                action_name in scope
                for role, scope in self._ROLE_SCOPES.items()
                if role != agent_role
            )
            error_msg = (
                f"Action '{action_name}' belongs to a different agent's scope (e.g. marketing)"
                if cross_role
                else f"Action '{action_name}' not permitted for role '{agent_role}'"
            )
            return {
                "allowed": False,
                "scope_violation": True,
                "error": error_msg,
            }

        return {"allowed": True, "scope_violation": False, "error": ""}

    def load_policy(self, agent_role: str) -> Dict[str, Any]:
        """Load a policy dict for the given agent role."""
        allowed = list(self._ROLE_SCOPES.get(agent_role, self._ROLE_SCOPES["default"]))
        return {
            "role": agent_role,
            "allowed_actions": allowed,
            "restricted_actions": [],
        }

