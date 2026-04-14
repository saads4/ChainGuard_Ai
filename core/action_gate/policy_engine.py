"""
Policy Engine - Loads and applies role-based policies per agent type

Manages policy enforcement for ChainGuardAI:
- Role-based policy loading
- Policy rule evaluation
- Dynamic policy updates
- Policy compliance checking
"""

import json
import time
from typing import Dict, Any, List, Optional
from pathlib import Path
from loguru import logger


class PolicyEngine:
    """Manages and enforces role-based policies for agent actions."""
    
    def __init__(self, policies_directory: str = "./core/action_gate/policies"):
        """
        Initialize PolicyEngine.
        
        Args:
            policies_directory: Directory containing policy files
        """
        self.policies_directory = Path(policies_directory)
        self.policies_directory.mkdir(parents=True, exist_ok=True)
        
        # Policy storage
        self.policies = {}
        self.default_policy = None
        
        # Policy cache
        self.policy_cache = {}
        self.cache_timestamps = {}
        
        # Statistics
        self.stats = {
            "policy_loads": 0,
            "cache_hits": 0,
            "policy_evaluations": 0,
            "policy_violations": 0,
            "avg_load_time": 0.0
        }
        
        # Load all policies
        self._load_all_policies()
        
        logger.info(f"Initialized PolicyEngine with {len(self.policies)} policies")
    
    def get_policy(self, agent_role: str) -> Dict[str, Any]:
        """
        Get policy for a specific agent role.
        
        Args:
            agent_role: Role of the agent
            
        Returns:
            Policy dictionary for the role
        """
        try:
            # Check cache first
            if agent_role in self.policy_cache:
                self.stats["cache_hits"] += 1
                return self.policy_cache[agent_role]
            
            # Load policy
            policy = self._load_policy(agent_role)
            
            # Cache policy
            self.policy_cache[agent_role] = policy
            self.cache_timestamps[agent_role] = time.time()
            
            return policy
            
        except Exception as e:
            logger.error(f"Failed to get policy for role {agent_role}: {str(e)}")
            return self.default_policy or {}
    
    def evaluate_policy(self, agent_role: str, action: Dict[str, Any], 
                       context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate policy for an action.
        
        Args:
            agent_role: Role of the agent
            action: Action to evaluate
            context: Additional context
            
        Returns:
            Policy evaluation result
        """
        try:
            start_time = time.time()
            
            self.stats["policy_evaluations"] += 1
            
            # Get policy
            policy = self.get_policy(agent_role)
            
            result = {
                "allowed": False,
                "confidence": 0.0,
                "violations": [],
                "requirements": [],
                "conditions_met": [],
                "evaluated_rules": [],
                "processing_time": 0.0
            }
            
            # Evaluate action against policy rules
            rules = policy.get("rules", [])
            
            for rule in rules:
                rule_result = self._evaluate_rule(rule, action, context)
                result["evaluated_rules"].append(rule_result)
                
                if not rule_result["passed"]:
                    result["violations"].append(rule_result["reason"])
                    result["requirements"].extend(rule_result.get("requirements", []))
                else:
                    result["conditions_met"].append(rule["name"])
            
            # Determine overall result
            result["allowed"] = len(result["violations"]) == 0
            result["confidence"] = self._calculate_policy_confidence(result["evaluated_rules"])
            
            # Update processing time
            result["processing_time"] = time.time() - start_time
            
            # Update statistics
            if not result["allowed"]:
                self.stats["policy_violations"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Policy evaluation failed: {str(e)}")
            return {
                "allowed": False,
                "confidence": 0.0,
                "violations": [f"Evaluation error: {str(e)}"],
                "requirements": [],
                "conditions_met": [],
                "evaluated_rules": [],
                "processing_time": 0.0
            }
    
    def _evaluate_rule(self, rule: Dict[str, Any], action: Dict[str, Any], 
                      context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single policy rule."""
        try:
            result = {
                "rule_name": rule.get("name", "unnamed"),
                "passed": False,
                "confidence": 0.0,
                "reason": "",
                "requirements": []
            }
            
            # Get rule conditions
            conditions = rule.get("conditions", [])
            action_type = action.get("type", "unknown")
            action_parameters = action.get("parameters", {})
            
            # Check if rule applies to this action type
            applicable_types = rule.get("action_types", ["*"])
            if applicable_types != ["*"] and action_type not in applicable_types:
                result["passed"] = True
                result["reason"] = "Rule not applicable to action type"
                result["confidence"] = 1.0
                return result
            
            # Evaluate all conditions
            all_conditions_met = True
            condition_results = []
            
            for condition in conditions:
                condition_result = self._evaluate_condition(condition, action, context)
                condition_results.append(condition_result)
                
                if not condition_result["met"]:
                    all_conditions_met = False
                    result["requirements"].extend(condition_result.get("requirements", []))
            
            # Determine rule result
            if all_conditions_met:
                result["passed"] = True
                result["reason"] = "All conditions met"
                result["confidence"] = sum(cr["confidence"] for cr in condition_results) / len(condition_results)
            else:
                result["passed"] = False
                result["reason"] = "Conditions not met"
                result["confidence"] = sum(cr["confidence"] for cr in condition_results) / len(condition_results)
            
            return result
            
        except Exception as e:
            logger.error(f"Rule evaluation failed: {str(e)}")
            return {
                "rule_name": rule.get("name", "unnamed"),
                "passed": False,
                "confidence": 0.0,
                "reason": f"Rule evaluation error: {str(e)}",
                "requirements": []
            }
    
    def _evaluate_condition(self, condition: Dict[str, Any], action: Dict[str, Any],
                           context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single condition."""
        try:
            result = {
                "met": False,
                "confidence": 0.0,
                "requirements": []
            }
            
            condition_type = condition.get("type", "simple")
            
            if condition_type == "simple":
                result = self._evaluate_simple_condition(condition, action, context)
            elif condition_type == "complex":
                result = self._evaluate_complex_condition(condition, action, context)
            elif condition_type == "temporal":
                result = self._evaluate_temporal_condition(condition, action, context)
            elif condition_type == "resource":
                result = self._evaluate_resource_condition(condition, action, context)
            else:
                result["requirements"].append(f"Unknown condition type: {condition_type}")
            
            return result
            
        except Exception as e:
            logger.error(f"Condition evaluation failed: {str(e)}")
            return {
                "met": False,
                "confidence": 0.0,
                "requirements": [f"Condition evaluation error: {str(e)}"]
            }
    
    def _evaluate_simple_condition(self, condition: Dict[str, Any], action: Dict[str, Any],
                                 context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a simple condition."""
        result = {"met": False, "confidence": 0.0, "requirements": []}
        
        try:
            field = condition.get("field")
            operator = condition.get("operator", "equals")
            expected_value = condition.get("value")
            
            # Get actual value
            if field.startswith("action."):
                actual_value = self._get_nested_value(action, field[7:])
            elif field.startswith("context."):
                actual_value = self._get_nested_value(context, field[8:])
            else:
                actual_value = action.get(field)
            
            # Evaluate condition
            if operator == "equals":
                result["met"] = actual_value == expected_value
            elif operator == "not_equals":
                result["met"] = actual_value != expected_value
            elif operator == "in":
                result["met"] = actual_value in expected_value
            elif operator == "not_in":
                result["met"] = actual_value not in expected_value
            elif operator == "greater_than":
                result["met"] = actual_value > expected_value
            elif operator == "less_than":
                result["met"] = actual_value < expected_value
            elif operator == "contains":
                result["met"] = str(expected_value) in str(actual_value)
            elif operator == "matches":
                import re
                result["met"] = bool(re.match(expected_value, str(actual_value)))
            else:
                result["requirements"].append(f"Unknown operator: {operator}")
            
            result["confidence"] = 1.0 if result["met"] else 0.0
            
            return result
            
        except Exception as e:
            result["requirements"].append(f"Simple condition error: {str(e)}")
            return result
    
    def _evaluate_complex_condition(self, condition: Dict[str, Any], action: Dict[str, Any],
                                   context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a complex condition with multiple sub-conditions."""
        result = {"met": False, "confidence": 0.0, "requirements": []}
        
        try:
            sub_conditions = condition.get("conditions", [])
            logic = condition.get("logic", "and")  # and/or
            
            sub_results = []
            for sub_cond in sub_conditions:
                sub_result = self._evaluate_condition(sub_cond, action, context)
                sub_results.append(sub_result)
            
            if logic == "and":
                result["met"] = all(sr["met"] for sr in sub_results)
            else:  # or
                result["met"] = any(sr["met"] for sr in sub_results)
            
            # Aggregate confidence
            result["confidence"] = sum(sr["confidence"] for sr in sub_results) / len(sub_results)
            
            # Aggregate requirements
            for sr in sub_results:
                result["requirements"].extend(sr["requirements"])
            
            return result
            
        except Exception as e:
            result["requirements"].append(f"Complex condition error: {str(e)}")
            return result
    
    def _evaluate_temporal_condition(self, condition: Dict[str, Any], action: Dict[str, Any],
                                    context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a temporal condition."""
        result = {"met": False, "confidence": 0.0, "requirements": []}
        
        try:
            current_time = time.time()
            time_field = condition.get("time_field", "current_time")
            
            if time_field == "current_time":
                actual_time = current_time
            else:
                actual_time = self._get_nested_value(context, time_field)
            
            # Check time ranges
            time_ranges = condition.get("allowed_ranges", [])
            
            for time_range in time_ranges:
                start_time = time_range.get("start")
                end_time = time_range.get("end")
                
                if start_time <= actual_time <= end_time:
                    result["met"] = True
                    break
            
            result["confidence"] = 1.0 if result["met"] else 0.0
            
            return result
            
        except Exception as e:
            result["requirements"].append(f"Temporal condition error: {str(e)}")
            return result
    
    def _evaluate_resource_condition(self, condition: Dict[str, Any], action: Dict[str, Any],
                                   context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a resource condition."""
        result = {"met": False, "confidence": 0.0, "requirements": []}
        
        try:
            resource_type = condition.get("resource_type")
            limit = condition.get("limit")
            operator = condition.get("operator", "less_than_or_equal")
            
            # Get resource usage
            resources = action.get("resources", {})
            actual_usage = resources.get(resource_type, 0)
            
            # Evaluate condition
            if operator == "less_than_or_equal":
                result["met"] = actual_usage <= limit
            elif operator == "less_than":
                result["met"] = actual_usage < limit
            elif operator == "greater_than":
                result["met"] = actual_usage > limit
            elif operator == "greater_than_or_equal":
                result["met"] = actual_usage >= limit
            
            result["confidence"] = 1.0 if result["met"] else 0.0
            
            if not result["met"]:
                result["requirements"].append(f"Resource {resource_type} usage ({actual_usage}) exceeds limit ({limit})")
            
            return result
            
        except Exception as e:
            result["requirements"].append(f"Resource condition error: {str(e)}")
            return result
    
    def _get_nested_value(self, obj: Dict[str, Any], path: str) -> Any:
        """Get nested value from dictionary using dot notation."""
        try:
            keys = path.split(".")
            value = obj
            
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return None
            
            return value
            
        except Exception:
            return None
    
    def _calculate_policy_confidence(self, rule_results: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence in policy evaluation."""
        try:
            if not rule_results:
                return 0.0
            
            confidences = [rr["confidence"] for rr in rule_results]
            return sum(confidences) / len(confidences)
            
        except Exception:
            return 0.0
    
    def _load_all_policies(self) -> None:
        """Load all policy files."""
        try:
            # Load default policy first
            default_policy_path = self.policies_directory / "default_policy.json"
            if default_policy_path.exists():
                self.default_policy = self._load_policy_file(default_policy_path)
                self.policies["default"] = self.default_policy
            
            # Load role-specific policies
            policy_files = [
                "finance_agent_policy.json",
                "marketing_agent_policy.json"
            ]
            
            for policy_file in policy_files:
                policy_path = self.policies_directory / policy_file
                if policy_path.exists():
                    policy = self._load_policy_file(policy_path)
                    role_name = policy_file.replace("_policy.json", "")
                    self.policies[role_name] = policy
            
            logger.info(f"Loaded {len(self.policies)} policies")
            
        except Exception as e:
            logger.error(f"Failed to load policies: {str(e)}")
    
    def _load_policy(self, agent_role: str) -> Dict[str, Any]:
        """Load policy for a specific role."""
        try:
            # Check if role-specific policy exists
            policy_file = f"{agent_role}_policy.json"
            policy_path = self.policies_directory / policy_file
            
            if policy_path.exists():
                return self._load_policy_file(policy_path)
            else:
                # Return default policy
                return self.default_policy or {}
                
        except Exception as e:
            logger.error(f"Failed to load policy for {agent_role}: {str(e)}")
            return self.default_policy or {}
    
    def _load_policy_file(self, file_path: Path) -> Dict[str, Any]:
        """Load policy from file."""
        try:
            with open(file_path, 'r') as f:
                policy = json.load(f)
            
            self.stats["policy_loads"] += 1
            logger.debug(f"Loaded policy from {file_path}")
            return policy
            
        except Exception as e:
            logger.error(f"Failed to load policy file {file_path}: {str(e)}")
            return {}
    
    def add_policy(self, agent_role: str, policy: Dict[str, Any]) -> bool:
        """Add or update a policy."""
        try:
            self.policies[agent_role] = policy
            
            # Clear cache for this role
            if agent_role in self.policy_cache:
                del self.policy_cache[agent_role]
            
            logger.info(f"Added/updated policy for role: {agent_role}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add policy: {str(e)}")
            return False
    
    def remove_policy(self, agent_role: str) -> bool:
        """Remove a policy."""
        try:
            if agent_role in self.policies:
                del self.policies[agent_role]
            
            if agent_role in self.policy_cache:
                del self.policy_cache[agent_role]
            
            logger.info(f"Removed policy for role: {agent_role}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove policy: {str(e)}")
            return False
    
    def save_policy(self, agent_role: str) -> bool:
        """Save policy to file."""
        try:
            if agent_role not in self.policies:
                return False
            
            policy = self.policies[agent_role]
            policy_file = f"{agent_role}_policy.json"
            policy_path = self.policies_directory / policy_file
            
            with open(policy_path, 'w') as f:
                json.dump(policy, f, indent=2)
            
            logger.info(f"Saved policy for {agent_role} to {policy_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save policy: {str(e)}")
            return False
    
    def get_policy_summary(self, agent_role: str) -> Dict[str, Any]:
        """Get summary of a policy."""
        try:
            policy = self.get_policy(agent_role)
            
            summary = {
                "role": agent_role,
                "rules_count": len(policy.get("rules", [])),
                "allowed_actions": policy.get("allowed_actions", []),
                "denied_actions": policy.get("denied_actions", []),
                "scope_constraints": policy.get("scope_constraints", {}),
                "compliance_rules": len(policy.get("compliance_rules", [])),
                "last_updated": policy.get("last_updated", "unknown")
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to get policy summary: {str(e)}")
            return {"error": str(e)}
    
    def clear_cache(self) -> None:
        """Clear policy cache."""
        self.policy_cache.clear()
        self.cache_timestamps.clear()
        logger.info("Policy cache cleared")
    
    def get_status(self) -> Dict[str, Any]:
        """Get policy engine status."""
        return {
            "status": "active",
            "loaded_policies": list(self.policies.keys()),
            "cache_size": len(self.policy_cache),
            "statistics": self.stats.copy(),
            "policies_directory": str(self.policies_directory)
        }
    
    def reset_statistics(self) -> None:
        """Reset policy engine statistics."""
        self.stats = {
            "policy_loads": 0,
            "cache_hits": 0,
            "policy_evaluations": 0,
            "policy_violations": 0,
            "avg_load_time": 0.0
        }
        logger.info("Policy engine statistics reset")
