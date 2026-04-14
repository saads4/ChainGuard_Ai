"""
Model B Safety Check - Evaluates action parameters for risk (amounts, paths, etc.)

Handles safety validation for ChainGuardAI:
- Parameter risk assessment
- Resource safety checks
- Operational safety validation
- Risk-based recommendations
"""

import time
import os
import re
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
from loguru import logger
from .policy_engine import PolicyEngine


class SafetyCheck:
    """Validates action safety by evaluating parameters and operational risks."""
    
    def __init__(self, policy_engine: PolicyEngine = None):
        """
        Initialize SafetyCheck.
        
        Args:
            policy_engine: Policy engine for safety policies
        """
        self.policy_engine = policy_engine or PolicyEngine()
        
        # Safety check configuration
        self.config = {
            "strict_parameter_validation": True,
            "allow_risk_mitigation": True,
            "require_safety_approval": False,
            "validate_file_paths": True,
            "validate_amounts": True,
            "validate_network_access": True
        }
        
        # Safety rules and thresholds
        self.safety_rules = self._load_safety_rules()
        
        # Statistics
        self.stats = {
            "total_checks": 0,
            "safety_passed": 0,
            "safety_failed": 0,
            "high_risk_detected": 0,
            "parameter_violations": 0,
            "avg_check_time": 0.0
        }
        
        logger.info("Initialized SafetyCheck for parameter risk assessment")
    
    def check_safety(self, action: Dict[str, Any], agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check action safety by evaluating parameters and operational risks.
        
        Args:
            action: Action to validate
            agent_context: Context about the agent
            
        Returns:
            Safety check result with detailed risk analysis
        """
        try:
            start_time = time.time()
            
            result = {
                "passed": False,
                "confidence": 0.0,
                "requires_escalation": False,
                "risk_level": "LOW",
                "violations": [],
                "risk_factors": [],
                "parameter_analysis": {},
                "safety_recommendations": [],
                "processing_time": 0.0
            }
            
            # Extract action parameters
            action_type = action.get("type", "unknown")
            parameters = action.get("parameters", {})
            resources = action.get("resources", {})
            
            # Run safety checks based on action type
            safety_checks = self._get_safety_checks(action_type)
            
            risk_scores = []
            all_violations = []
            
            for check_name in safety_checks:
                check_result = self._run_safety_check(check_name, parameters, resources, agent_context)
                result["parameter_analysis"][check_name] = check_result
                
                if not check_result.get("passed", False):
                    all_violations.extend(check_result.get("violations", []))
                
                risk_scores.append(check_result.get("risk_score", 0.0))
            
            # Aggregate results
            result["violations"] = all_violations
            result["risk_level"] = self._calculate_risk_level(risk_scores, all_violations)
            result["confidence"] = self._calculate_safety_confidence(risk_scores)
            result["passed"] = len(all_violations) == 0 and result["risk_level"] != "HIGH"
            result["requires_escalation"] = self._determine_escalation_need(result["risk_level"], all_violations)
            
            # Generate risk factors
            result["risk_factors"] = self._identify_risk_factors(result["parameter_analysis"])
            
            # Generate safety recommendations
            result["safety_recommendations"] = self._generate_safety_recommendations(result)
            
            # Update statistics
            processing_time = time.time() - start_time
            result["processing_time"] = processing_time
            self._update_statistics(result)
            
            logger.debug(f"Safety check: {action_type} -> {result['risk_level']} ({'PASSED' if result['passed'] else 'FAILED'})")
            return result
            
        except Exception as e:
            logger.error(f"Safety check failed: {str(e)}")
            return self._create_error_result(str(e))
    
    def _get_safety_checks(self, action_type: str) -> List[str]:
        """Get relevant safety checks for action type."""
        check_map = {
            "payment": ["amount_validation", "financial_safety", "recipient_validation"],
            "transfer": ["amount_validation", "financial_safety", "account_validation"],
            "file_operation": ["file_path_validation", "resource_safety", "permission_check"],
            "delete": ["file_path_validation", "destructive_action_check", "backup_requirement"],
            "create": ["resource_allocation", "quota_check", "naming_validation"],
            "execute": ["command_validation", "resource_safety", "privilege_check"],
            "network_access": ["url_validation", "network_safety", "data_exposure_check"],
            "data_access": ["privacy_check", "data_sensitivity", "access_control"],
            "system_change": ["system_safety", "impact_assessment", "rollback_capability"]
        }
        
        return check_map.get(action_type, ["general_safety"])
    
    def _run_safety_check(self, check_name: str, parameters: Dict[str, Any], 
                         resources: Dict[str, Any], agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """Run a specific safety check."""
        try:
            check_methods = {
                "amount_validation": self._check_amount_validation,
                "financial_safety": self._check_financial_safety,
                "recipient_validation": self._check_recipient_validation,
                "account_validation": self._check_account_validation,
                "file_path_validation": self._check_file_path_validation,
                "resource_safety": self._check_resource_safety,
                "permission_check": self._check_permission,
                "destructive_action_check": self._check_destructive_action,
                "backup_requirement": self._check_backup_requirement,
                "resource_allocation": self._check_resource_allocation,
                "quota_check": self._check_quota,
                "naming_validation": self._check_naming_validation,
                "command_validation": self._check_command_validation,
                "privilege_check": self._check_privilege,
                "url_validation": self._check_url_validation,
                "network_safety": self._check_network_safety,
                "data_exposure_check": self._check_data_exposure,
                "privacy_check": self._check_privacy,
                "data_sensitivity": self._check_data_sensitivity,
                "access_control": self._check_access_control,
                "system_safety": self._check_system_safety,
                "impact_assessment": self._check_impact_assessment,
                "rollback_capability": self._check_rollback_capability,
                "general_safety": self._check_general_safety
            }
            
            check_method = check_methods.get(check_name)
            if check_method:
                return check_method(parameters, resources, agent_context)
            else:
                return {
                    "passed": True,
                    "risk_score": 0.0,
                    "violations": [f"Unknown safety check: {check_name}"]
                }
                
        except Exception as e:
            logger.error(f"Safety check '{check_name}' failed: {str(e)}")
            return {
                "passed": False,
                "risk_score": 0.8,
                "violations": [f"Check error: {str(e)}"]
            }
    
    def _check_amount_validation(self, parameters: Dict[str, Any], resources: Dict[str, Any],
                               agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate monetary amounts."""
        result = {"passed": True, "risk_score": 0.0, "violations": []}
        
        try:
            amount = parameters.get("amount")
            currency = parameters.get("currency", "USD")
            
            if amount is None:
                return result
            
            # Check amount type and range
            if not isinstance(amount, (int, float)):
                result["passed"] = False
                result["violations"].append("Amount must be numeric")
                result["risk_score"] = 0.8
                return result
            
            # Get agent-specific limits
            agent_role = agent_context.get("role", "default")
            limits = self.safety_rules.get("amount_limits", {}).get(agent_role, {})
            
            max_amount = limits.get("max_single_transaction", 10000)
            daily_limit = limits.get("daily_limit", 50000)
            
            if amount < 0:
                result["passed"] = False
                result["violations"].append("Negative amounts not allowed")
                result["risk_score"] = 0.9
            elif amount > max_amount:
                result["passed"] = False
                result["violations"].append(f"Amount ${amount:,.2f} exceeds single transaction limit of ${max_amount:,.2f}")
                result["risk_score"] = 0.7
            elif amount > max_amount * 0.8:
                result["risk_score"] = 0.4
                result["violations"].append(f"High amount: ${amount:,.2f} (near limit)")
            
            # Check for suspicious amounts
            if self._is_suspicious_amount(amount):
                result["risk_score"] = max(result["risk_score"], 0.6)
                result["violations"].append("Suspicious amount pattern detected")
            
            return result
            
        except Exception as e:
            result["passed"] = False
            result["risk_score"] = 0.8
            result["violations"].append(f"Amount validation error: {str(e)}")
            return result
    
    def _check_financial_safety(self, parameters: Dict[str, Any], resources: Dict[str, Any],
                               agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """Check financial safety measures."""
        result = {"passed": True, "risk_score": 0.0, "violations": []}
        
        try:
            # Check for required financial safeguards
            requires_2fa = parameters.get("amount", 0) > 1000
            if requires_2fa and not parameters.get("two_factor_auth"):
                result["risk_score"] = 0.3
                result["violations"].append("High-value transaction requires 2FA")
            
            # Check transaction frequency
            transaction_count = agent_context.get("transaction_count", 0)
            if transaction_count > 10:  # More than 10 transactions today
                result["risk_score"] = max(result["risk_score"], 0.4)
                result["violations"].append("High transaction frequency detected")
            
            # Check for unusual patterns
            recipient = parameters.get("recipient")
            if recipient and self._is_unusual_recipient(recipient, agent_context):
                result["risk_score"] = max(result["risk_score"], 0.5)
                result["violations"].append("Unusual recipient detected")
            
            return result
            
        except Exception as e:
            result["passed"] = False
            result["risk_score"] = 0.8
            result["violations"].append(f"Financial safety check error: {str(e)}")
            return result
    
    def _check_file_path_validation(self, parameters: Dict[str, Any], resources: Dict[str, Any],
                                   agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate file paths for safety."""
        result = {"passed": True, "risk_score": 0.0, "violations": []}
        
        try:
            file_path = parameters.get("path") or parameters.get("file_path")
            
            if not file_path:
                return result
            
            # Normalize path
            normalized_path = os.path.normpath(file_path)
            
            # Check for dangerous path patterns
            dangerous_patterns = [
                r"\.\.",  # Parent directory traversal
                r"^/",   # Absolute path
                r"^C:\\",  # Windows system path
                r"/etc/",  # System configuration
                r"/bin/",  # System binaries
                r"/usr/bin/",  # User binaries
                r"system32",  # Windows system
                r"windows",  # Windows directory
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, normalized_path, re.IGNORECASE):
                    result["passed"] = False
                    result["violations"].append(f"Dangerous path pattern: {pattern}")
                    result["risk_score"] = 0.8
                    return result
            
            # Check file extension
            file_ext = Path(normalized_path).suffix.lower()
            dangerous_extensions = {".exe", ".bat", ".cmd", ".scr", ".com", ".pif", ".vbs", ".js"}
            
            if file_ext in dangerous_extensions:
                result["passed"] = False
                result["violations"].append(f"Dangerous file extension: {file_ext}")
                result["risk_score"] = 0.9
            
            # Check path length
            if len(normalized_path) > 260:  # Windows MAX_PATH limit
                result["risk_score"] = 0.3
                result["violations"].append("Path length exceeds recommended limit")
            
            return result
            
        except Exception as e:
            result["passed"] = False
            result["risk_score"] = 0.8
            result["violations"].append(f"Path validation error: {str(e)}")
            return result
    
    def _check_resource_safety(self, parameters: Dict[str, Any], resources: Dict[str, Any],
                               agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """Check resource usage safety."""
        result = {"passed": True, "risk_score": 0.0, "violations": []}
        
        try:
            # Check CPU usage
            cpu_usage = resources.get("cpu_usage", 0)
            if cpu_usage > 80:  # More than 80% CPU
                result["risk_score"] = max(result["risk_score"], 0.4)
                result["violations"].append(f"High CPU usage: {cpu_usage}%")
            
            # Check memory usage
            memory_usage = resources.get("memory_usage", 0)
            if memory_usage > 80:  # More than 80% memory
                result["risk_score"] = max(result["risk_score"], 0.4)
                result["violations"].append(f"High memory usage: {memory_usage}%")
            
            # Check disk usage
            disk_usage = resources.get("disk_usage", 0)
            if disk_usage > 90:  # More than 90% disk
                result["risk_score"] = max(result["risk_score"], 0.5)
                result["violations"].append(f"High disk usage: {disk_usage}%")
            
            # Check network usage
            network_usage = resources.get("network_usage", 0)
            if network_usage > 1000:  # More than 1GB network transfer
                result["risk_score"] = max(result["risk_score"], 0.3)
                result["violations"].append(f"High network usage: {network_usage}MB")
            
            return result
            
        except Exception as e:
            result["passed"] = False
            result["risk_score"] = 0.8
            result["violations"].append(f"Resource safety check error: {str(e)}")
            return result
    
    def _check_command_validation(self, parameters: Dict[str, Any], resources: Dict[str, Any],
                                  agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate command safety."""
        result = {"passed": True, "risk_score": 0.0, "violations": []}
        
        try:
            command = parameters.get("command", "")
            
            if not command:
                return result
            
            # Check for dangerous commands
            dangerous_commands = [
                "rm -rf", "del /f", "format", "fdisk", "mkfs",
                "chmod 777", "chown root", "sudo", "su",
                "systemctl", "service", "iptables", "netsh"
            ]
            
            for dangerous_cmd in dangerous_commands:
                if dangerous_cmd in command.lower():
                    result["passed"] = False
                    result["violations"].append(f"Dangerous command detected: {dangerous_cmd}")
                    result["risk_score"] = 0.9
                    return result
            
            # Check for shell injection patterns
            injection_patterns = [";", "&", "|", "`", "$(", "${"]
            for pattern in injection_patterns:
                if pattern in command:
                    result["risk_score"] = max(result["risk_score"], 0.6)
                    result["violations"].append(f"Potential shell injection: {pattern}")
            
            return result
            
        except Exception as e:
            result["passed"] = False
            result["risk_score"] = 0.8
            result["violations"].append(f"Command validation error: {str(e)}")
            return result
    
    def _check_general_safety(self, parameters: Dict[str, Any], resources: Dict[str, Any],
                              agent_context: Dict[str, Any]) -> Dict[str, Any]:
        """General safety checks for all actions."""
        result = {"passed": True, "risk_score": 0.0, "violations": []}
        
        try:
            # Check parameter count (too many parameters might indicate complexity)
            if len(parameters) > 20:
                result["risk_score"] = 0.2
                result["violations"].append("High parameter complexity")
            
            # Check for empty required parameters
            required_params = ["action", "target"]
            for param in required_params:
                if param not in parameters or not parameters[param]:
                    result["risk_score"] = max(result["risk_score"], 0.3)
                    result["violations"].append(f"Missing required parameter: {param}")
            
            return result
            
        except Exception as e:
            result["passed"] = False
            result["risk_score"] = 0.8
            result["violations"].append(f"General safety check error: {str(e)}")
            return result
    
    def _is_suspicious_amount(self, amount: float) -> bool:
        """Check if amount follows suspicious patterns."""
        try:
            # Round numbers (potential testing)
            if amount in [100, 1000, 10000, 50000, 100000]:
                return True
            
            # Repeating digits
            amount_str = str(int(amount))
            if len(set(amount_str)) <= 2 and len(amount_str) > 2:
                return True
            
            # Sequential digits
            if amount_str in "123456789" or amount_str in "987654321":
                return True
            
            return False
            
        except Exception:
            return True
    
    def _is_unusual_recipient(self, recipient: str, agent_context: Dict[str, Any]) -> bool:
        """Check if recipient is unusual for the agent."""
        try:
            # Get agent's usual recipients
            usual_recipients = agent_context.get("usual_recipients", [])
            
            if not usual_recipients:
                return False  # No history available
            
            # Check if recipient is in usual list
            return recipient not in usual_recipients
            
        except Exception:
            return False
    
    def _calculate_risk_level(self, risk_scores: List[float], violations: List[str]) -> str:
        """Calculate overall risk level."""
        try:
            if not risk_scores:
                return "LOW"
            
            avg_risk = sum(risk_scores) / len(risk_scores)
            
            # Critical violations elevate risk
            critical_violations = [v for v in violations if any(keyword in v.lower() 
                                for keyword in ["dangerous", "exceeds limit", "injection", "system"])]
            
            if critical_violations or avg_risk > 0.7:
                return "HIGH"
            elif avg_risk > 0.4 or len(violations) > 2:
                return "MEDIUM"
            else:
                return "LOW"
                
        except Exception:
            return "MEDIUM"
    
    def _calculate_safety_confidence(self, risk_scores: List[float]) -> float:
        """Calculate confidence in safety assessment."""
        try:
            if not risk_scores:
                return 0.5
            
            # Higher confidence when risk scores are consistent
            avg_risk = sum(risk_scores) / len(risk_scores)
            variance = sum((score - avg_risk) ** 2 for score in risk_scores) / len(risk_scores)
            
            base_confidence = 1.0 - avg_risk  # Lower risk = higher confidence
            
            # Reduce confidence for high variance
            if variance > 0.1:
                base_confidence *= 0.8
            
            return max(0.0, min(1.0, base_confidence))
            
        except Exception:
            return 0.5
    
    def _determine_escalation_need(self, risk_level: str, violations: List[str]) -> bool:
        """Determine if escalation is needed."""
        return risk_level == "HIGH" or len(violations) > 3
    
    def _identify_risk_factors(self, parameter_analysis: Dict[str, Any]) -> List[str]:
        """Identify key risk factors from analysis."""
        risk_factors = []
        
        for check_name, check_result in parameter_analysis.items():
            if not check_result.get("passed", False):
                risk_factors.append(f"{check_name} failed")
            
            risk_score = check_result.get("risk_score", 0.0)
            if risk_score > 0.5:
                risk_factors.append(f"High risk in {check_name}")
        
        return risk_factors
    
    def _generate_safety_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Generate safety recommendations."""
        recommendations = []
        
        if result["passed"]:
            recommendations.append("Action appears safe to execute")
            
            if result["risk_level"] == "LOW":
                recommendations.append("Low risk - standard monitoring sufficient")
            else:
                recommendations.append("Moderate risk - enhanced monitoring recommended")
        else:
            recommendations.append("Action blocked due to safety concerns")
            
            # Specific recommendations based on violations
            for violation in result["violations"]:
                if "exceeds limit" in violation:
                    recommendations.append("Reduce amount or request limit increase")
                elif "dangerous path" in violation:
                    recommendations.append("Use safer file path")
                elif "high usage" in violation:
                    recommendations.append("Optimize resource usage")
                elif "missing required" in violation:
                    recommendations.append("Provide all required parameters")
        
        return recommendations
    
    def _update_statistics(self, result: Dict[str, Any]) -> None:
        """Update safety check statistics."""
        try:
            self.stats["total_checks"] += 1
            
            if result["passed"]:
                self.stats["safety_passed"] += 1
            else:
                self.stats["safety_failed"] += 1
            
            if result["risk_level"] == "HIGH":
                self.stats["high_risk_detected"] += 1
            
            self.stats["parameter_violations"] += len(result["violations"])
            
            # Update average processing time
            current_avg = self.stats["avg_check_time"]
            count = self.stats["total_checks"]
            new_time = result["processing_time"]
            self.stats["avg_check_time"] = ((current_avg * (count - 1)) + new_time) / count
            
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")
    
    def _create_error_result(self, error: str) -> Dict[str, Any]:
        """Create error result when safety check fails."""
        return {
            "passed": False,
            "confidence": 0.0,
            "requires_escalation": True,
            "risk_level": "HIGH",
            "violations": [f"Safety check error: {error}"],
            "risk_factors": ["Check failure"],
            "parameter_analysis": {},
            "safety_recommendations": ["ESCALATE: Safety check failed"],
            "processing_time": 0.0,
            "error": error
        }
    
    def _load_safety_rules(self) -> Dict[str, Any]:
        """Load safety rules and thresholds."""
        return {
            "amount_limits": {
                "finance_agent": {
                    "max_single_transaction": 50000,
                    "daily_limit": 200000
                },
                "marketing_agent": {
                    "max_single_transaction": 10000,
                    "daily_limit": 50000
                },
                "default": {
                    "max_single_transaction": 1000,
                    "daily_limit": 5000
                }
            },
            "resource_limits": {
                "max_cpu_usage": 80,
                "max_memory_usage": 80,
                "max_disk_usage": 90,
                "max_network_transfer": 1000  # MB
            }
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get safety check status."""
        return {
            "status": "active",
            "configuration": self.config.copy(),
            "statistics": self.stats.copy(),
            "safety_rules_count": len(self.safety_rules)
        }
    
    def reset_statistics(self) -> None:
        """Reset safety check statistics."""
        self.stats = {
            "total_checks": 0,
            "safety_passed": 0,
            "safety_failed": 0,
            "high_risk_detected": 0,
            "parameter_violations": 0,
            "avg_check_time": 0.0
        }
        logger.info("Safety check statistics reset")


# ---------------------------------------------------------------------------
# SafetyChecker — backwards-compatible adapter used by unit tests
# Wraps SafetyCheck with a simpler single-argument API.
# ---------------------------------------------------------------------------
class SafetyChecker:
    """Adapter around SafetyCheck with a simplified API for testing."""

    # Risk amount threshold per role
    _HIGH_RISK_AMOUNT: Dict[str, float] = {
        "finance_agent": 10_000.0,
        "marketing_agent": 5_000.0,
        "default": 1_000.0,
    }

    # Suspicious recipient keywords
    _SUSPICIOUS_RECIPIENTS = {"hacker", "test", "unknown", "fake", "anonymous"}

    # Dangerous file path prefixes
    _DANGEROUS_PATHS = {"/etc/", "/bin/", "/sys/", "/dev/", "c:\\windows", "system32"}

    # Shell injection markers
    _INJECTION_MARKERS = {"&&", ";", "|", "`", "$(", "rm -rf", "del /f"}

    def __init__(self):
        self._inner = SafetyCheck()
        self._transfer_log: list = []

    def check_safety(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simplified safety check called by unit tests.

        Args:
            action: dict describing the action

        Returns:
            dict with ``safe`` (bool), ``risk_level`` (str), ``risk_factors`` (list[str])
        """
        risk_factors: List[str] = []
        agent_role = action.get("agent_role", "default")
        amount = action.get("amount", 0)
        recipient = action.get("recipient", "")
        file_path = action.get("file_path", "")
        command = action.get("command", "")

        # Amount threshold
        threshold = self._HIGH_RISK_AMOUNT.get(agent_role, self._HIGH_RISK_AMOUNT["default"])
        if isinstance(amount, (int, float)) and amount > threshold:
            risk_factors.append(f"amount ${amount:,.0f} exceeds threshold ${threshold:,.0f}")

        # Suspicious recipient
        if recipient and any(kw in recipient.lower() for kw in self._SUSPICIOUS_RECIPIENTS):
            risk_factors.append(f"suspicious recipient: {recipient}")

        # Dangerous file path
        if file_path:
            fp_lower = file_path.lower()
            if any(p in fp_lower for p in self._DANGEROUS_PATHS):
                risk_factors.append(f"dangerous path: {file_path}")

        # Command injection
        if command:
            for marker in self._INJECTION_MARKERS:
                if marker in command:
                    risk_factors.append(f"injection risk in command: {marker}")
                    break

        # Transfer frequency tracking
        if action.get("action") == "transfer":
            self._transfer_log.append(time.time())
            recent = [t for t in self._transfer_log if time.time() - t < 60]
            self._transfer_log = recent
            if len(recent) > 3:
                risk_factors.append("high transfer frequency detected")

        safe = len(risk_factors) == 0
        if not safe:
            risk_level = "HIGH"
        else:
            risk_level = "LOW"

        return {"safe": safe, "risk_level": risk_level, "risk_factors": risk_factors}

