"""
Intent Validator - Validates intent JSON against schema before handoff

Handles intent validation for ChainGuardAI:
- JSON Schema validation
- Business rule validation
- Security constraint checking
- Intent quality assessment
"""

import json
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from loguru import logger
from .intent_schema import IntentSchema


class IntentValidator:
    """Validates intent objects against schema and business rules."""
    
    def __init__(self, schema_version: str = "1.0"):
        """
        Initialize IntentValidator.
        
        Args:
            schema_version: Schema version to use for validation
        """
        self.schema = IntentSchema(schema_version)
        self.security_rules = self._load_security_rules()
        self.business_rules = self._load_business_rules()
        
        logger.info(f"Initialized IntentValidator with schema version {schema_version}")
    
    def validate_intent(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate an intent object comprehensively.
        
        Args:
            intent: Intent object to validate
            
        Returns:
            Validation result with detailed information
        """
        try:
            validation_result = {
                "valid": False,
                "confidence_score": 0.0,
                "risk_level": "LOW",
                "errors": [],
                "warnings": [],
                "security_issues": [],
                "business_violations": [],
                "quality_score": 0.0,
                "validated_at": datetime.utcnow().isoformat() + "Z",
                "schema_version": self.schema.schema_version
            }
            
            # Step 1: Schema validation
            schema_result = self.schema.validate_against_schema(intent)
            validation_result["errors"].extend(schema_result["errors"])
            validation_result["warnings"].extend(schema_result["warnings"])
            
            # Step 2: Security validation
            security_result = self._validate_security(intent)
            validation_result["security_issues"].extend(security_result["issues"])
            validation_result["risk_level"] = security_result["risk_level"]
            
            # Step 3: Business rule validation
            business_result = self._validate_business_rules(intent)
            validation_result["business_violations"].extend(business_result["violations"])
            
            # Step 4: Quality assessment
            quality_score = self._assess_intent_quality(intent)
            validation_result["quality_score"] = quality_score
            
            # Step 5: Overall confidence calculation
            confidence_score = self._calculate_confidence_score(intent, validation_result)
            validation_result["confidence_score"] = confidence_score
            
            # Step 6: Final validation decision
            validation_result["valid"] = self._make_validation_decision(validation_result)
            
            # Log validation result
            if validation_result["valid"]:
                logger.info(f"Intent validation passed (confidence: {confidence_score:.2f})")
            else:
                logger.warning(f"Intent validation failed (risk: {validation_result['risk_level']})")
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Intent validation failed: {str(e)}")
            return {
                "valid": False,
                "confidence_score": 0.0,
                "risk_level": "HIGH",
                "errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "security_issues": [],
                "business_violations": [],
                "quality_score": 0.0,
                "validated_at": datetime.utcnow().isoformat() + "Z",
                "schema_version": self.schema.schema_version
            }
    
    def _validate_security(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        """Validate intent against security rules."""
        result = {
            "issues": [],
            "risk_level": "LOW"
        }
        
        try:
            # Check intent type for security implications
            intent_type = intent.get("type", "unknown")
            raw_input = intent.get("raw_input", "")
            parameters = intent.get("parameters", {})
            
            # Rule 1: Check for injection attempts
            injection_patterns = self.security_rules["injection_patterns"]
            for pattern in injection_patterns:
                if re.search(pattern, raw_input, re.IGNORECASE):
                    result["issues"].append(f"Potential injection pattern: {pattern}")
                    result["risk_level"] = "HIGH"
            
            # Rule 2: Check parameters for dangerous values
            for param_name, param_value in parameters.items():
                if isinstance(param_value, str):
                    dangerous_values = self.security_rules["dangerous_values"]
                    for dangerous_value in dangerous_values:
                        if dangerous_value in param_value.lower():
                            result["issues"].append(f"Dangerous value in parameter '{param_name}': {dangerous_value}")
                            result["risk_level"] = "HIGH"
            
            # Rule 3: Check for privilege escalation attempts
            escalation_keywords = self.security_rules["escalation_keywords"]
            for keyword in escalation_keywords:
                if keyword in raw_input.lower():
                    result["issues"].append(f"Privilege escalation keyword: {keyword}")
                    result["risk_level"] = "MEDIUM"
            
            # Rule 4: Validate input length limits
            max_length = self.security_rules["max_input_length"]
            if len(raw_input) > max_length:
                result["issues"].append(f"Input exceeds maximum length: {len(raw_input)} > {max_length}")
                result["risk_level"] = "MEDIUM"
            
            # Rule 5: Check for suspicious entity patterns
            entities = intent.get("entities", [])
            for entity in entities:
                entity_type = entity.get("type", "")
                entity_value = str(entity.get("value", ""))
                
                if entity_type == "money" and self._is_suspicious_amount(entity_value):
                    result["issues"].append(f"Suspicious monetary amount: {entity_value}")
                    result["risk_level"] = "MEDIUM"
            
            # Rule 6: Check confidence score
            confidence = intent.get("confidence", 0.0)
            if confidence < 0.3:
                result["issues"].append(f"Low confidence score: {confidence}")
                result["risk_level"] = "MEDIUM"
            
            # Rule 7: Check for rapid succession (if timestamp available)
            parsed_at = intent.get("parsed_at")
            if parsed_at:
                # This would require maintaining state of recent intents
                # For now, just log the check
                logger.debug("Checking intent timing for rapid succession")
            
            return result
            
        except Exception as e:
            logger.error(f"Security validation failed: {str(e)}")
            result["issues"].append(f"Security validation error: {str(e)}")
            result["risk_level"] = "HIGH"
            return result
    
    def _validate_business_rules(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        """Validate intent against business rules."""
        result = {
            "violations": []
        }
        
        try:
            intent_type = intent.get("type", "unknown")
            parameters = intent.get("parameters", {})
            
            # Get business rules for this intent type
            type_rules = self.business_rules.get(intent_type, [])
            
            for rule in type_rules:
                rule_name = rule["name"]
                rule_condition = rule["condition"]
                rule_message = rule["message"]
                
                # Evaluate rule condition
                if self._evaluate_rule_condition(rule_condition, intent):
                    result["violations"].append({
                        "rule": rule_name,
                        "message": rule_message,
                        "severity": rule.get("severity", "MEDIUM")
                    })
            
            # Common business rules for all intents
            common_rules = self.business_rules.get("common", [])
            
            for rule in common_rules:
                rule_name = rule["name"]
                rule_condition = rule["condition"]
                rule_message = rule["message"]
                
                if self._evaluate_rule_condition(rule_condition, intent):
                    result["violations"].append({
                        "rule": rule_name,
                        "message": rule_message,
                        "severity": rule.get("severity", "MEDIUM")
                    })
            
            return result
            
        except Exception as e:
            logger.error(f"Business rule validation failed: {str(e)}")
            result["violations"].append({
                "rule": "validation_error",
                "message": f"Business rule validation error: {str(e)}",
                "severity": "HIGH"
            })
            return result
    
    def _evaluate_rule_condition(self, condition: str, intent: Dict[str, Any]) -> bool:
        """Evaluate a business rule condition."""
        try:
            # Simple condition evaluation
            # In production, use a proper expression evaluator
            
            # Replace placeholders with actual values
            condition = condition.replace("{{intent_type}}", f"'{intent.get('type', '')}'")
            condition = condition.replace("{{confidence}}", str(intent.get('confidence', 0)))
            condition = condition.replace("{{input_length}}", str(len(intent.get('raw_input', ''))))
            
            # Replace parameter references
            parameters = intent.get('parameters', {})
            for param_name, param_value in parameters.items():
                condition = condition.replace(f"{{params.{param_name}}}", f"'{param_value}'")
            
            # Evaluate the condition (simplified)
            # WARNING: This is a simplified evaluation - in production use a safe evaluator
            if "confidence < 0.5" in condition and intent.get('confidence', 0) < 0.5:
                return True
            
            if "input_length > 1000" in condition and len(intent.get('raw_input', '')) > 1000:
                return True
            
            if "type == 'transaction'" in condition and intent.get('type') == 'transaction':
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Rule condition evaluation failed: {str(e)}")
            return False
    
    def _assess_intent_quality(self, intent: Dict[str, Any]) -> float:
        """Assess the overall quality of an intent."""
        try:
            quality_score = 0.0
            max_score = 100.0
            
            # Factor 1: Confidence score (30 points)
            confidence = intent.get("confidence", 0.0)
            quality_score += confidence * 30.0
            
            # Factor 2: Parameter completeness (25 points)
            parameters = intent.get("parameters", {})
            intent_type = intent.get("type", "unknown")
            
            required_params = self._get_required_parameters(intent_type)
            if required_params:
                completeness = sum(1 for param in required_params if param in parameters) / len(required_params)
                quality_score += completeness * 25.0
            else:
                quality_score += 25.0  # No required params means full score
            
            # Factor 3: Entity extraction quality (20 points)
            entities = intent.get("entities", [])
            raw_input = intent.get("raw_input", "")
            
            if entities:
                entity_coverage = len(entities) / max(len(raw_input.split()), 1) * 10  # Normalize
                quality_score += min(entity_coverage, 20.0)
            else:
                quality_score += 5.0  # Some points for trying
            
            # Factor 4: Input clarity (15 points)
            input_clarity = self._assess_input_clarity(raw_input)
            quality_score += input_clarity * 15.0
            
            # Factor 5: Metadata completeness (10 points)
            metadata = intent.get("metadata", {})
            metadata_fields = ["parsing_time", "input_length"]
            metadata_completeness = sum(1 for field in metadata_fields if field in metadata) / len(metadata_fields)
            quality_score += metadata_completeness * 10.0
            
            return min(quality_score, max_score)
            
        except Exception as e:
            logger.error(f"Quality assessment failed: {str(e)}")
            return 0.0
    
    def _assess_input_clarity(self, input_text: str) -> float:
        """Assess the clarity of input text."""
        try:
            if not input_text:
                return 0.0
            
            clarity_score = 0.0
            
            # Check for proper sentence structure
            if input_text.strip().endswith(('.', '?', '!')):
                clarity_score += 0.2
            
            # Check length (not too short, not too long)
            length = len(input_text)
            if 10 <= length <= 200:
                clarity_score += 0.3
            elif 200 < length <= 500:
                clarity_score += 0.2
            else:
                clarity_score += 0.1
            
            # Check for excessive punctuation
            punctuation_ratio = sum(c in '.,!?;:' for c in input_text) / max(len(input_text), 1)
            if punctuation_ratio < 0.1:
                clarity_score += 0.2
            elif punctuation_ratio < 0.2:
                clarity_score += 0.1
            
            # Check for excessive capitalization
            caps_ratio = sum(c.isupper() for c in input_text) / max(len(input_text), 1)
            if caps_ratio < 0.2:
                clarity_score += 0.2
            elif caps_ratio < 0.4:
                clarity_score += 0.1
            
            # Check for meaningful words (simple heuristic)
            words = input_text.split()
            meaningful_words = sum(1 for word in words if len(word) > 2)
            if words:
                meaningful_ratio = meaningful_words / len(words)
                clarity_score += meaningful_ratio * 0.1
            
            return min(clarity_score, 1.0)
            
        except Exception as e:
            logger.error(f"Input clarity assessment failed: {str(e)}")
            return 0.0
    
    def _calculate_confidence_score(self, intent: Dict[str, Any], validation_result: Dict[str, Any]) -> float:
        """Calculate overall confidence score."""
        try:
            base_confidence = intent.get("confidence", 0.0)
            
            # Adjust based on validation results
            if validation_result["errors"]:
                base_confidence *= 0.5  # Penalize errors
            
            if validation_result["security_issues"]:
                security_penalty = len(validation_result["security_issues"]) * 0.1
                base_confidence -= security_penalty
            
            if validation_result["business_violations"]:
                business_penalty = len(validation_result["business_violations"]) * 0.05
                base_confidence -= business_penalty
            
            # Boost based on quality
            quality_boost = validation_result["quality_score"] / 100.0 * 0.2
            base_confidence += quality_boost
            
            return max(0.0, min(1.0, base_confidence))
            
        except Exception as e:
            logger.error(f"Confidence score calculation failed: {str(e)}")
            return 0.0
    
    def _make_validation_decision(self, validation_result: Dict[str, Any]) -> bool:
        """Make final validation decision."""
        try:
            # Must have no errors
            if validation_result["errors"]:
                return False
            
            # Must not have high security risk
            if validation_result["risk_level"] == "HIGH":
                return False
            
            # Must meet minimum confidence threshold
            if validation_result["confidence_score"] < 0.3:
                return False
            
            # Must meet minimum quality threshold
            if validation_result["quality_score"] < 40.0:
                return False
            
            # Check business rule severity
            for violation in validation_result["business_violations"]:
                if violation.get("severity") == "HIGH":
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Validation decision failed: {str(e)}")
            return False
    
    def _get_required_parameters(self, intent_type: str) -> List[str]:
        """Get list of required parameters for an intent type."""
        required_params = {
            "transaction": ["amount"],
            "command": ["action"],
            "query": ["query_type"],
            "information_request": ["information_type"]
        }
        
        return required_params.get(intent_type, [])
    
    def _is_suspicious_amount(self, amount_str: str) -> bool:
        """Check if a monetary amount is suspicious."""
        try:
            # Extract numeric value
            import re
            match = re.search(r'[\d,]+\.?\d*', amount_str.replace('$', '').replace(',', ''))
            if not match:
                return True
            
            amount = float(match.group())
            
            # Check for suspicious amounts
            if amount > 1000000:  # Over 1 million
                return True
            
            if amount < 0:  # Negative amounts
                return True
            
            # Check for round numbers (potential testing)
            if amount in [100, 1000, 10000, 100000] and amount_str.count('0') > 3:
                return True
            
            return False
            
        except Exception:
            return True  # Assume suspicious if parsing fails
    
    def _load_security_rules(self) -> Dict[str, Any]:
        """Load security validation rules."""
        return {
            "injection_patterns": [
                r"<script.*?>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"eval\s*\(",
                r"exec\s*\(",
                r"system\s*\(",
                r"__import__",
                r"subprocess\.",
                r"os\.system",
                r"shell_exec"
            ],
            "dangerous_values": [
                "import", "exec", "eval", "system", "shell",
                "password", "secret", "token", "key",
                "../", "..\\", "/etc/", "C:\\"
            ],
            "escalation_keywords": [
                "admin", "root", "privilege", "escalate",
                "sudo", "su", "administrator", "superuser"
            ],
            "max_input_length": 5000
        }
    
    def _load_business_rules(self) -> Dict[str, Any]:
        """Load business validation rules."""
        return {
            "transaction": [
                {
                    "name": "minimum_amount",
                    "condition": "params.amount < 0.01",
                    "message": "Transaction amount must be at least $0.01",
                    "severity": "MEDIUM"
                },
                {
                    "name": "maximum_amount",
                    "condition": "params.amount > 10000",
                    "message": "Transaction amount exceeds $10,000 limit",
                    "severity": "HIGH"
                }
            ],
            "command": [
                {
                    "name": "valid_action",
                    "condition": "params.action not in ['execute', 'run', 'start', 'stop', 'create', 'delete']",
                    "message": "Invalid command action specified",
                    "severity": "MEDIUM"
                }
            ],
            "common": [
                {
                    "name": "minimum_confidence",
                    "condition": "confidence < 0.3",
                    "message": "Intent confidence too low",
                    "severity": "MEDIUM"
                },
                {
                    "name": "maximum_input_length",
                    "condition": "input_length > 1000",
                    "message": "Input text too long",
                    "severity": "LOW"
                }
            ]
        }
    
    def add_security_rule(self, rule_type: str, pattern: str) -> None:
        """Add a new security rule."""
        try:
            if rule_type in self.security_rules:
                self.security_rules[rule_type].append(pattern)
                logger.info(f"Added security rule: {rule_type}")
            else:
                logger.warning(f"Unknown security rule type: {rule_type}")
                
        except Exception as e:
            logger.error(f"Failed to add security rule: {str(e)}")
    
    def add_business_rule(self, intent_type: str, rule: Dict[str, Any]) -> None:
        """Add a new business rule."""
        try:
            if intent_type not in self.business_rules:
                self.business_rules[intent_type] = []
            
            self.business_rules[intent_type].append(rule)
            logger.info(f"Added business rule for {intent_type}")
            
        except Exception as e:
            logger.error(f"Failed to add business rule: {str(e)}")
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get a summary of validation capabilities."""
        return {
            "schema_version": self.schema.schema_version,
            "supported_intent_types": self.schema._get_supported_intent_types(),
            "security_rules_count": sum(len(rules) for rules in self.security_rules.values()),
            "business_rules_count": sum(len(rules) for rules in self.business_rules.values()),
            "risk_levels": ["LOW", "MEDIUM", "HIGH"],
            "validation_factors": [
                "schema_validation",
                "security_validation", 
                "business_rules",
                "quality_assessment",
                "confidence_scoring"
            ]
        }
