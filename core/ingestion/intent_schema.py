"""
Intent Schema - JSON Schema definition for valid intent objects

Defines the schema for structured intent objects in ChainGuardAI:
- JSON Schema validation
- Intent structure definition
- Parameter type specifications
- Schema versioning
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from loguru import logger


class IntentSchema:
    """Defines and manages JSON schemas for intent validation."""
    
    def __init__(self, schema_version: str = "1.0"):
        """
        Initialize IntentSchema.
        
        Args:
            schema_version: Version of the schema to use
        """
        self.schema_version = schema_version
        self.schemas = self._load_schemas()
        self.current_schema = self.schemas.get(schema_version)
        
        if not self.current_schema:
            raise ValueError(f"Schema version {schema_version} not found")
        
        logger.info(f"Initialized IntentSchema with version {schema_version}")
    
    def get_schema(self) -> Dict[str, Any]:
        """Get the current intent schema."""
        return self.current_schema
    
    def validate_against_schema(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate an intent object against the schema.
        
        Args:
            intent: Intent object to validate
            
        Returns:
            Validation result with errors if any
        """
        try:
            errors = []
            warnings = []
            
            # Basic structure validation
            errors.extend(self._validate_basic_structure(intent))
            
            # Type-specific validation
            intent_type = intent.get("type", "unknown")
            errors.extend(self._validate_intent_type(intent, intent_type))
            
            # Parameter validation
            errors.extend(self._validate_parameters(intent, intent_type))
            
            # Metadata validation
            warnings.extend(self._validate_metadata(intent))
            
            # Entity validation
            errors.extend(self._validate_entities(intent))
            
            is_valid = len(errors) == 0
            
            result = {
                "valid": is_valid,
                "errors": errors,
                "warnings": warnings,
                "schema_version": self.schema_version,
                "validated_at": datetime.utcnow().isoformat() + "Z"
            }
            
            if is_valid:
                logger.debug("Intent validation passed")
            else:
                logger.warning(f"Intent validation failed with {len(errors)} errors")
            
            return result
            
        except Exception as e:
            logger.error(f"Schema validation failed: {str(e)}")
            return {
                "valid": False,
                "errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "schema_version": self.schema_version,
                "validated_at": datetime.utcnow().isoformat() + "Z"
            }
    
    def _validate_basic_structure(self, intent: Dict[str, Any]) -> List[str]:
        """Validate basic intent structure."""
        errors = []
        
        required_fields = ["id", "type", "confidence", "raw_input", "parsed_at", "parameters", "entities"]
        
        for field in required_fields:
            if field not in intent:
                errors.append(f"Missing required field: {field}")
        
        # Validate field types
        if "id" in intent and not isinstance(intent["id"], str):
            errors.append("Field 'id' must be a string")
        
        if "type" in intent and not isinstance(intent["type"], str):
            errors.append("Field 'type' must be a string")
        
        if "confidence" in intent and not isinstance(intent["confidence"], (int, float)):
            errors.append("Field 'confidence' must be a number")
        
        if "raw_input" in intent and not isinstance(intent["raw_input"], str):
            errors.append("Field 'raw_input' must be a string")
        
        if "parsed_at" in intent and not isinstance(intent["parsed_at"], str):
            errors.append("Field 'parsed_at' must be a string")
        
        if "parameters" in intent and not isinstance(intent["parameters"], dict):
            errors.append("Field 'parameters' must be a dictionary")
        
        if "entities" in intent and not isinstance(intent["entities"], list):
            errors.append("Field 'entities' must be a list")
        
        # Validate confidence range
        if "confidence" in intent:
            confidence = intent["confidence"]
            if not (0.0 <= confidence <= 1.0):
                errors.append("Field 'confidence' must be between 0.0 and 1.0")
        
        return errors
    
    def _validate_intent_type(self, intent: Dict[str, Any], intent_type: str) -> List[str]:
        """Validate intent type specific requirements."""
        errors = []
        
        # Check if intent type is supported
        supported_types = self._get_supported_intent_types()
        if intent_type not in supported_types:
            errors.append(f"Unsupported intent type: {intent_type}")
        
        # Type-specific validation
        type_requirements = self._get_type_requirements(intent_type)
        
        for requirement in type_requirements:
            field = requirement["field"]
            required = requirement.get("required", False)
            field_type = requirement.get("type", "any")
            
            if required and field not in intent.get("parameters", {}):
                errors.append(f"Required parameter missing for {intent_type}: {field}")
            
            if field in intent.get("parameters", {}):
                value = intent["parameters"][field]
                if not self._validate_field_type(value, field_type):
                    errors.append(f"Parameter '{field}' must be of type {field_type}")
        
        return errors
    
    def _validate_parameters(self, intent: Dict[str, Any], intent_type: str) -> List[str]:
        """Validate intent parameters."""
        errors = []
        parameters = intent.get("parameters", {})
        
        # Check for dangerous parameters
        dangerous_patterns = [
            "import", "exec", "eval", "open", "file",
            "__", "subprocess", "os.", "sys."
        ]
        
        for param_name, param_value in parameters.items():
            if isinstance(param_value, str):
                for pattern in dangerous_patterns:
                    if pattern in param_value.lower():
                        errors.append(f"Dangerous pattern in parameter '{param_name}': {pattern}")
        
        # Validate parameter values
        for param_name, param_value in parameters.items():
            validation_errors = self._validate_parameter_value(param_name, param_value, intent_type)
            errors.extend(validation_errors)
        
        return errors
    
    def _validate_parameter_value(self, param_name: str, param_value: Any, intent_type: str) -> List[str]:
        """Validate individual parameter value."""
        errors = []
        
        # Length validation for strings
        if isinstance(param_value, str):
            if len(param_value) > 1000:
                errors.append(f"Parameter '{param_name}' too long: {len(param_value)} chars")
        
        # Numeric validation
        if isinstance(param_value, (int, float)):
            if param_value < 0 and param_name in ["amount", "quantity", "count"]:
                errors.append(f"Parameter '{param_name}' should be positive")
            
            if param_name == "confidence" and not (0.0 <= param_value <= 1.0):
                errors.append(f"Parameter '{param_name}' must be between 0.0 and 1.0")
        
        # List validation
        if isinstance(param_value, list):
            if len(param_value) > 100:
                errors.append(f"Parameter '{param_name}' list too long: {len(param_value)} items")
        
        return errors
    
    def _validate_metadata(self, intent: Dict[str, Any]) -> List[str]:
        """Validate intent metadata."""
        warnings = []
        metadata = intent.get("metadata", {})
        
        # Check for missing metadata
        if not metadata:
            warnings.append("No metadata provided")
        
        # Validate parsing time
        if "parsing_time" in metadata:
            parsing_time = metadata["parsing_time"]
            if not isinstance(parsing_time, (int, float)):
                warnings.append("Parsing time must be a number")
            elif parsing_time > 10.0:
                warnings.append(f"Parsing took too long: {parsing_time}s")
        
        # Validate input length
        if "input_length" in metadata:
            input_length = metadata["input_length"]
            if not isinstance(input_length, int):
                warnings.append("Input length must be an integer")
            elif input_length > 5000:
                warnings.append(f"Input very long: {input_length} chars")
        
        return warnings
    
    def _validate_entities(self, intent: Dict[str, Any]) -> List[str]:
        """Validate intent entities."""
        errors = []
        entities = intent.get("entities", [])
        
        for i, entity in enumerate(entities):
            if not isinstance(entity, dict):
                errors.append(f"Entity {i} must be a dictionary")
                continue
            
            # Required entity fields
            required_entity_fields = ["type", "value"]
            for field in required_entity_fields:
                if field not in entity:
                    errors.append(f"Entity {i} missing required field: {field}")
            
            # Validate entity types
            if "type" in entity:
                entity_type = entity["type"]
                supported_entity_types = self._get_supported_entity_types()
                if entity_type not in supported_entity_types:
                    errors.append(f"Unsupported entity type: {entity_type}")
            
            # Validate position fields
            if "start" in entity and "end" in entity:
                start = entity["start"]
                end = entity["end"]
                if not (isinstance(start, int) and isinstance(end, int)):
                    errors.append(f"Entity {i} position fields must be integers")
                elif start >= end:
                    errors.append(f"Entity {i} start position must be less than end")
        
        return errors
    
    def _validate_field_type(self, value: Any, expected_type: str) -> bool:
        """Validate field type."""
        type_mapping = {
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "array": list,
            "object": dict,
            "any": object
        }
        
        expected_python_type = type_mapping.get(expected_type, object)
        return isinstance(value, expected_python_type)
    
    def _get_supported_intent_types(self) -> List[str]:
        """Get list of supported intent types."""
        return [
            "query", "command", "transaction", "information_request",
            "greeting", "farewell", "error", "unknown"
        ]
    
    def _get_supported_entity_types(self) -> List[str]:
        """Get list of supported entity types."""
        return [
            "money", "phone", "address", "company", "time",
            "date", "email", "url", "person", "location"
        ]
    
    def _get_type_requirements(self, intent_type: str) -> List[Dict[str, Any]]:
        """Get type-specific parameter requirements."""
        requirements = {
            "transaction": [
                {"field": "amount", "required": True, "type": "number"},
                {"field": "recipient", "required": False, "type": "string"},
                {"field": "currency", "required": False, "type": "string"}
            ],
            "command": [
                {"field": "action", "required": True, "type": "string"},
                {"field": "target", "required": False, "type": "string"}
            ],
            "query": [
                {"field": "query_type", "required": True, "type": "string"},
                {"field": "subject", "required": False, "type": "string"}
            ],
            "information_request": [
                {"field": "information_type", "required": True, "type": "string"},
                {"field": "source", "required": False, "type": "string"}
            ]
        }
        
        return requirements.get(intent_type, [])
    
    def _load_schemas(self) -> Dict[str, Dict[str, Any]]:
        """Load all schema versions."""
        base_schema = {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "type": {"type": "string"},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "raw_input": {"type": "string"},
                "parsed_at": {"type": "string", "format": "date-time"},
                "parameters": {"type": "object"},
                "entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},
                            "value": {},
                            "start": {"type": "integer"},
                            "end": {"type": "integer"}
                        },
                        "required": ["type", "value"]
                    }
                },
                "context": {"type": "object"},
                "metadata": {"type": "object"}
            },
            "required": ["id", "type", "confidence", "raw_input", "parsed_at", "parameters", "entities"]
        }
        
        return {
            "1.0": base_schema,
            "1.1": base_schema  # Future versions can extend this
        }
    
    def create_intent_template(self, intent_type: str) -> Dict[str, Any]:
        """Create a template intent object for a given type."""
        template = {
            "id": f"intent_template_{int(datetime.utcnow().timestamp() * 1000)}",
            "type": intent_type,
            "confidence": 0.0,
            "raw_input": "",
            "parsed_at": datetime.utcnow().isoformat() + "Z",
            "parameters": {},
            "entities": [],
            "context": {},
            "metadata": {
                "input_length": 0,
                "parsing_time": 0.0,
                "template": True
            }
        }
        
        # Add type-specific default parameters
        requirements = self._get_type_requirements(intent_type)
        for req in requirements:
            field = req["field"]
            field_type = req.get("type", "string")
            
            default_value = self._get_default_value(field_type)
            if default_value is not None:
                template["parameters"][field] = default_value
        
        return template
    
    def _get_default_value(self, field_type: str) -> Any:
        """Get default value for a field type."""
        defaults = {
            "string": "",
            "number": 0,
            "integer": 0,
            "boolean": False,
            "array": [],
            "object": {},
            "any": None
        }
        
        return defaults.get(field_type)
    
    def upgrade_schema(self, intent: Dict[str, Any], from_version: str, to_version: str) -> Dict[str, Any]:
        """Upgrade an intent from one schema version to another."""
        try:
            if from_version == to_version:
                return intent
            
            # Apply version-specific upgrades
            upgraded_intent = intent.copy()
            
            # Example upgrade from 1.0 to 1.1
            if from_version == "1.0" and to_version == "1.1":
                # Add new metadata fields
                if "metadata" not in upgraded_intent:
                    upgraded_intent["metadata"] = {}
                
                upgraded_intent["metadata"]["schema_version"] = to_version
                upgraded_intent["metadata"]["upgraded_at"] = datetime.utcnow().isoformat() + "Z"
            
            logger.info(f"Upgraded intent from {from_version} to {to_version}")
            return upgraded_intent
            
        except Exception as e:
            logger.error(f"Schema upgrade failed: {str(e)}")
            return intent
    
    def export_schema(self, file_path: str) -> bool:
        """Export the current schema to a file."""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.current_schema, f, indent=2)
            
            logger.info(f"Exported schema to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export schema: {str(e)}")
            return False
    
    def import_schema(self, file_path: str, version: str) -> bool:
        """Import a schema from a file."""
        try:
            with open(file_path, 'r') as f:
                schema = json.load(f)
            
            self.schemas[version] = schema
            logger.info(f"Imported schema version {version} from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import schema: {str(e)}")
            return False
