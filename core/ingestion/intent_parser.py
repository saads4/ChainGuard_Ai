"""
Intent Parser - Converts raw text to structured JSON intent object

Handles intent parsing for ChainGuardAI:
- Raw text to structured intent conversion
- Intent type classification
- Parameter extraction
- Context-aware parsing
"""

import re
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from loguru import logger


class IntentParser:
    """Parses raw input into structured intent objects."""
    
    def __init__(self):
        """Initialize IntentParser."""
        self.intent_patterns = self._load_intent_patterns()
        self.parameter_extractors = self._load_parameter_extractors()
        
        logger.info("Initialized IntentParser")
    
    def parse_intent(self, sanitized_input: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Parse sanitized input into a structured intent object.
        
        Args:
            sanitized_input: Sanitized input string
            context: Additional context for parsing
            
        Returns:
            Structured intent object
        """
        try:
            start_time = time.time()
            
            # Initialize intent structure
            intent = {
                "id": f"intent_{int(time.time() * 1000)}",
                "type": "unknown",
                "confidence": 0.0,
                "raw_input": sanitized_input,
                "parsed_at": datetime.utcnow().isoformat() + "Z",
                "parameters": {},
                "entities": [],
                "context": context or {},
                "metadata": {
                    "input_length": len(sanitized_input),
                    "parsing_time": 0.0
                }
            }
            
            # Detect intent type
            intent_type, confidence = self._detect_intent_type(sanitized_input, context)
            intent["type"] = intent_type
            intent["confidence"] = confidence
            
            # Extract parameters
            parameters = self._extract_parameters(sanitized_input, intent_type, context)
            intent["parameters"] = parameters
            
            # Extract entities
            entities = self._extract_entities(sanitized_input)
            intent["entities"] = entities
            
            # Add parsing time
            intent["metadata"]["parsing_time"] = time.time() - start_time
            
            logger.info(f"Parsed intent: {intent_type} (confidence: {confidence:.2f})")
            return intent
            
        except Exception as e:
            logger.error(f"Failed to parse intent: {str(e)}")
            return self._create_error_intent(sanitized_input, str(e))
    
    def _detect_intent_type(self, input_text: str, context: Optional[Dict[str, Any]]) -> Tuple[str, float]:
        """Detect the type of intent from input text."""
        try:
            # Normalize input
            normalized_text = input_text.lower().strip()
            
            # Check each intent pattern
            best_match = ("unknown", 0.0)
            
            for intent_type, patterns in self.intent_patterns.items():
                max_confidence = 0.0
                
                for pattern in patterns:
                    confidence = self._calculate_pattern_match(normalized_text, pattern)
                    if confidence > max_confidence:
                        max_confidence = confidence
                
                if max_confidence > best_match[1]:
                    best_match = (intent_type, max_confidence)
            
            # Consider context if provided
            if context and best_match[1] < 0.7:
                context_boost = self._get_context_boost(normalized_text, context)
                if context_boost:
                    boosted_confidence = min(best_match[1] + context_boost, 1.0)
                    best_match = (best_match[0], boosted_confidence)
            
            return best_match
            
        except Exception as e:
            logger.error(f"Intent type detection failed: {str(e)}")
            return ("unknown", 0.0)
    
    def _calculate_pattern_match(self, text: str, pattern: Dict[str, Any]) -> float:
        """Calculate confidence score for a pattern match."""
        try:
            keywords = pattern.get("keywords", [])
            regex_patterns = pattern.get("regex_patterns", [])
            required_words = pattern.get("required_words", [])
            
            confidence = 0.0
            
            # Keyword matching
            if keywords:
                keyword_matches = sum(1 for keyword in keywords if keyword in text)
                keyword_confidence = keyword_matches / len(keywords)
                confidence += keyword_confidence * 0.4
            
            # Regex pattern matching
            if regex_patterns:
                regex_matches = 0
                for regex_pattern in regex_patterns:
                    if re.search(regex_pattern, text, re.IGNORECASE):
                        regex_matches += 1
                
                if regex_patterns:
                    regex_confidence = regex_matches / len(regex_patterns)
                    confidence += regex_confidence * 0.4
            
            # Required words matching
            if required_words:
                required_matches = all(word in text for word in required_words)
                if required_matches:
                    confidence += 0.2
                else:
                    confidence *= 0.5  # Penalize missing required words
            
            return min(confidence, 1.0)
            
        except Exception as e:
            logger.error(f"Pattern match calculation failed: {str(e)}")
            return 0.0
    
    def _extract_parameters(self, input_text: str, intent_type: str, 
                           context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract parameters from input text based on intent type."""
        try:
            parameters = {}
            
            # Get parameter extractors for this intent type
            extractors = self.parameter_extractors.get(intent_type, [])
            
            for extractor in extractors:
                param_name = extractor["name"]
                extraction_method = extractor["method"]
                
                if extraction_method == "regex":
                    value = self._extract_with_regex(input_text, extractor["pattern"])
                elif extraction_method == "keywords":
                    value = self._extract_with_keywords(input_text, extractor["keywords"])
                elif extraction_method == "context":
                    value = context.get(param_name) if context else None
                else:
                    continue
                
                if value is not None:
                    parameters[param_name] = value
            
            # Add common parameters
            common_params = self._extract_common_parameters(input_text)
            parameters.update(common_params)
            
            return parameters
            
        except Exception as e:
            logger.error(f"Parameter extraction failed: {str(e)}")
            return {}
    
    def _extract_with_regex(self, text: str, pattern: str) -> Optional[str]:
        """Extract parameter using regex pattern."""
        try:
            match = re.search(pattern, text, re.IGNORECASE)
            return match.group(1) if match else None
        except Exception:
            return None
    
    def _extract_with_keywords(self, text: str, keywords: List[str]) -> Optional[str]:
        """Extract parameter using keyword matching."""
        try:
            for keyword in keywords:
                if keyword.lower() in text.lower():
                    return keyword
            return None
        except Exception:
            return None
    
    def _extract_common_parameters(self, input_text: str) -> Dict[str, Any]:
        """Extract common parameters from any input."""
        try:
            parameters = {}
            
            # Extract numbers
            numbers = re.findall(r'\b\d+\.?\d*\b', input_text)
            if numbers:
                parameters["numbers"] = [float(n) if '.' in n else int(n) for n in numbers]
            
            # Extract email addresses
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', input_text)
            if emails:
                parameters["emails"] = emails
            
            # Extract URLs
            urls = re.findall(r'https?://[^\s<>"{}|\\^`[\]]+', input_text)
            if urls:
                parameters["urls"] = urls
            
            # Extract dates
            dates = re.findall(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', input_text)
            if dates:
                parameters["dates"] = dates
            
            return parameters
            
        except Exception as e:
            logger.error(f"Common parameter extraction failed: {str(e)}")
            return {}
    
    def _extract_entities(self, input_text: str) -> List[Dict[str, Any]]:
        """Extract named entities from input text."""
        try:
            entities = []
            
            # Simple entity extraction patterns
            entity_patterns = {
                "money": r'\$\d+(?:,\d{3})*(?:\.\d{2})?',
                "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                "address": r'\d+\s+\w+\s+(?:street|st|avenue|ave|road|rd|boulevard|blvd)',
                "company": r'\b(?:Inc|Corp|LLC|Ltd|Co)\b',
                "time": r'\b\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?\b'
            }
            
            for entity_type, pattern in entity_patterns.items():
                matches = re.findall(pattern, input_text, re.IGNORECASE)
                for match in matches:
                    entities.append({
                        "type": entity_type,
                        "value": match,
                        "start": input_text.find(match),
                        "end": input_text.find(match) + len(match)
                    })
            
            return entities
            
        except Exception as e:
            logger.error(f"Entity extraction failed: {str(e)}")
            return []
    
    def _get_context_boost(self, text: str, context: Dict[str, Any]) -> float:
        """Get confidence boost from context."""
        try:
            boost = 0.0
            
            # Check for recent conversation context
            if "previous_intent" in context:
                previous_intent = context["previous_intent"]
                if previous_intent in text.lower():
                    boost += 0.2
            
            # Check for user preferences
            if "user_preferences" in context:
                prefs = context["user_preferences"]
                for pref_key, pref_value in prefs.items():
                    if str(pref_value).lower() in text.lower():
                        boost += 0.1
            
            # Check for session context
            if "session_context" in context:
                session_ctx = context["session_context"]
                if "current_task" in session_ctx:
                    current_task = session_ctx["current_task"]
                    if current_task.lower() in text.lower():
                        boost += 0.15
            
            return min(boost, 0.3)  # Cap boost at 0.3
            
        except Exception as e:
            logger.error(f"Context boost calculation failed: {str(e)}")
            return 0.0
    
    def _create_error_intent(self, input_text: str, error_message: str) -> Dict[str, Any]:
        """Create an error intent object."""
        return {
            "id": f"intent_error_{int(time.time() * 1000)}",
            "type": "error",
            "confidence": 0.0,
            "raw_input": input_text,
            "parsed_at": datetime.utcnow().isoformat() + "Z",
            "parameters": {},
            "entities": [],
            "context": {},
            "error": error_message,
            "metadata": {
                "input_length": len(input_text),
                "parsing_time": 0.0,
                "error": True
            }
        }
    
    def _load_intent_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load intent patterns for classification."""
        return {
            "query": [
                {
                    "keywords": ["what", "how", "when", "where", "why", "who", "which"],
                    "regex_patterns": [r"\b(what|how|when|where|why|who|which)\b"],
                    "required_words": []
                },
                {
                    "keywords": ["tell me", "show me", "explain", "describe"],
                    "regex_patterns": [r"\b(tell me|show me|explain|describe)\b"],
                    "required_words": []
                }
            ],
            "command": [
                {
                    "keywords": ["execute", "run", "start", "stop", "create", "delete"],
                    "regex_patterns": [r"\b(execute|run|start|stop|create|delete)\b"],
                    "required_words": []
                },
                {
                    "keywords": ["please", "can you", "could you"],
                    "regex_patterns": [r"\b(please|can you|could you)\b"],
                    "required_words": ["execute", "run", "start", "stop", "create", "delete"]
                }
            ],
            "transaction": [
                {
                    "keywords": ["transfer", "send", "pay", "receive", "deposit", "withdraw"],
                    "regex_patterns": [r"\b(transfer|send|pay|receive|deposit|withdraw)\b"],
                    "required_words": []
                },
                {
                    "keywords": ["$", "money", "amount", "payment"],
                    "regex_patterns": [r"\$\d+(?:,\d{3})*(?:\.\d{2})?"],
                    "required_words": []
                }
            ],
            "information_request": [
                {
                    "keywords": ["get", "fetch", "retrieve", "find", "search"],
                    "regex_patterns": [r"\b(get|fetch|retrieve|find|search)\b"],
                    "required_words": []
                }
            ],
            "greeting": [
                {
                    "keywords": ["hello", "hi", "hey", "good morning", "good afternoon"],
                    "regex_patterns": [r"\b(hello|hi|hey|good morning|good afternoon)\b"],
                    "required_words": []
                }
            ],
            "farewell": [
                {
                    "keywords": ["goodbye", "bye", "see you", "farewell"],
                    "regex_patterns": [r"\b(goodbye|bye|see you|farewell)\b"],
                    "required_words": []
                }
            ]
        }
    
    def _load_parameter_extractors(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load parameter extractors for different intent types."""
        return {
            "transaction": [
                {
                    "name": "amount",
                    "method": "regex",
                    "pattern": r"\$\s*(\d+(?:,\d{3})*(?:\.\d{2})?)"
                },
                {
                    "name": "recipient",
                    "method": "regex",
                    "pattern": r"(?:to|for)\s+([A-Za-z0-9\s]+)"
                },
                {
                    "name": "currency",
                    "method": "keywords",
                    "keywords": ["USD", "EUR", "GBP", "JPY"]
                }
            ],
            "command": [
                {
                    "name": "action",
                    "method": "keywords",
                    "keywords": ["execute", "run", "start", "stop", "create", "delete"]
                },
                {
                    "name": "target",
                    "method": "regex",
                    "pattern": r"(?:execute|run|start|stop|create|delete)\s+([A-Za-z0-9_\-]+)"
                }
            ],
            "query": [
                {
                    "name": "query_type",
                    "method": "keywords",
                    "keywords": ["what", "how", "when", "where", "why", "who", "which"]
                },
                {
                    "name": "subject",
                    "method": "regex",
                    "pattern": r"(?:what|how|when|where|why|who|which)\s+(?:is|are|was|were)\s+([A-Za-z0-9\s]+)"
                }
            ]
        }
    
    def add_intent_pattern(self, intent_type: str, pattern: Dict[str, Any]) -> None:
        """Add a new intent pattern."""
        try:
            if intent_type not in self.intent_patterns:
                self.intent_patterns[intent_type] = []
            
            self.intent_patterns[intent_type].append(pattern)
            logger.info(f"Added pattern for intent type: {intent_type}")
            
        except Exception as e:
            logger.error(f"Failed to add intent pattern: {str(e)}")
    
    def add_parameter_extractor(self, intent_type: str, extractor: Dict[str, Any]) -> None:
        """Add a new parameter extractor."""
        try:
            if intent_type not in self.parameter_extractors:
                self.parameter_extractors[intent_type] = []
            
            self.parameter_extractors[intent_type].append(extractor)
            logger.info(f"Added parameter extractor for intent type: {intent_type}")
            
        except Exception as e:
            logger.error(f"Failed to add parameter extractor: {str(e)}")
    
    def get_supported_intent_types(self) -> List[str]:
        """Get list of supported intent types."""
        return list(self.intent_patterns.keys())
    
    def parse_batch(self, inputs: List[str], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Parse multiple inputs in batch."""
        results = []
        
        for input_text in inputs:
            intent = self.parse_intent(input_text, context)
            results.append(intent)
        
        logger.info(f"Parsed batch of {len(inputs)} inputs")
        return results
