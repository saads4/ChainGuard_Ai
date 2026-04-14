"""
Regex Detector - Fast pattern matching for known injection phrases

Handles regex-based pattern detection for ChainGuardAI:
- High-performance pattern matching
- Predefined malicious pattern library
- Pattern categorization and risk scoring
- Real-time pattern management
"""

import re
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from loguru import logger


class RegexDetector:
    """Fast regex-based injection pattern detector."""
    
    def __init__(self, patterns_file: str = None, case_sensitive: bool = False):
        """
        Initialize RegexDetector.
        
        Args:
            patterns_file: Path to patterns JSON file
            case_sensitive: Whether patterns should be case sensitive
        """
        self.patterns_file = patterns_file
        self.case_sensitive = case_sensitive
        self.patterns = {}
        self.compiled_patterns = {}
        
        # Statistics
        self.stats = {
            "total_checks": 0,
            "total_matches": 0,
            "patterns_loaded": 0,
            "avg_check_time": 0.0
        }
        
        # Load patterns
        self._load_patterns()
        
        logger.info(f"Initialized RegexDetector with {len(self.patterns)} patterns")
    
    def detect(self, input_text: str) -> Dict[str, Any]:
        """
        Detect injection patterns in input text.
        
        Args:
            input_text: Text to analyze
            
        Returns:
            Detection result with matches and risk score
        """
        try:
            start_time = time.time()
            
            result = {
                "matches_found": 0,
                "matches": [],
                "risk_score": 0.0,
                "pattern_categories": {},
                "processing_time": 0.0,
                "detailed_matches": []
            }
            
            # Run pattern matching
            matches = self._match_patterns(input_text)
            
            # Process matches
            if matches:
                result["matches_found"] = len(matches)
                result["matches"] = [match["pattern"] for match in matches]
                result["detailed_matches"] = matches
                result["risk_score"] = self._calculate_risk_score(matches)
                result["pattern_categories"] = self._categorize_matches(matches)
            
            # Update statistics
            processing_time = time.time() - start_time
            result["processing_time"] = processing_time
            self._update_stats(len(matches), processing_time)
            
            logger.debug(f"Regex detection: {len(matches)} matches, risk: {result['risk_score']:.3f}")
            return result
            
        except Exception as e:
            logger.error(f"Regex detection failed: {str(e)}")
            return {
                "matches_found": 0,
                "matches": [],
                "risk_score": 0.0,
                "pattern_categories": {},
                "processing_time": 0.0,
                "error": str(e)
            }
    
    def _match_patterns(self, input_text: str) -> List[Dict[str, Any]]:
        """Match all patterns against input text."""
        matches = []
        
        try:
            for category, patterns in self.patterns.items():
                for pattern_info in patterns:
                    pattern = pattern_info["regex"]
                    risk = pattern_info["risk"]
                    description = pattern_info.get("description", "")
                    
                    # Get compiled pattern
                    compiled_pattern = self.compiled_patterns.get(f"{category}_{pattern}")
                    if not compiled_pattern:
                        continue
                    
                    # Find all matches
                    pattern_matches = list(compiled_pattern.finditer(input_text))
                    
                    for match in pattern_matches:
                        match_info = {
                            "category": category,
                            "pattern": pattern,
                            "description": description,
                            "risk": risk,
                            "match_text": match.group(),
                            "start_pos": match.start(),
                            "end_pos": match.end(),
                            "line_number": input_text[:match.start()].count('\n') + 1
                        }
                        matches.append(match_info)
            
            # Sort by risk (highest first)
            matches.sort(key=lambda x: x["risk"], reverse=True)
            
            return matches
            
        except Exception as e:
            logger.error(f"Pattern matching failed: {str(e)}")
            return []
    
    def _calculate_risk_score(self, matches: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score from matches."""
        if not matches:
            return 0.0
        
        try:
            # Weighted risk calculation
            total_risk = 0.0
            max_risk = 0.0
            
            for match in matches:
                risk = match["risk"]
                total_risk += risk
                max_risk = max(max_risk, risk)
            
            # Normalize risk score (0-1)
            # Consider both total risk and maximum single risk
            normalized_risk = min((total_risk * 0.3 + max_risk * 0.7) / 10.0, 1.0)
            
            return normalized_risk
            
        except Exception as e:
            logger.error(f"Risk score calculation failed: {str(e)}")
            return 0.0
    
    def _categorize_matches(self, matches: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize matches by pattern type."""
        categories = {}
        
        for match in matches:
            category = match["category"]
            categories[category] = categories.get(category, 0) + 1
        
        return categories
    
    def _load_patterns(self) -> None:
        """Load regex patterns from file or defaults."""
        try:
            if self.patterns_file and Path(self.patterns_file).exists():
                self._load_patterns_from_file()
            else:
                self._load_default_patterns()
            
            # Compile patterns for performance
            self._compile_patterns()
            
            self.stats["patterns_loaded"] = sum(len(patterns) for patterns in self.patterns.values())
            
        except Exception as e:
            logger.error(f"Failed to load patterns: {str(e)}")
            self._load_default_patterns()
            self._compile_patterns()
    
    def _load_patterns_from_file(self) -> None:
        """Load patterns from JSON file."""
        try:
            with open(self.patterns_file, 'r') as f:
                self.patterns = json.load(f)
            
            logger.info(f"Loaded patterns from {self.patterns_file}")
            
        except Exception as e:
            logger.error(f"Failed to load patterns from file: {str(e)}")
            raise
    
    def _load_default_patterns(self) -> None:
        """Load default regex patterns."""
        self.patterns = {
            "prompt_injection": [
                {
                    "regex": r"(?i)(ignore|forget|disregard)\s+(?:previous|all|the)\s+(?:instructions|commands|rules)",
                    "risk": 8.0,
                    "description": "Instruction override attempt"
                },
                {
                    "regex": r"(?i)act\s+as\s+(?:a|an)\s+[^.!?]+",
                    "risk": 7.0,
                    "description": "Role playing instruction"
                },
                {
                    "regex": r"(?i)you\s+are\s+(?:a|an)\s+[^.!?]+",
                    "risk": 7.0,
                    "description": "Identity assignment"
                },
                {
                    "regex": r"(?i)(?:override|bypass|ignore)\s+(?:security|protection|filters)",
                    "risk": 9.0,
                    "description": "Security bypass attempt"
                },
                {
                    "regex": r"(?i)(?:jailbreak|break\s+free|escape)\s+(?:the|your)\s+(?:constraints|restrictions|rules)",
                    "risk": 10.0,
                    "description": "Jailbreak attempt"
                }
            ],
            "code_injection": [
                {
                    "regex": r"(?i)<script[^>]*>.*?</script>",
                    "risk": 9.0,
                    "description": "Script tag injection"
                },
                {
                    "regex": r"(?i)javascript:",
                    "risk": 8.0,
                    "description": "JavaScript protocol"
                },
                {
                    "regex": r"(?i)on\w+\s*=",
                    "risk": 7.0,
                    "description": "Event handler injection"
                },
                {
                    "regex": r"(?i)eval\s*\(",
                    "risk": 9.0,
                    "description": "Eval function call"
                },
                {
                    "regex": r"(?i)exec\s*\(",
                    "risk": 9.0,
                    "description": "Exec function call"
                },
                {
                    "regex": r"(?i)system\s*\(",
                    "risk": 9.0,
                    "description": "System function call"
                },
                {
                    "regex": r"(?i)__import__",
                    "risk": 8.0,
                    "description": "Import function access"
                },
                {
                    "regex": r"(?i)subprocess\.",
                    "risk": 8.0,
                    "description": "Subprocess module access"
                },
                {
                    "regex": r"(?i)os\.system",
                    "risk": 9.0,
                    "description": "OS system call"
                }
            ],
            "data_extraction": [
                {
                    "regex": r"(?i)(?:print|show|display|reveal|expose)\s+(?:your|the)\s+(?:instructions|prompts|system\s+prompt)",
                    "risk": 7.0,
                    "description": "System prompt extraction attempt"
                },
                {
                    "regex": r"(?i)(?:what\s+are\s+your|tell\s+me\s+your)\s+(?:instructions|guidelines|rules)",
                    "risk": 6.0,
                    "description": "Guideline extraction"
                },
                {
                    "regex": r"(?i)(?:show|display|print)\s+(?:the|your)\s+(?:source\s+code|implementation)",
                    "risk": 8.0,
                    "description": "Source code extraction"
                }
            ],
            "privilege_escalation": [
                {
                    "regex": r"(?i)(?:admin|root|privilege|escalate)",
                    "risk": 8.0,
                    "description": "Privilege escalation keywords"
                },
                {
                    "regex": r"(?i)(?:sudo|su|administrator|superuser)",
                    "risk": 7.0,
                    "description": "Admin access keywords"
                },
                {
                    "regex": r"(?i)(?:gain|obtain|get)\s+(?:access|control|privileges)",
                    "risk": 7.0,
                    "description": "Access gain attempt"
                }
            ],
            "encoding_attacks": [
                {
                    "regex": r"(?i)(?:base64|b64)\s*:\s*[A-Za-z0-9+/=]+",
                    "risk": 8.0,
                    "description": "Base64 encoded content"
                },
                {
                    "regex": r"(?i)\\u[0-9a-fA-F]{4}",
                    "risk": 6.0,
                    "description": "Unicode escape sequence"
                },
                {
                    "regex": r"(?i)\\x[0-9a-fA-F]{2}",
                    "risk": 6.0,
                    "description": "Hex escape sequence"
                },
                {
                    "regex": r"(?i)%(?:[0-9a-fA-F]{2})",
                    "risk": 5.0,
                    "description": "URL encoding"
                }
            ],
            "hidden_content": [
                {
                    "regex": r"[\u200B-\u200D\uFEFF]",
                    "risk": 5.0,
                    "description": "Zero-width characters"
                },
                {
                    "regex": r"[\u2060\u180E\u061C]",
                    "risk": 4.0,
                    "description": "Invisible formatting characters"
                },
                {
                    "regex": r"[\x00-\x1F\x7F]",
                    "risk": 3.0,
                    "description": "Control characters"
                }
            ],
            "suspicious_commands": [
                {
                    "regex": r"(?i)(?:curl|wget|nc|netcat)\s+",
                    "risk": 8.0,
                    "description": "Network command tools"
                },
                {
                    "regex": r"(?i)(?:cat|type)\s+/",
                    "risk": 7.0,
                    "description": "File read commands"
                },
                {
                    "regex": r"(?i)(?:rm|del)\s+",
                    "risk": 8.0,
                    "description": "File deletion commands"
                },
                {
                    "regex": r"(?i)(?:chmod|chown)\s+",
                    "risk": 7.0,
                    "description": "Permission modification"
                }
            ]
        }
    
    def _compile_patterns(self) -> None:
        """Compile all regex patterns for performance."""
        self.compiled_patterns = {}
        
        try:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            
            for category, patterns in self.patterns.items():
                for pattern_info in patterns:
                    pattern = pattern_info["regex"]
                    pattern_key = f"{category}_{pattern}"
                    
                    try:
                        compiled_pattern = re.compile(pattern, flags | re.DOTALL)
                        self.compiled_patterns[pattern_key] = compiled_pattern
                    except re.error as e:
                        logger.warning(f"Failed to compile pattern '{pattern}': {str(e)}")
                        continue
            
            logger.info(f"Compiled {len(self.compiled_patterns)} regex patterns")
            
        except Exception as e:
            logger.error(f"Pattern compilation failed: {str(e)}")
    
    def add_pattern(self, category: str, pattern: str, risk: float, description: str = "") -> bool:
        """Add a new regex pattern."""
        try:
            if category not in self.patterns:
                self.patterns[category] = []
            
            pattern_info = {
                "regex": pattern,
                "risk": risk,
                "description": description
            }
            
            self.patterns[category].append(pattern_info)
            
            # Compile the new pattern
            flags = 0 if self.case_sensitive else re.IGNORECASE
            compiled_pattern = re.compile(pattern, flags | re.DOTALL)
            self.compiled_patterns[f"{category}_{pattern}"] = compiled_pattern
            
            self.stats["patterns_loaded"] += 1
            
            logger.info(f"Added pattern to category '{category}': {pattern}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add pattern: {str(e)}")
            return False
    
    def remove_pattern(self, category: str, pattern: str) -> bool:
        """Remove a regex pattern."""
        try:
            if category not in self.patterns:
                return False
            
            # Find and remove pattern
            patterns = self.patterns[category]
            for i, pattern_info in enumerate(patterns):
                if pattern_info["regex"] == pattern:
                    del patterns[i]
                    
                    # Remove compiled pattern
                    pattern_key = f"{category}_{pattern}"
                    if pattern_key in self.compiled_patterns:
                        del self.compiled_patterns[pattern_key]
                    
                    self.stats["patterns_loaded"] -= 1
                    
                    logger.info(f"Removed pattern from category '{category}': {pattern}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to remove pattern: {str(e)}")
            return False
    
    def update_pattern(self, category: str, pattern: str, new_risk: float = None, 
                      new_description: str = None) -> bool:
        """Update an existing pattern."""
        try:
            if category not in self.patterns:
                return False
            
            # Find and update pattern
            patterns = self.patterns[category]
            for pattern_info in patterns:
                if pattern_info["regex"] == pattern:
                    if new_risk is not None:
                        pattern_info["risk"] = new_risk
                    if new_description is not None:
                        pattern_info["description"] = new_description
                    
                    logger.info(f"Updated pattern in category '{category}': {pattern}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to update pattern: {str(e)}")
            return False
    
    def save_patterns(self, file_path: str = None) -> bool:
        """Save patterns to JSON file."""
        try:
            save_path = file_path or self.patterns_file
            if not save_path:
                logger.error("No file path specified for saving patterns")
                return False
            
            with open(save_path, 'w') as f:
                json.dump(self.patterns, f, indent=2)
            
            logger.info(f"Saved patterns to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save patterns: {str(e)}")
            return False
    
    def get_pattern_categories(self) -> List[str]:
        """Get list of pattern categories."""
        return list(self.patterns.keys())
    
    def get_patterns_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get patterns for a specific category."""
        return self.patterns.get(category, [])
    
    def get_status(self) -> Dict[str, Any]:
        """Get detector status and statistics."""
        return {
            "status": "active",
            "patterns_loaded": self.stats["patterns_loaded"],
            "categories": list(self.patterns.keys()),
            "case_sensitive": self.case_sensitive,
            "statistics": self.stats.copy(),
            "compiled_patterns": len(self.compiled_patterns)
        }
    
    def _update_stats(self, matches_found: int, processing_time: float) -> None:
        """Update detection statistics."""
        self.stats["total_checks"] += 1
        self.stats["total_matches"] += matches_found
        
        # Update average processing time
        current_avg = self.stats["avg_check_time"]
        count = self.stats["total_checks"]
        self.stats["avg_check_time"] = ((current_avg * (count - 1)) + processing_time) / count
    
    def reset_statistics(self) -> None:
        """Reset detection statistics."""
        self.stats = {
            "total_checks": 0,
            "total_matches": 0,
            "patterns_loaded": self.stats["patterns_loaded"],
            "avg_check_time": 0.0
        }
        logger.info("Regex detector statistics reset")
    
    def test_pattern(self, pattern: str, test_text: str) -> Dict[str, Any]:
        """Test a pattern against test text."""
        try:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            compiled_pattern = re.compile(pattern, flags | re.DOTALL)
            
            matches = list(compiled_pattern.finditer(test_text))
            
            return {
                "pattern": pattern,
                "test_text": test_text,
                "matches_found": len(matches),
                "matches": [
                    {
                        "text": match.group(),
                        "start": match.start(),
                        "end": match.end()
                    }
                    for match in matches
                ]
            }
            
        except Exception as e:
            return {
                "pattern": pattern,
                "test_text": test_text,
                "matches_found": 0,
                "error": str(e)
            }
