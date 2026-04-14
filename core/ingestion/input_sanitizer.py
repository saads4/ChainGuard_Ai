"""
Input Sanitizer - Strips instructions, tags, hidden content from raw input

Handles input sanitization for ChainGuardAI:
- HTML tag removal
- Instruction pattern detection and removal
- Hidden content extraction and removal
- Content normalization
"""

import re
import html
import unicodedata
from typing import Dict, Any, List, Optional, Tuple
from loguru import logger


class InputSanitizer:
    """Sanitizes raw input by removing dangerous or unwanted content."""
    
    def __init__(self, strip_html: bool = True, strip_instructions: bool = True, 
                 strip_hidden_content: bool = True):
        """
        Initialize InputSanitizer.
        
        Args:
            strip_html: Whether to strip HTML tags
            strip_instructions: Whether to strip instruction patterns
            strip_hidden_content: Whether to strip hidden content
        """
        self.strip_html = strip_html
        self.strip_instructions = strip_instructions
        self.strip_hidden_content = strip_hidden_content
        
        # Load patterns
        self.html_patterns = self._load_html_patterns()
        self.instruction_patterns = self._load_instruction_patterns()
        self.hidden_content_patterns = self._load_hidden_content_patterns()
        self.normalization_rules = self._load_normalization_rules()
        
        logger.info("Initialized InputSanitizer")
    
    def sanitize(self, raw_input: str) -> str:
        """
        Sanitize raw input text.
        
        Args:
            raw_input: Raw input string to sanitize
            
        Returns:
            Sanitized input string
        """
        try:
            if not raw_input:
                return ""
            
            sanitized = raw_input
            removed_content = {
                "html_tags": [],
                "instructions": [],
                "hidden_content": [],
                "other": []
            }
            
            # Step 1: Strip HTML tags
            if self.strip_html:
                sanitized, html_removed = self._strip_html_tags(sanitized)
                removed_content["html_tags"] = html_removed
            
            # Step 2: Strip instruction patterns
            if self.strip_instructions:
                sanitized, instructions_removed = self._strip_instruction_patterns(sanitized)
                removed_content["instructions"] = instructions_removed
            
            # Step 3: Strip hidden content
            if self.strip_hidden_content:
                sanitized, hidden_removed = self._strip_hidden_content(sanitized)
                removed_content["hidden_content"] = hidden_removed
            
            # Step 4: Normalize content
            sanitized = self._normalize_content(sanitized)
            
            # Step 5: Apply additional cleaning
            sanitized = self._apply_additional_cleaning(sanitized)
            
            # Log sanitization results
            total_removed = sum(len(content) for content in removed_content.values())
            if total_removed > 0:
                logger.info(f"Sanitized input: removed {total_removed} items")
            
            return sanitized.strip()
            
        except Exception as e:
            logger.error(f"Input sanitization failed: {str(e)}")
            return raw_input  # Return original if sanitization fails
    
    def _strip_html_tags(self, text: str) -> Tuple[str, List[str]]:
        """Strip HTML tags from text."""
        try:
            removed_tags = []
            sanitized = text
            
            # Remove HTML tags
            for pattern_name, pattern in self.html_patterns.items():
                matches = re.findall(pattern, sanitized, re.IGNORECASE | re.DOTALL)
                removed_tags.extend(matches)
                sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE | re.DOTALL)
            
            # Decode HTML entities
            sanitized = html.unescape(sanitized)
            
            return sanitized, removed_tags
            
        except Exception as e:
            logger.error(f"HTML stripping failed: {str(e)}")
            return text, []
    
    def _strip_instruction_patterns(self, text: str) -> Tuple[str, List[str]]:
        """Strip instruction patterns from text."""
        try:
            removed_instructions = []
            sanitized = text
            
            # Remove instruction patterns
            for pattern_name, pattern in self.instruction_patterns.items():
                matches = re.findall(pattern, sanitized, re.IGNORECASE | re.DOTALL)
                removed_instructions.extend(matches)
                sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE | re.DOTALL)
            
            return sanitized, removed_instructions
            
        except Exception as e:
            logger.error(f"Instruction pattern stripping failed: {str(e)}")
            return text, []
    
    def _strip_hidden_content(self, text: str) -> Tuple[str, List[str]]:
        """Strip hidden content from text."""
        try:
            removed_hidden = []
            sanitized = text
            
            # Remove hidden content patterns
            for pattern_name, pattern in self.hidden_content_patterns.items():
                matches = re.findall(pattern, sanitized, re.IGNORECASE | re.DOTALL)
                removed_hidden.extend(matches)
                sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE | re.DOTALL)
            
            return sanitized, removed_hidden
            
        except Exception as e:
            logger.error(f"Hidden content stripping failed: {str(e)}")
            return text, []
    
    def _normalize_content(self, text: str) -> str:
        """Normalize text content."""
        try:
            normalized = text
            
            # Apply normalization rules
            for rule_name, rule in self.normalization_rules.items():
                if rule["type"] == "regex":
                    normalized = re.sub(rule["pattern"], rule["replacement"], normalized)
                elif rule["type"] == "unicode":
                    normalized = unicodedata.normalize(rule["form"], normalized)
                elif rule["type"] == "case":
                    if rule["form"] == "lower":
                        normalized = normalized.lower()
                    elif rule["form"] == "upper":
                        normalized = normalized.upper()
            
            return normalized
            
        except Exception as e:
            logger.error(f"Content normalization failed: {str(e)}")
            return text
    
    def _apply_additional_cleaning(self, text: str) -> str:
        """Apply additional cleaning rules."""
        try:
            cleaned = text
            
            # Remove excessive whitespace
            cleaned = re.sub(r'\s+', ' ', cleaned)
            
            # Remove leading/trailing whitespace
            cleaned = cleaned.strip()
            
            # Remove null bytes
            cleaned = cleaned.replace('\x00', '')
            
            # Remove control characters except newlines and tabs
            cleaned = re.sub(r'[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]', '', cleaned)
            
            # Remove excessive punctuation
            cleaned = re.sub(r'([!?.,;:])\1+', r'\1', cleaned)
            
            # Remove suspicious character sequences
            cleaned = re.sub(r'[<>&\'"]', '', cleaned)
            
            return cleaned
            
        except Exception as e:
            logger.error(f"Additional cleaning failed: {str(e)}")
            return text
    
    def analyze_input(self, raw_input: str) -> Dict[str, Any]:
        """
        Analyze raw input for potential issues.
        
        Args:
            raw_input: Raw input string to analyze
            
        Returns:
            Analysis results
        """
        try:
            analysis = {
                "length": len(raw_input),
                "has_html": False,
                "has_instructions": False,
                "has_hidden_content": False,
                "suspicious_patterns": [],
                "encoding_issues": [],
                "risk_level": "LOW"
            }
            
            # Check for HTML
            for pattern in self.html_patterns.values():
                if re.search(pattern, raw_input, re.IGNORECASE):
                    analysis["has_html"] = True
                    break
            
            # Check for instructions
            for pattern in self.instruction_patterns.values():
                if re.search(pattern, raw_input, re.IGNORECASE):
                    analysis["has_instructions"] = True
                    break
            
            # Check for hidden content
            for pattern in self.hidden_content_patterns.values():
                if re.search(pattern, raw_input, re.IGNORECASE):
                    analysis["has_hidden_content"] = True
                    break
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'<script.*?>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'eval\s*\(',
                r'exec\s*\(',
                r'system\s*\(',
                r'__import__',
                r'subprocess\.',
                r'os\.system',
                r'base64_decode',
                r'shell_exec',
                r'passthru',
                r'file_get_contents',
                r'curl\s+',
                r'wget\s+',
                r'nc\s+',
                r'netcat'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, raw_input, re.IGNORECASE):
                    analysis["suspicious_patterns"].append(pattern)
            
            # Check for encoding issues
            try:
                raw_input.encode('utf-8')
            except UnicodeEncodeError as e:
                analysis["encoding_issues"].append(str(e))
            
            # Determine risk level
            if analysis["suspicious_patterns"]:
                analysis["risk_level"] = "HIGH"
            elif analysis["has_instructions"] or analysis["has_hidden_content"]:
                analysis["risk_level"] = "MEDIUM"
            elif analysis["has_html"]:
                analysis["risk_level"] = "LOW"
            
            return analysis
            
        except Exception as e:
            logger.error(f"Input analysis failed: {str(e)}")
            return {
                "length": 0,
                "has_html": False,
                "has_instructions": False,
                "has_hidden_content": False,
                "suspicious_patterns": [],
                "encoding_issues": [str(e)],
                "risk_level": "HIGH"
            }
    
    def extract_safe_content(self, raw_input: str) -> Dict[str, Any]:
        """
        Extract safe content from raw input.
        
        Args:
            raw_input: Raw input string
            
        Returns:
            Dictionary with safe and unsafe content
        """
        try:
            # Sanitize the input
            sanitized = self.sanitize(raw_input)
            
            # Analyze the original input
            analysis = self.analyze_input(raw_input)
            
            # Determine content safety
            is_safe = (
                analysis["risk_level"] == "LOW" and
                len(analysis["suspicious_patterns"]) == 0 and
                len(analysis["encoding_issues"]) == 0
            )
            
            return {
                "original": raw_input,
                "sanitized": sanitized,
                "is_safe": is_safe,
                "risk_level": analysis["risk_level"],
                "removed_elements": {
                    "html_tags": len([m for pattern in self.html_patterns.values() 
                                    for m in re.findall(pattern, raw_input, re.IGNORECASE)]),
                    "instructions": len([m for pattern in self.instruction_patterns.values() 
                                       for m in re.findall(pattern, raw_input, re.IGNORECASE)]),
                    "hidden_content": len([m for pattern in self.hidden_content_patterns.values() 
                                         for m in re.findall(pattern, raw_input, re.IGNORECASE)])
                },
                "analysis": analysis
            }
            
        except Exception as e:
            logger.error(f"Safe content extraction failed: {str(e)}")
            return {
                "original": raw_input,
                "sanitized": raw_input,
                "is_safe": False,
                "risk_level": "HIGH",
                "removed_elements": {"html_tags": 0, "instructions": 0, "hidden_content": 0},
                "analysis": {"error": str(e)}
            }
    
    def _load_html_patterns(self) -> Dict[str, str]:
        """Load HTML tag patterns."""
        return {
            "script_tags": r'<script[^>]*>.*?</script>',
            "style_tags": r'<style[^>]*>.*?</style>',
            "html_comments": r'<!--.*?-->',
            "html_tags": r'<[^>]+>',
            "html_entities": r'&[a-zA-Z]+;|&#[0-9]+;',
            "iframes": r'<iframe[^>]*>.*?</iframe>',
            "objects": r'<object[^>]*>.*?</object>',
            "embeds": r'<embed[^>]*>.*?</embed>',
            "forms": r'<form[^>]*>.*?</form>',
            "inputs": r'<input[^>]*>',
            "links": r'<link[^>]*>',
            "meta": r'<meta[^>]*>'
        }
    
    def _load_instruction_patterns(self) -> Dict[str, str]:
        """Load instruction patterns."""
        return {
            "system_instructions": r'(?:ignore|forget|disregard)\s+(?:previous|all|the)\s+(?:instructions|commands|rules)',
            "role_instructions": r'act\s+as\s+(?:a|an)\s+[^.!?]+',
            "persona_instructions": r'you\s+are\s+(?:a|an)\s+[^.!?]+',
            "override_instructions": r'(?:override|bypass|ignore)\s+(?:security|protection|filters)',
            "jailbreak_attempts": r'(?:jailbreak|break\s+free|escape)\s+(?:the|your)\s+(?:constraints|restrictions|rules)',
            "prompt_injection": r'(?:prompt|input)\s+(?:injection|injection\s+attack)',
            "hidden_instructions": r'\[.*?\]|\{.*?\}|\<.*?\>',
            "base64_instructions": r'(?:base64|b64)\s*:\s*[A-Za-z0-9+/=]+',
            "unicode_instructions": r'\\u[0-9a-fA-F]{4}',
            "hex_instructions": r'\\x[0-9a-fA-F]{2}'
        }
    
    def _load_hidden_content_patterns(self) -> Dict[str, str]:
        """Load hidden content patterns."""
        return {
            "zero_width_chars": r'[\u200B-\u200D\uFEFF]',
            "invisible_chars": r'[\u2060\u180E\u061C]',
            "control_chars": r'[\x00-\x1F\x7F]',
            "private_use_chars": r'[\uE000-\uF8FF]',
            "formatting_chars": r'[\u202A-\u202E\u2066-\u2069]',
            "surrogate_pairs": r'[\uD800-\uDFFF]',
            "combining_chars": r'[\u0300-\u036F\u1DC0-\u1DFF]',
            "whitespace_variants": r'[\u2000-\u200A\u202F\u205F\u3000]',
            "mathematical_symbols": r'[\u2200-\u22FF\u27C0-\u27EF]',
            "currency_symbols": r'[\u20A0-\u20CF]'
        }
    
    def _load_normalization_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load content normalization rules."""
        return {
            "unicode_normalization": {
                "type": "unicode",
                "form": "NFKC"
            },
            "lowercase_conversion": {
                "type": "case",
                "form": "lower"
            },
            "multiple_spaces": {
                "type": "regex",
                "pattern": r'\s+',
                "replacement": ' '
            },
            "multiple_newlines": {
                "type": "regex",
                "pattern": r'\n+',
                "replacement": '\n'
            },
            "tab_normalization": {
                "type": "regex",
                "pattern": r'\t',
                "replacement": ' '
            },
            "carriage_return": {
                "type": "regex",
                "pattern": r'\r',
                "replacement": ''
            }
        }
    
    def add_sanitization_pattern(self, category: str, pattern_name: str, pattern: str) -> None:
        """Add a new sanitization pattern."""
        try:
            if category == "html":
                self.html_patterns[pattern_name] = pattern
            elif category == "instructions":
                self.instruction_patterns[pattern_name] = pattern
            elif category == "hidden":
                self.hidden_content_patterns[pattern_name] = pattern
            else:
                logger.warning(f"Unknown pattern category: {category}")
                return
            
            logger.info(f"Added {category} pattern: {pattern_name}")
            
        except Exception as e:
            logger.error(f"Failed to add sanitization pattern: {str(e)}")
    
    def remove_sanitization_pattern(self, category: str, pattern_name: str) -> None:
        """Remove a sanitization pattern."""
        try:
            if category == "html" and pattern_name in self.html_patterns:
                del self.html_patterns[pattern_name]
            elif category == "instructions" and pattern_name in self.instruction_patterns:
                del self.instruction_patterns[pattern_name]
            elif category == "hidden" and pattern_name in self.hidden_content_patterns:
                del self.hidden_content_patterns[pattern_name]
            else:
                logger.warning(f"Pattern not found: {category}.{pattern_name}")
                return
            
            logger.info(f"Removed {category} pattern: {pattern_name}")
            
        except Exception as e:
            logger.error(f"Failed to remove sanitization pattern: {str(e)}")
    
    def get_sanitization_stats(self) -> Dict[str, Any]:
        """Get statistics about sanitization capabilities."""
        return {
            "html_patterns_count": len(self.html_patterns),
            "instruction_patterns_count": len(self.instruction_patterns),
            "hidden_content_patterns_count": len(self.hidden_content_patterns),
            "normalization_rules_count": len(self.normalization_rules),
            "strip_html": self.strip_html,
            "strip_instructions": self.strip_instructions,
            "strip_hidden_content": self.strip_hidden_content,
            "supported_categories": ["html", "instructions", "hidden"]
        }
    
    def test_sanitization(self, test_inputs: List[str]) -> Dict[str, Any]:
        """Test sanitization on sample inputs."""
        try:
            results = []
            
            for i, test_input in enumerate(test_inputs):
                start_time = time.time()
                
                # Analyze original
                original_analysis = self.analyze_input(test_input)
                
                # Sanitize
                sanitized = self.sanitize(test_input)
                
                # Analyze sanitized
                sanitized_analysis = self.analyze_input(sanitized)
                
                processing_time = time.time() - start_time
                
                results.append({
                    "test_index": i,
                    "original_length": len(test_input),
                    "sanitized_length": len(sanitized),
                    "original_risk": original_analysis["risk_level"],
                    "sanitized_risk": sanitized_analysis["risk_level"],
                    "processing_time": processing_time,
                    "content_removed": len(test_input) - len(sanitized)
                })
            
            return {
                "test_count": len(test_inputs),
                "results": results,
                "avg_processing_time": sum(r["processing_time"] for r in results) / len(results),
                "total_content_removed": sum(r["content_removed"] for r in results)
            }
            
        except Exception as e:
            logger.error(f"Sanitization testing failed: {str(e)}")
            return {"error": str(e)}
