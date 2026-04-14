"""
Stage 1: Regex Detection - Fast pattern matching for known injection phrases

Provides fast regex-based pattern matching for ChainGuardAI:
- Predefined malicious pattern library
- High-performance pattern matching
- Pattern categorization and scoring
- Real-time pattern updates
"""

from .regex_detector import RegexDetector

__all__ = ["RegexDetector"]
