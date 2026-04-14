"""
Stage 3: Classifier Detection - ML classifier: does intent match agent's role?

Provides ML-based intent classification for ChainGuardAI:
- Intent classification model
- Role-based validation
- Confidence scoring
- Model training and management
"""

from .intent_classifier import IntentClassifier

__all__ = ["IntentClassifier"]
