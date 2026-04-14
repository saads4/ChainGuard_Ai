"""
Stage 2: Embedding Detection - Semantic anomaly via sentence-transformer embeddings

Provides semantic embedding-based anomaly detection for ChainGuardAI:
- Sentence transformer embeddings
- Semantic similarity analysis
- Anomaly scoring and thresholding
- Embedding cache management
"""

from .embedding_detector import EmbeddingDetector
from .embedding_cache import EmbeddingCache
from .anomaly_scorer import AnomalyScorer

__all__ = [
    "EmbeddingDetector",
    "EmbeddingCache", 
    "AnomalyScorer",
]
