"""
Embedding Detector - Semantic anomaly via sentence-transformer embeddings

Handles embedding-based semantic anomaly detection for ChainGuardAI:
- Sentence transformer embeddings generation
- Semantic similarity comparison
- Anomaly detection and scoring
- Embedding cache management
"""

import time
from typing import Dict, Any, List, Optional, Tuple
from loguru import logger
from .embedding_cache import EmbeddingCache
from .anomaly_scorer import AnomalyScorer

# Optional heavy ML dependencies — graceful degradation if not installed
try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    _ML_AVAILABLE = True
except ImportError:
    np = None  # type: ignore
    SentenceTransformer = None  # type: ignore
    cosine_similarity = None  # type: ignore
    _ML_AVAILABLE = False
    logger.warning(
        "sentence-transformers / sklearn not installed. "
        "Stage-2 embedding detection will be DISABLED. "
        "Run: pip install sentence-transformers scikit-learn"
    )


class EmbeddingDetector:
    """Detects semantic anomalies using sentence transformer embeddings."""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", cache_size: int = 1000,
                 similarity_threshold: float = 0.7):
        """
        Initialize EmbeddingDetector.
        
        Args:
            model_name: Name of the sentence transformer model
            cache_size: Size of the embedding cache
            similarity_threshold: Threshold for anomaly detection
        """
        self.model_name = model_name
        self.cache_size = cache_size
        self.similarity_threshold = similarity_threshold
        
        # Initialize components
        self.model = None
        self.cache = EmbeddingCache(cache_size)
        self.anomaly_scorer = AnomalyScorer(similarity_threshold)
        
        # Statistics
        self.stats = {
            "total_embeddings": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "anomalies_detected": 0,
            "avg_embedding_time": 0.0,
            "avg_similarity_time": 0.0
        }
        
        # Load model (only when ML stack is available)
        if _ML_AVAILABLE:
            self._load_model()
        else:
            logger.warning("EmbeddingDetector: ML libraries unavailable — detector disabled")
        
        logger.info(f"Initialized EmbeddingDetector with model: {model_name}")
    
    def detect(self, input_text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Detect semantic anomalies in input text.
        
        Args:
            input_text: Text to analyze
            context: Additional context for analysis
            
        Returns:
            Detection result with similarity scores and anomaly assessment
        """
        # Graceful degradation when ML stack is unavailable
        if not _ML_AVAILABLE or self.model is None:
            return {
                "similarity_score": 1.0,
                "anomaly_detected": False,
                "anomaly_score": 0.0,
                "embedding_vector": None,
                "reference_embeddings": 0,
                "processing_time": 0.0,
                "cache_hit": False,
                "detailed_analysis": {"note": "ML stack unavailable — stage 2 skipped"}
            }

        try:
            start_time = time.time()
            
            result = {
                "similarity_score": 0.0,
                "anomaly_detected": False,
                "anomaly_score": 0.0,
                "embedding_vector": None,
                "reference_embeddings": 0,
                "processing_time": 0.0,
                "cache_hit": False,
                "detailed_analysis": {}
            }
            
            # Generate embedding for input text
            embedding_start = time.time()
            input_embedding = self._get_embedding(input_text)
            embedding_time = time.time() - embedding_start
            
            if input_embedding is None:
                logger.error("Failed to generate embedding for input text")
                return self._create_error_result("Failed to generate embedding")
            
            result["embedding_vector"] = input_embedding.tolist()
            
            # Get reference embeddings from cache
            reference_embeddings = self.cache.get_reference_embeddings()
            result["reference_embeddings"] = len(reference_embeddings)
            
            if len(reference_embeddings) == 0:
                # No reference embeddings available, add this as reference
                self.cache.add_embedding(input_text, input_embedding)
                result["similarity_score"] = 1.0  # Assume normal when no references
                result["anomaly_detected"] = False
                result["processing_time"] = time.time() - start_time
                return result
            
            # Calculate similarities
            similarity_start = time.time()
            similarities = self._calculate_similarities(input_embedding, reference_embeddings)
            similarity_time = time.time() - similarity_start
            
            # Find maximum similarity
            max_similarity = np.max(similarities) if similarities.size > 0 else 0.0
            result["similarity_score"] = float(max_similarity)
            
            # Detect anomaly
            anomaly_result = self.anomaly_scorer.score_anomaly(
                input_embedding, reference_embeddings, context
            )
            result.update(anomaly_result)
            
            # Update cache with new embedding if not anomalous
            if not result["anomaly_detected"]:
                self.cache.add_embedding(input_text, input_embedding)
            
            # Add timing information
            total_time = time.time() - start_time
            result["processing_time"] = total_time
            result["detailed_analysis"] = {
                "embedding_generation_time": embedding_time,
                "similarity_calculation_time": similarity_time,
                "cache_hit": self.cache.last_hit
            }
            
            # Update statistics
            self._update_stats(embedding_time, similarity_time, result["anomaly_detected"])
            
            logger.debug(f"Embedding detection: similarity={max_similarity:.3f}, anomaly={result['anomaly_detected']}")
            return result
            
        except Exception as e:
            logger.error(f"Embedding detection failed: {str(e)}")
            return self._create_error_result(str(e))
    
    def _get_embedding(self, text: str) -> Optional[Any]:
        """Get embedding for text, using cache if available."""
        try:
            # Check cache first
            cached_embedding = self.cache.get_embedding(text)
            if cached_embedding is not None:
                self.stats["cache_hits"] += 1
                return cached_embedding
            
            # Generate new embedding
            if self.model is None:
                logger.error("Model not loaded")
                return None
            
            embedding = self.model.encode([text])[0]
            self.stats["cache_misses"] += 1
            self.stats["total_embeddings"] += 1
            
            # Cache the embedding
            self.cache.add_embedding(text, embedding)
            
            return embedding
            
        except Exception as e:
            logger.error(f"Failed to get embedding: {str(e)}")
            return None
    
    def _calculate_similarities(self, input_embedding, 
                              reference_embeddings: List) -> Any:
        """Calculate cosine similarities between input and reference embeddings."""
        if not _ML_AVAILABLE:
            return np.array([]) if np is not None else []
        try:
            if len(reference_embeddings) == 0:
                return np.array([])
            
            # Stack reference embeddings
            ref_matrix = np.vstack(reference_embeddings)
            
            # Reshape input embedding for similarity calculation
            input_reshaped = input_embedding.reshape(1, -1)
            
            # Calculate cosine similarities
            similarities = cosine_similarity(input_reshaped, ref_matrix)[0]
            
            return similarities
            
        except Exception as e:
            logger.error(f"Failed to calculate similarities: {str(e)}")
            return np.array([])
    
    def _load_model(self) -> None:
        """Load the sentence transformer model."""
        if not _ML_AVAILABLE:
            self.model = None
            return
        try:
            logger.info(f"Loading sentence transformer model: {self.model_name}")
            self.model = SentenceTransformer(self.model_name)
            logger.info("Model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            self.model = None
    
    def _update_stats(self, embedding_time: float, similarity_time: float, 
                     anomaly_detected: bool) -> None:
        """Update detection statistics."""
        try:
            # Update timing averages
            total_embeddings = self.stats["total_embeddings"]
            if total_embeddings > 0:
                current_avg = self.stats["avg_embedding_time"]
                self.stats["avg_embedding_time"] = ((current_avg * (total_embeddings - 1)) + embedding_time) / total_embeddings
            
            # Update anomaly count
            if anomaly_detected:
                self.stats["anomalies_detected"] += 1
            
            # Update similarity time average
            current_avg = self.stats["avg_similarity_time"]
            count = self.stats["total_embeddings"]
            self.stats["avg_similarity_time"] = ((current_avg * (count - 1)) + similarity_time) / count
            
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")
    
    def _create_error_result(self, error: str) -> Dict[str, Any]:
        """Create error result when detection fails."""
        return {
            "similarity_score": 0.0,
            "anomaly_detected": True,  # Assume anomalous on error
            "anomaly_score": 1.0,
            "embedding_vector": None,
            "reference_embeddings": 0,
            "processing_time": 0.0,
            "cache_hit": False,
            "error": error
        }
    
    def add_reference_texts(self, texts: List[str]) -> int:
        """Add reference texts to build the embedding baseline."""
        try:
            added_count = 0
            
            for text in texts:
                if text.strip():  # Skip empty texts
                    embedding = self._get_embedding(text)
                    if embedding is not None:
                        added_count += 1
            
            logger.info(f"Added {added_count} reference texts to embedding baseline")
            return added_count
            
        except Exception as e:
            logger.error(f"Failed to add reference texts: {str(e)}")
            return 0
    
    def set_similarity_threshold(self, threshold: float) -> None:
        """Update the similarity threshold for anomaly detection."""
        self.similarity_threshold = threshold
        self.anomaly_scorer.threshold = threshold
        logger.info(f"Updated similarity threshold to {threshold}")
    
    def get_embedding_info(self) -> Dict[str, Any]:
        """Get information about the embedding model and cache."""
        try:
            return {
                "model_name": self.model_name,
                "model_loaded": self.model is not None,
                "cache_size": self.cache_size,
                "cache_entries": len(self.cache.embeddings),
                "similarity_threshold": self.similarity_threshold,
                "statistics": self.stats.copy(),
                "cache_hit_rate": (
                    self.stats["cache_hits"] / 
                    max(self.stats["cache_hits"] + self.stats["cache_misses"], 1)
                )
            }
            
        except Exception as e:
            logger.error(f"Failed to get embedding info: {str(e)}")
            return {"error": str(e)}
    
    def clear_cache(self) -> None:
        """Clear the embedding cache."""
        self.cache.clear()
        logger.info("Embedding cache cleared")
    
    def export_embeddings(self, file_path: str) -> bool:
        """Export cached embeddings to file."""
        try:
            return self.cache.export_embeddings(file_path)
            
        except Exception as e:
            logger.error(f"Failed to export embeddings: {str(e)}")
            return False
    
    def import_embeddings(self, file_path: str) -> int:
        """Import embeddings from file."""
        try:
            return self.cache.import_embeddings(file_path)
            
        except Exception as e:
            logger.error(f"Failed to import embeddings: {str(e)}")
            return 0
    
    def batch_detect(self, texts: List[str], contexts: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Run detection on multiple texts in batch."""
        try:
            results = []
            
            for i, text in enumerate(texts):
                context = contexts[i] if contexts and i < len(contexts) else None
                result = self.detect(text, context)
                results.append(result)
            
            logger.info(f"Batch embedding detection completed: {len(results)} texts processed")
            return results
            
        except Exception as e:
            logger.error(f"Batch embedding detection failed: {str(e)}")
            return []
    
    def get_status(self) -> Dict[str, Any]:
        """Get detector status."""
        return {
            "status": "active" if self.model is not None else "error",
            "model_name": self.model_name,
            "model_loaded": self.model is not None,
            "cache_status": self.cache.get_status(),
            "anomaly_scorer_status": self.anomaly_scorer.get_status(),
            "statistics": self.stats.copy()
        }
    
    def reset_statistics(self) -> None:
        """Reset detection statistics."""
        self.stats = {
            "total_embeddings": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "anomalies_detected": 0,
            "avg_embedding_time": 0.0,
            "avg_similarity_time": 0.0
        }
        logger.info("Embedding detector statistics reset")
    
    def test_embedding(self, text: str) -> Dict[str, Any]:
        """Test embedding generation for a text."""
        try:
            start_time = time.time()
            embedding = self._get_embedding(text)
            generation_time = time.time() - start_time
            
            if embedding is None:
                return {
                    "text": text,
                    "success": False,
                    "error": "Failed to generate embedding"
                }
            
            return {
                "text": text,
                "success": True,
                "embedding_shape": embedding.shape,
                "embedding_norm": float(np.linalg.norm(embedding)),
                "generation_time": generation_time,
                "cache_hit": self.cache.last_hit
            }
            
        except Exception as e:
            return {
                "text": text,
                "success": False,
                "error": str(e)
            }
