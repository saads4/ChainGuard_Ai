"""
Anomaly Scorer - Cosine similarity comparison and threshold logic

Handles anomaly scoring and thresholding for ChainGuardAI:
- Cosine similarity calculation
- Anomaly threshold logic
- Context-aware scoring
- Statistical anomaly detection
"""

import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler
from loguru import logger


class AnomalyScorer:
    """Scores semantic anomalies using similarity and statistical methods."""
    
    def __init__(self, threshold: float = 0.7, method: str = "cosine"):
        """
        Initialize AnomalyScorer.
        
        Args:
            threshold: Similarity threshold for anomaly detection
            method: Scoring method ("cosine", "statistical", "hybrid")
        """
        self.threshold = threshold
        self.method = method
        
        # Statistical components
        self.scaler = StandardScaler()
        self.reference_stats = None
        
        logger.info(f"Initialized AnomalyScorer with threshold: {threshold}, method: {method}")
    
    def score_anomaly(self, input_embedding: np.ndarray, 
                     reference_embeddings: List[np.ndarray],
                     context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Score anomaly for an input embedding.
        
        Args:
            input_embedding: Input embedding to score
            reference_embeddings: List of reference embeddings
            context: Additional context for scoring
            
        Returns:
            Anomaly scoring result
        """
        try:
            result = {
                "anomaly_detected": False,
                "anomaly_score": 0.0,
                "similarity_score": 0.0,
                "statistical_score": 0.0,
                "confidence": 0.0,
                "method_used": self.method,
                "threshold_used": self.threshold
            }
            
            if len(reference_embeddings) == 0:
                # No reference embeddings available
                result["anomaly_detected"] = False
                result["anomaly_score"] = 0.0
                result["similarity_score"] = 1.0
                result["confidence"] = 0.0
                return result
            
            # Calculate scores based on method
            if self.method == "cosine":
                cosine_score = self._calculate_cosine_score(input_embedding, reference_embeddings)
                result["similarity_score"] = cosine_score
                result["anomaly_score"] = 1.0 - cosine_score
                
            elif self.method == "statistical":
                stat_score = self._calculate_statistical_score(input_embedding, reference_embeddings)
                result["statistical_score"] = stat_score
                result["anomaly_score"] = stat_score
                
            elif self.method == "hybrid":
                cosine_score = self._calculate_cosine_score(input_embedding, reference_embeddings)
                stat_score = self._calculate_statistical_score(input_embedding, reference_embeddings)
                
                result["similarity_score"] = cosine_score
                result["statistical_score"] = stat_score
                result["anomaly_score"] = (cosine_score * 0.6) + (stat_score * 0.4)
                
            else:
                logger.warning(f"Unknown scoring method: {self.method}, using cosine")
                cosine_score = self._calculate_cosine_score(input_embedding, reference_embeddings)
                result["similarity_score"] = cosine_score
                result["anomaly_score"] = 1.0 - cosine_score
            
            # Apply context adjustments
            if context:
                result["anomaly_score"] = self._apply_context_adjustments(
                    result["anomaly_score"], context
                )
            
            # Determine if anomaly detected
            similarity_based = 1.0 - result["anomaly_score"]
            result["anomaly_detected"] = similarity_based < self.threshold
            
            # Calculate confidence
            result["confidence"] = self._calculate_confidence(
                result["anomaly_score"], len(reference_embeddings)
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Anomaly scoring failed: {str(e)}")
            return {
                "anomaly_detected": True,  # Assume anomalous on error
                "anomaly_score": 1.0,
                "similarity_score": 0.0,
                "statistical_score": 0.0,
                "confidence": 0.0,
                "method_used": self.method,
                "threshold_used": self.threshold,
                "error": str(e)
            }
    
    def _calculate_cosine_score(self, input_embedding: np.ndarray, 
                               reference_embeddings: List[np.ndarray]) -> float:
        """Calculate cosine similarity score."""
        try:
            if len(reference_embeddings) == 0:
                return 1.0
            
            # Stack reference embeddings
            ref_matrix = np.vstack(reference_embeddings)
            
            # Calculate cosine similarities
            similarities = cosine_similarity(
                input_embedding.reshape(1, -1), 
                ref_matrix
            )[0]
            
            # Return maximum similarity
            return float(np.max(similarities))
            
        except Exception as e:
            logger.error(f"Cosine score calculation failed: {str(e)}")
            return 0.0
    
    def _calculate_statistical_score(self, input_embedding: np.ndarray,
                                   reference_embeddings: List[np.ndarray]) -> float:
        """Calculate statistical anomaly score."""
        try:
            if len(reference_embeddings) < 3:
                # Not enough references for statistical analysis
                return 0.5
            
            # Stack reference embeddings
            ref_matrix = np.vstack(reference_embeddings)
            
            # Calculate mean and standard deviation
            ref_mean = np.mean(ref_matrix, axis=0)
            ref_std = np.std(ref_matrix, axis=0)
            
            # Avoid division by zero
            ref_std = np.where(ref_std == 0, 1e-8, ref_std)
            
            # Calculate z-scores
            z_scores = np.abs((input_embedding - ref_mean) / ref_std)
            
            # Average z-score as anomaly score (normalized to 0-1)
            avg_z_score = np.mean(z_scores)
            # Normalize z-score to 0-1 range (assuming most z-scores < 3)
            normalized_score = min(avg_z_score / 3.0, 1.0)
            
            return float(normalized_score)
            
        except Exception as e:
            logger.error(f"Statistical score calculation failed: {str(e)}")
            return 0.5
    
    def _apply_context_adjustments(self, anomaly_score: float, 
                                 context: Dict[str, Any]) -> float:
        """Apply context-based adjustments to anomaly score."""
        try:
            adjusted_score = anomaly_score
            
            # Adjust based on user history
            if "user_history" in context:
                user_history = context["user_history"]
                trust_score = user_history.get("trust_score", 0.5)
                
                # Reduce anomaly score for trusted users
                if trust_score > 0.7:
                    adjusted_score *= 0.8
                elif trust_score < 0.3:
                    adjusted_score *= 1.2
            
            # Adjust based on session context
            if "session_context" in context:
                session_ctx = context["session_context"]
                previous_anomalies = session_ctx.get("recent_anomalies", 0)
                
                # Increase score if recent anomalies detected
                if previous_anomalies > 2:
                    adjusted_score *= 1.3
                elif previous_anomalies == 0:
                    adjusted_score *= 0.9
            
            # Adjust based on input characteristics
            if "input_characteristics" in context:
                input_chars = context["input_characteristics"]
                
                # Penalize very short or very long inputs
                length = input_chars.get("length", 0)
                if length < 5 or length > 1000:
                    adjusted_score *= 1.1
                
                # Penalize inputs with special characters
                special_char_ratio = input_chars.get("special_char_ratio", 0.0)
                if special_char_ratio > 0.2:
                    adjusted_score *= 1.15
            
            # Ensure score stays within bounds
            return max(0.0, min(1.0, adjusted_score))
            
        except Exception as e:
            logger.error(f"Context adjustment failed: {str(e)}")
            return anomaly_score
    
    def _calculate_confidence(self, anomaly_score: float, 
                            reference_count: int) -> float:
        """Calculate confidence in the anomaly score."""
        try:
            # Base confidence on reference count
            if reference_count < 5:
                base_confidence = 0.3
            elif reference_count < 20:
                base_confidence = 0.6
            elif reference_count < 100:
                base_confidence = 0.8
            else:
                base_confidence = 0.9
            
            # Adjust confidence based on score extremity
            if anomaly_score < 0.1 or anomaly_score > 0.9:
                # Higher confidence for extreme scores
                confidence = min(base_confidence * 1.2, 1.0)
            elif 0.4 <= anomaly_score <= 0.6:
                # Lower confidence for ambiguous scores
                confidence = base_confidence * 0.8
            else:
                confidence = base_confidence
            
            return float(confidence)
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {str(e)}")
            return 0.5
    
    def update_reference_statistics(self, reference_embeddings: List[np.ndarray]) -> None:
        """Update statistical reference data."""
        try:
            if len(reference_embeddings) < 3:
                logger.warning("Not enough reference embeddings for statistics")
                return
            
            # Stack embeddings
            ref_matrix = np.vstack(reference_embeddings)
            
            # Calculate statistics
            self.reference_stats = {
                "mean": np.mean(ref_matrix, axis=0),
                "std": np.std(ref_matrix, axis=0),
                "min": np.min(ref_matrix, axis=0),
                "max": np.max(ref_matrix, axis=0),
                "count": len(reference_embeddings)
            }
            
            logger.info(f"Updated reference statistics with {len(reference_embeddings)} embeddings")
            
        except Exception as e:
            logger.error(f"Failed to update reference statistics: {str(e)}")
    
    def set_threshold(self, threshold: float) -> None:
        """Update anomaly detection threshold."""
        if 0.0 <= threshold <= 1.0:
            self.threshold = threshold
            logger.info(f"Updated anomaly threshold to {threshold}")
        else:
            logger.error(f"Invalid threshold value: {threshold}")
    
    def set_method(self, method: str) -> None:
        """Update scoring method."""
        valid_methods = ["cosine", "statistical", "hybrid"]
        if method in valid_methods:
            self.method = method
            logger.info(f"Updated scoring method to {method}")
        else:
            logger.error(f"Invalid method: {method}. Valid methods: {valid_methods}")
    
    def get_threshold_recommendations(self, reference_embeddings: List[np.ndarray]) -> Dict[str, float]:
        """Get recommended threshold values based on reference data."""
        try:
            if len(reference_embeddings) < 10:
                logger.warning("Not enough reference embeddings for threshold recommendations")
                return {"default": 0.7}
            
            # Calculate similarity distribution
            similarities = []
            ref_matrix = np.vstack(reference_embeddings)
            
            for i in range(len(reference_embeddings)):
                # Calculate similarity with other embeddings
                other_embeddings = np.delete(ref_matrix, i, axis=0)
                sim = cosine_similarity(
                    reference_embeddings[i].reshape(1, -1),
                    other_embeddings
                )[0]
                similarities.extend(sim)
            
            similarities = np.array(similarities)
            
            # Calculate percentiles
            p10 = np.percentile(similarities, 10)
            p25 = np.percentile(similarities, 25)
            p50 = np.percentile(similarities, 50)
            
            recommendations = {
                "strict": float(p10),  # Very strict
                "moderate": float(p25),  # Moderate
                "lenient": float(p50),  # Lenient
                "default": 0.7  # Default fallback
            }
            
            logger.info(f"Generated threshold recommendations: {recommendations}")
            return recommendations
            
        except Exception as e:
            logger.error(f"Failed to generate threshold recommendations: {str(e)}")
            return {"default": 0.7}
    
    def analyze_similarity_distribution(self, reference_embeddings: List[np.ndarray]) -> Dict[str, Any]:
        """Analyze the distribution of similarities in reference embeddings."""
        try:
            if len(reference_embeddings) < 2:
                return {"error": "Not enough reference embeddings"}
            
            # Calculate all pairwise similarities
            similarities = []
            ref_matrix = np.vstack(reference_embeddings)
            
            for i in range(len(reference_embeddings)):
                for j in range(i + 1, len(reference_embeddings)):
                    sim = cosine_similarity(
                        reference_embeddings[i].reshape(1, -1),
                        reference_embeddings[j].reshape(1, -1)
                    )[0][0]
                    similarities.append(sim)
            
            similarities = np.array(similarities)
            
            # Calculate statistics
            analysis = {
                "count": len(similarities),
                "mean": float(np.mean(similarities)),
                "std": float(np.std(similarities)),
                "min": float(np.min(similarities)),
                "max": float(np.max(similarities)),
                "median": float(np.median(similarities)),
                "percentiles": {
                    "5": float(np.percentile(similarities, 5)),
                    "25": float(np.percentile(similarities, 25)),
                    "75": float(np.percentile(similarities, 75)),
                    "95": float(np.percentile(similarities, 95))
                }
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Similarity distribution analysis failed: {str(e)}")
            return {"error": str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get scorer status."""
        return {
            "status": "active",
            "threshold": self.threshold,
            "method": self.method,
            "reference_stats_available": self.reference_stats is not None,
            "reference_count": self.reference_stats["count"] if self.reference_stats else 0
        }
    
    def reset_statistics(self) -> None:
        """Reset reference statistics."""
        self.reference_stats = None
        logger.info("Anomaly scorer statistics reset")
    
    def test_scoring(self, test_embedding: np.ndarray, 
                    reference_embeddings: List[np.ndarray]) -> Dict[str, Any]:
        """Test anomaly scoring with provided embeddings."""
        try:
            result = self.score_anomaly(test_embedding, reference_embeddings)
            
            # Add additional test information
            result["test_info"] = {
                "input_embedding_norm": float(np.linalg.norm(test_embedding)),
                "reference_count": len(reference_embeddings),
                "reference_embeddings_norm": [
                    float(np.linalg.norm(emb)) for emb in reference_embeddings[:5]  # Sample first 5
                ]
            }
            
            return result
            
        except Exception as e:
            return {"error": str(e)}
