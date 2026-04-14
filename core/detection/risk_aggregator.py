"""
Risk Aggregator - Combines stage scores into final risk level (LOW/MED/HIGH)

Combines detection results from all stages for ChainGuardAI:
- Weighted risk score calculation
- Risk level determination
- Stage result aggregation
- Risk threshold management
"""

import time
from typing import Dict, Any, List, Optional
from loguru import logger


class RiskAggregator:
    """Aggregates risk scores from multiple detection stages."""
    
    def __init__(self, weights: Dict[str, float] = None, thresholds: Dict[str, float] = None):
        """
        Initialize RiskAggregator.
        
        Args:
            weights: Weights for each detection stage
            thresholds: Risk level thresholds
        """
        self.weights = weights or {
            "regex": 0.3,
            "embedding": 0.4,
            "classifier": 0.3
        }
        
        self.thresholds = thresholds or {
            "low": 0.3,
            "medium": 0.6,
            "high": 0.8
        }
        
        # Validate weights sum to 1.0
        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            logger.warning(f"Weights sum to {total_weight}, normalizing to 1.0")
            for key in self.weights:
                self.weights[key] /= total_weight
        
        # Statistics
        self.stats = {
            "total_aggregations": 0,
            "risk_levels": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
            "avg_risk_score": 0.0,
            "stage_contributions": {
                "regex": {"total": 0.0, "count": 0},
                "embedding": {"total": 0.0, "count": 0},
                "classifier": {"total": 0.0, "count": 0}
            }
        }
        
        logger.info(f"Initialized RiskAggregator with weights: {self.weights}")
    
    def aggregate_risk(self, stage1_result: Dict[str, Any], stage2_result: Dict[str, Any],
                      stage3_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aggregate risk scores from all detection stages.
        
        Args:
            stage1_result: Regex detection result
            stage2_result: Embedding detection result
            stage3_result: Classifier detection result
            
        Returns:
            Aggregated risk result
        """
        try:
            # Extract risk scores from each stage
            stage_scores = {
                "regex": self._extract_stage_score(stage1_result),
                "embedding": self._extract_stage_score(stage2_result),
                "classifier": self._extract_stage_score(stage3_result)
            }
            
            # Calculate weighted risk score
            weighted_score = self._calculate_weighted_score(stage_scores)
            
            # Determine risk level
            risk_level = self._determine_risk_level(weighted_score)
            
            # Create summary
            summary = self._create_summary(stage_scores, weighted_score, risk_level)
            
            # Update statistics
            self._update_stats(weighted_score, risk_level, stage_scores)
            
            result = {
                "score": weighted_score,
                "level": risk_level,
                "summary": summary,
                "stage_scores": stage_scores,
                "weights": self.weights.copy(),
                "thresholds": self.thresholds.copy(),
                "aggregation_timestamp": time.time()
            }
            
            logger.debug(f"Risk aggregation: {weighted_score:.3f} -> {risk_level}")
            return result
            
        except Exception as e:
            logger.error(f"Risk aggregation failed: {str(e)}")
            return self._create_error_result(str(e))
    
    def _extract_stage_score(self, stage_result: Dict[str, Any]) -> float:
        """Extract risk score from stage result."""
        try:
            # Handle different stage result formats
            if "risk_score" in stage_result:
                return float(stage_result["risk_score"])
            elif "anomaly_score" in stage_result:
                return float(stage_result["anomaly_score"])
            elif stage_result.get("is_malicious", False):
                # For classifier, use confidence if malicious
                confidence = stage_result.get("confidence", 0.0)
                return float(confidence)
            else:
                # Default to low risk
                return 0.0
                
        except Exception as e:
            logger.error(f"Failed to extract stage score: {str(e)}")
            return 0.0
    
    def _calculate_weighted_score(self, stage_scores: Dict[str, float]) -> float:
        """Calculate weighted risk score from stage scores."""
        try:
            weighted_score = 0.0
            
            for stage, score in stage_scores.items():
                weight = self.weights.get(stage, 0.0)
                weighted_score += score * weight
                
                # Update stage contribution statistics
                if stage in self.stats["stage_contributions"]:
                    self.stats["stage_contributions"][stage]["total"] += score
                    self.stats["stage_contributions"][stage]["count"] += 1
            
            return float(weighted_score)
            
        except Exception as e:
            logger.error(f"Weighted score calculation failed: {str(e)}")
            return 0.0
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        try:
            if score >= self.thresholds["high"]:
                return "HIGH"
            elif score >= self.thresholds["medium"]:
                return "MEDIUM"
            else:
                return "LOW"
                
        except Exception as e:
            logger.error(f"Risk level determination failed: {str(e)}")
            return "MEDIUM"  # Default to medium on error
    
    def _create_summary(self, stage_scores: Dict[str, float], weighted_score: float, 
                       risk_level: str) -> Dict[str, Any]:
        """Create aggregation summary."""
        try:
            summary = {
                "final_score": weighted_score,
                "risk_level": risk_level,
                "stage_breakdown": {},
                "dominant_stage": None,
                "risk_factors": [],
                "confidence": self._calculate_aggregation_confidence(stage_scores)
            }
            
            # Stage breakdown
            for stage, score in stage_scores.items():
                weight = self.weights.get(stage, 0.0)
                contribution = score * weight
                
                summary["stage_breakdown"][stage] = {
                    "score": score,
                    "weight": weight,
                    "contribution": contribution
                }
                
                # Identify dominant stage
                if summary["dominant_stage"] is None or contribution > summary["stage_breakdown"][summary["dominant_stage"]]["contribution"]:
                    summary["dominant_stage"] = stage
            
            # Risk factors
            for stage, score in stage_scores.items():
                if score > 0.5:
                    summary["risk_factors"].append(f"High {stage} risk detected")
                elif score > 0.3:
                    summary["risk_factors"].append(f"Moderate {stage} risk detected")
            
            if not summary["risk_factors"]:
                summary["risk_factors"].append("Low overall risk")
            
            return summary
            
        except Exception as e:
            logger.error(f"Summary creation failed: {str(e)}")
            return {"error": str(e)}
    
    def _calculate_aggregation_confidence(self, stage_scores: Dict[str, float]) -> float:
        """Calculate confidence in the aggregated risk score."""
        try:
            # Count non-zero stages
            non_zero_stages = sum(1 for score in stage_scores.values() if score > 0)
            
            # Base confidence on number of contributing stages
            if non_zero_stages == 3:
                base_confidence = 0.9
            elif non_zero_stages == 2:
                base_confidence = 0.7
            elif non_zero_stages == 1:
                base_confidence = 0.5
            else:
                base_confidence = 0.3
            
            # Adjust based on score variance
            scores = list(stage_scores.values())
            if len(scores) > 1:
                variance = max(scores) - min(scores)
                if variance > 0.5:
                    base_confidence *= 0.8  # Lower confidence for inconsistent results
                elif variance < 0.1:
                    base_confidence *= 1.1  # Higher confidence for consistent results
            
            return min(base_confidence, 1.0)
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {str(e)}")
            return 0.5
    
    def _update_stats(self, weighted_score: float, risk_level: str, 
                     stage_scores: Dict[str, float]) -> None:
        """Update aggregation statistics."""
        try:
            self.stats["total_aggregations"] += 1
            
            # Update risk level counts
            self.stats["risk_levels"][risk_level] += 1
            
            # Update average risk score
            current_avg = self.stats["avg_risk_score"]
            count = self.stats["total_aggregations"]
            self.stats["avg_risk_score"] = ((current_avg * (count - 1)) + weighted_score) / count
            
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")
    
    def _create_error_result(self, error: str) -> Dict[str, Any]:
        """Create error result when aggregation fails."""
        return {
            "score": 1.0,  # Max risk on error
            "level": "HIGH",
            "summary": {"error": error},
            "stage_scores": {"regex": 0.0, "embedding": 0.0, "classifier": 0.0},
            "weights": self.weights.copy(),
            "thresholds": self.thresholds.copy(),
            "aggregation_timestamp": time.time(),
            "error": error
        }
    
    def set_weights(self, weights: Dict[str, float]) -> bool:
        """Update stage weights."""
        try:
            # Validate weights
            total_weight = sum(weights.values())
            if abs(total_weight - 1.0) > 0.01:
                logger.error(f"Weights must sum to 1.0, got {total_weight}")
                return False
            
            # Validate stage names
            valid_stages = {"regex", "embedding", "classifier"}
            for stage in weights:
                if stage not in valid_stages:
                    logger.error(f"Invalid stage name: {stage}")
                    return False
            
            self.weights = weights.copy()
            logger.info(f"Updated weights: {self.weights}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set weights: {str(e)}")
            return False
    
    def set_thresholds(self, thresholds: Dict[str, float]) -> bool:
        """Update risk level thresholds."""
        try:
            # Validate thresholds
            if not (0 <= thresholds.get("low", 0) <= thresholds.get("medium", 0) <= thresholds.get("high", 0) <= 1.0):
                logger.error("Thresholds must be in ascending order: low <= medium <= high <= 1.0")
                return False
            
            self.thresholds = thresholds.copy()
            logger.info(f"Updated thresholds: {self.thresholds}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set thresholds: {str(e)}")
            return False
    
    def get_stage_contributions(self) -> Dict[str, Dict[str, float]]:
        """Get contribution statistics for each stage."""
        try:
            contributions = {}
            
            for stage, stats in self.stats["stage_contributions"].items():
                if stats["count"] > 0:
                    avg_contribution = stats["total"] / stats["count"]
                    contributions[stage] = {
                        "average_score": avg_contribution,
                        "total_contributions": stats["total"],
                        "contribution_count": stats["count"]
                    }
                else:
                    contributions[stage] = {
                        "average_score": 0.0,
                        "total_contributions": 0.0,
                        "contribution_count": 0
                    }
            
            return contributions
            
        except Exception as e:
            logger.error(f"Failed to get stage contributions: {str(e)}")
            return {}
    
    def get_risk_distribution(self) -> Dict[str, Any]:
        """Get distribution of risk levels."""
        try:
            total = self.stats["total_aggregations"]
            
            if total == 0:
                return {
                    "total": 0,
                    "percentages": {"LOW": 0.0, "MEDIUM": 0.0, "HIGH": 0.0},
                    "counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
                }
            
            percentages = {
                level: (count / total) * 100 
                for level, count in self.stats["risk_levels"].items()
            }
            
            return {
                "total": total,
                "percentages": percentages,
                "counts": self.stats["risk_levels"].copy()
            }
            
        except Exception as e:
            logger.error(f"Failed to get risk distribution: {str(e)}")
            return {}
    
    def get_status(self) -> Dict[str, Any]:
        """Get aggregator status."""
        return {
            "status": "active",
            "weights": self.weights.copy(),
            "thresholds": self.thresholds.copy(),
            "statistics": self.stats.copy(),
            "stage_contributions": self.get_stage_contributions(),
            "risk_distribution": self.get_risk_distribution()
        }
    
    def reset_statistics(self) -> None:
        """Reset aggregation statistics."""
        self.stats = {
            "total_aggregations": 0,
            "risk_levels": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
            "avg_risk_score": 0.0,
            "stage_contributions": {
                "regex": {"total": 0.0, "count": 0},
                "embedding": {"total": 0.0, "count": 0},
                "classifier": {"total": 0.0, "count": 0}
            }
        }
        logger.info("Risk aggregator statistics reset")
    
    def analyze_risk_trends(self, window_size: int = 100) -> Dict[str, Any]:
        """Analyze recent risk trends (would need historical data storage)."""
        try:
            # This would require storing recent aggregation results
            # For now, return current statistics as trend analysis
            current_stats = self.stats.copy()
            
            return {
                "window_size": window_size,
                "current_avg_risk": current_stats["avg_risk_score"],
                "risk_level_distribution": current_stats["risk_levels"],
                "stage_performance": self.get_stage_contributions(),
                "trend_analysis": "Historical trend analysis requires data storage implementation"
            }
            
        except Exception as e:
            logger.error(f"Risk trend analysis failed: {str(e)}")
            return {"error": str(e)}
