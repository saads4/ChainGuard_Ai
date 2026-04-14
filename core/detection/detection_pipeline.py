"""
Detection Pipeline - Orchestrates all detectors; returns final risk score

Coordinates the multi-stage injection detection for ChainGuardAI:
- Stage 1: Regex pattern matching
- Stage 2: Embedding-based semantic analysis  
- Stage 3: ML classifier intent validation
- Risk aggregation and final scoring
"""

import time
from typing import Dict, Any, List, Optional
from loguru import logger
from .stage1_regex.regex_detector import RegexDetector
from .stage2_embedding.embedding_detector import EmbeddingDetector
from .stage3_classifier.intent_classifier import IntentClassifier
from .risk_aggregator import RiskAggregator


class DetectionPipeline:
    """Orchestrates multi-stage injection detection."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize DetectionPipeline.
        
        Args:
            config: Configuration dictionary for detection pipeline
        """
        self.config = config or self._get_default_config()
        
        # Initialize detectors
        self.regex_detector = RegexDetector(
            patterns_file=self.config.get("regex_patterns_file"),
            case_sensitive=self.config.get("regex_case_sensitive", False)
        )
        
        self.embedding_detector = EmbeddingDetector(
            model_name=self.config.get("embedding_model", "all-MiniLM-L6-v2"),
            cache_size=self.config.get("embedding_cache_size", 1000),
            similarity_threshold=self.config.get("embedding_similarity_threshold", 0.7)
        )
        
        self.intent_classifier = IntentClassifier(
            model_path=self.config.get("classifier_model_path"),
            confidence_threshold=self.config.get("classifier_confidence_threshold", 0.8)
        )
        
        # Initialize risk aggregator
        self.risk_aggregator = RiskAggregator(
            weights=self.config.get("risk_weights", {
                "regex": 0.3,
                "embedding": 0.4,
                "classifier": 0.3
            }),
            thresholds=self.config.get("risk_thresholds", {
                "low": 0.3,
                "medium": 0.6,
                "high": 0.8
            })
        )
        
        # Pipeline statistics
        self.stats = {
            "total_detections": 0,
            "regex_detections": 0,
            "embedding_detections": 0,
            "classifier_detections": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
            "avg_processing_time": 0.0
        }
        
        logger.info("Initialized DetectionPipeline")
    
    def detect_injection(self, input_text: str, intent: Optional[Dict[str, Any]] = None,
                        context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run full injection detection pipeline.
        
        Args:
            input_text: Input text to analyze
            intent: Parsed intent object (optional)
            context: Additional context (optional)
            
        Returns:
            Complete detection result with risk assessment
        """
        try:
            start_time = time.time()
            
            # Initialize result structure
            result = {
                "input_text": input_text,
                "intent": intent,
                "context": context,
                "timestamp": time.time(),
                "stages": {},
                "final_risk_score": 0.0,
                "risk_level": "LOW",
                "detection_summary": {},
                "processing_time": 0.0,
                "recommendations": []
            }
            
            # Stage 1: Regex Detection
            stage1_result = self._run_stage1_regex(input_text)
            result["stages"]["regex"] = stage1_result
            
            # Stage 2: Embedding Detection
            stage2_result = self._run_stage2_embedding(input_text, context)
            result["stages"]["embedding"] = stage2_result
            
            # Stage 3: Intent Classification
            stage3_result = self._run_stage3_classifier(intent or {}, context)
            result["stages"]["classifier"] = stage3_result
            
            # Risk Aggregation
            risk_result = self.risk_aggregator.aggregate_risk(
                stage1_result,
                stage2_result, 
                stage3_result
            )
            result["final_risk_score"] = risk_result["score"]
            result["risk_level"] = risk_result["level"]
            result["detection_summary"] = risk_result["summary"]
            
            # Generate recommendations
            result["recommendations"] = self._generate_recommendations(result)
            
            # Calculate processing time
            result["processing_time"] = time.time() - start_time
            
            # Update statistics
            self._update_statistics(result)
            
            # Log results
            self._log_detection_result(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Detection pipeline failed: {str(e)}")
            return self._create_error_result(input_text, intent, context, str(e))
    
    def _run_stage1_regex(self, input_text: str) -> Dict[str, Any]:
        """Run Stage 1: Regex pattern matching."""
        try:
            start_time = time.time()
            
            # Run regex detection
            regex_result = self.regex_detector.detect(input_text)
            
            # Add timing
            regex_result["processing_time"] = time.time() - start_time
            
            logger.debug(f"Stage 1 (Regex) completed: {regex_result['matches_found']} matches")
            return regex_result
            
        except Exception as e:
            logger.error(f"Stage 1 (Regex) failed: {str(e)}")
            return {
                "matches_found": 0,
                "matches": [],
                "risk_score": 0.0,
                "processing_time": 0.0,
                "error": str(e)
            }
    
    def _run_stage2_embedding(self, input_text: str, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Run Stage 2: Embedding-based semantic analysis."""
        try:
            start_time = time.time()
            
            # Run embedding detection
            embedding_result = self.embedding_detector.detect(input_text, context)
            
            # Add timing
            embedding_result["processing_time"] = time.time() - start_time
            
            logger.debug(f"Stage 2 (Embedding) completed: similarity={embedding_result.get('similarity_score', 0):.3f}")
            return embedding_result
            
        except Exception as e:
            logger.error(f"Stage 2 (Embedding) failed: {str(e)}")
            return {
                "similarity_score": 0.0,
                "anomaly_detected": False,
                "processing_time": 0.0,
                "error": str(e)
            }
    
    def _run_stage3_classifier(self, intent: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Run Stage 3: ML-based intent classification."""
        try:
            start_time = time.time()
            
            # Run intent classification
            classifier_result = self.intent_classifier.classify(intent, context)
            
            # Add timing
            classifier_result["processing_time"] = time.time() - start_time
            
            logger.debug(f"Stage 3 (Classifier) completed: confidence={classifier_result.get('confidence', 0):.3f}")
            return classifier_result
            
        except Exception as e:
            logger.error(f"Stage 3 (Classifier) failed: {str(e)}")
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "predicted_class": "unknown",
                "processing_time": 0.0,
                "error": str(e)
            }
    
    def _generate_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on detection results."""
        recommendations = []
        
        risk_level = result["risk_level"]
        stages = result["stages"]
        
        # High risk recommendations
        if risk_level == "HIGH":
            recommendations.append("BLOCK: High injection risk detected")
            recommendations.append("Review input for malicious patterns")
            recommendations.append("Consider escalating to human review")
        
        # Medium risk recommendations
        elif risk_level == "MEDIUM":
            recommendations.append("CAUTION: Medium injection risk detected")
            recommendations.append("Apply additional validation")
            recommendations.append("Monitor for suspicious behavior")
        
        # Low risk recommendations
        else:
            recommendations.append("PROCEED: Low injection risk detected")
            recommendations.append("Continue with standard processing")
        
        # Stage-specific recommendations
        if stages.get("regex", {}).get("matches_found", 0) > 0:
            recommendations.append("Regex patterns matched - review specific matches")
        
        if stages.get("embedding", {}).get("anomaly_detected", False):
            recommendations.append("Semantic anomaly detected - unusual language patterns")
        
        if stages.get("classifier", {}).get("is_malicious", False):
            recommendations.append("ML classifier flagged as malicious")
        
        # Performance recommendations
        total_time = result["processing_time"]
        if total_time > 5.0:
            recommendations.append("Processing time high - consider optimization")
        
        return recommendations
    
    def _update_statistics(self, result: Dict[str, Any]) -> None:
        """Update pipeline statistics."""
        try:
            self.stats["total_detections"] += 1
            
            # Update stage-specific stats
            if result["stages"]["regex"].get("matches_found", 0) > 0:
                self.stats["regex_detections"] += 1
            
            if result["stages"]["embedding"].get("anomaly_detected", False):
                self.stats["embedding_detections"] += 1
            
            if result["stages"]["classifier"].get("is_malicious", False):
                self.stats["classifier_detections"] += 1
            
            # Update risk level stats
            risk_level = result["risk_level"]
            if risk_level == "HIGH":
                self.stats["high_risk_count"] += 1
            elif risk_level == "MEDIUM":
                self.stats["medium_risk_count"] += 1
            else:
                self.stats["low_risk_count"] += 1
            
            # Update average processing time
            current_avg = self.stats["avg_processing_time"]
            new_time = result["processing_time"]
            count = self.stats["total_detections"]
            self.stats["avg_processing_time"] = ((current_avg * (count - 1)) + new_time) / count
            
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")
    
    def _log_detection_result(self, result: Dict[str, Any]) -> None:
        """Log detection results."""
        try:
            risk_level = result["risk_level"]
            risk_score = result["final_risk_score"]
            processing_time = result["processing_time"]
            
            # Log summary
            logger.info(
                f"Detection completed - Risk: {risk_level} ({risk_score:.3f}), "
                f"Time: {processing_time:.3f}s"
            )
            
            # Log stage details if high risk
            if risk_level == "HIGH":
                stages = result["stages"]
                logger.warning(
                    f"High risk detection - Regex: {stages['regex'].get('matches_found', 0)}, "
                    f"Embedding: {stages['embedding'].get('anomaly_detected', False)}, "
                    f"Classifier: {stages['classifier'].get('is_malicious', False)}"
                )
                
        except Exception as e:
            logger.error(f"Failed to log detection result: {str(e)}")
    
    def _create_error_result(self, input_text: str, intent: Optional[Dict[str, Any]],
                            context: Optional[Dict[str, Any]], error: str) -> Dict[str, Any]:
        """Create error result when pipeline fails."""
        return {
            "input_text": input_text,
            "intent": intent,
            "context": context,
            "timestamp": time.time(),
            "stages": {
                "regex": {"error": error},
                "embedding": {"error": error},
                "classifier": {"error": error}
            },
            "final_risk_score": 1.0,  # Max risk on error
            "risk_level": "HIGH",
            "detection_summary": {"error": error},
            "processing_time": 0.0,
            "recommendations": ["BLOCK: Pipeline error - treat as high risk"],
            "error": error
        }
    
    def batch_detect(self, inputs: List[str], intents: Optional[List[Dict[str, Any]]] = None,
                    contexts: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Run detection on multiple inputs in batch.
        
        Args:
            inputs: List of input texts
            intents: List of intent objects (optional)
            contexts: List of context objects (optional)
            
        Returns:
            List of detection results
        """
        try:
            results = []
            
            for i, input_text in enumerate(inputs):
                intent = intents[i] if intents and i < len(intents) else None
                context = contexts[i] if contexts and i < len(contexts) else None
                
                result = self.detect_injection(input_text, intent, context)
                results.append(result)
            
            logger.info(f"Batch detection completed: {len(results)} inputs processed")
            return results
            
        except Exception as e:
            logger.error(f"Batch detection failed: {str(e)}")
            return []
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current pipeline status and statistics."""
        try:
            return {
                "status": "active",
                "configuration": self.config,
                "detectors": {
                    "regex": self.regex_detector.get_status(),
                    "embedding": self.embedding_detector.get_status(),
                    "classifier": self.intent_classifier.get_status()
                },
                "risk_aggregator": self.risk_aggregator.get_status(),
                "statistics": self.stats.copy(),
                "performance": {
                    "avg_processing_time": self.stats["avg_processing_time"],
                    "total_detections": self.stats["total_detections"]
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get pipeline status: {str(e)}")
            return {"status": "error", "error": str(e)}
    
    def update_configuration(self, new_config: Dict[str, Any]) -> bool:
        """Update pipeline configuration."""
        try:
            # Update config
            self.config.update(new_config)
            
            # Update detectors if needed
            if "regex_patterns_file" in new_config:
                self.regex_detector.load_patterns(new_config["regex_patterns_file"])
            
            if "embedding_similarity_threshold" in new_config:
                self.embedding_detector.set_similarity_threshold(new_config["embedding_similarity_threshold"])
            
            if "classifier_confidence_threshold" in new_config:
                self.intent_classifier.set_confidence_threshold(new_config["classifier_confidence_threshold"])
            
            # Update risk aggregator
            if "risk_weights" in new_config:
                self.risk_aggregator.set_weights(new_config["risk_weights"])
            
            if "risk_thresholds" in new_config:
                self.risk_aggregator.set_thresholds(new_config["risk_thresholds"])
            
            logger.info("Pipeline configuration updated")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update configuration: {str(e)}")
            return False
    
    def reset_statistics(self) -> None:
        """Reset pipeline statistics."""
        self.stats = {
            "total_detections": 0,
            "regex_detections": 0,
            "embedding_detections": 0,
            "classifier_detections": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
            "avg_processing_time": 0.0
        }
        logger.info("Pipeline statistics reset")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "regex_patterns_file": "./core/detection/stage1_regex/patterns.json",
            "regex_case_sensitive": False,
            "embedding_model": "all-MiniLM-L6-v2",
            "embedding_cache_size": 1000,
            "embedding_similarity_threshold": 0.7,
            "classifier_model_path": "./core/detection/stage3_classifier/classifier_model",
            "classifier_confidence_threshold": 0.8,
            "risk_weights": {
                "regex": 0.3,
                "embedding": 0.4,
                "classifier": 0.3
            },
            "risk_thresholds": {
                "low": 0.3,
                "medium": 0.6,
                "high": 0.8
            }
        }
