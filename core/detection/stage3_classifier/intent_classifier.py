"""
Intent Classifier - ML classifier: does intent match agent's role?

Handles ML-based intent classification for ChainGuardAI:
- Intent classification model
- Role-based validation
- Confidence scoring
- Model training and management
"""

import json
import time
import pickle
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from loguru import logger


class IntentClassifier:
    """ML-based intent classifier for injection detection."""
    
    def __init__(self, model_path: str = None, confidence_threshold: float = 0.8):
        """
        Initialize IntentClassifier.
        
        Args:
            model_path: Path to trained model files
            confidence_threshold: Minimum confidence for classification
        """
        self.model_path = model_path
        self.confidence_threshold = confidence_threshold
        
        # Model components
        self.model = None
        self.vectorizer = None
        self.label_encoder = None
        self.is_trained = False
        
        # Training data
        self.training_data = []
        self.feature_names = []
        
        # Statistics
        self.stats = {
            "total_classifications": 0,
            "malicious_classifications": 0,
            "avg_confidence": 0.0,
            "model_accuracy": 0.0,
            "feature_count": 0
        }
        
        # Load or initialize model
        self._load_or_initialize_model()
        
        logger.info(f"Initialized IntentClassifier with threshold: {confidence_threshold}")
    
    def classify(self, intent: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Classify intent as malicious or benign.
        
        Args:
            intent: Parsed intent object
            context: Additional context for classification
            
        Returns:
            Classification result with confidence and prediction
        """
        try:
            start_time = time.time()
            
            result = {
                "is_malicious": False,
                "confidence": 0.0,
                "predicted_class": "benign",
                "probabilities": {},
                "features_used": 0,
                "processing_time": 0.0,
                "model_trained": self.is_trained
            }
            
            if not self.is_trained:
                # Default to benign if model not trained
                result["confidence"] = 0.5
                result["predicted_class"] = "benign"
                result["processing_time"] = time.time() - start_time
                return result
            
            # Extract features from intent
            features = self._extract_features(intent, context)
            result["features_used"] = len(features)
            
            if len(features) == 0:
                logger.warning("No features extracted for classification")
                result["confidence"] = 0.5
                result["predicted_class"] = "benign"
                result["processing_time"] = time.time() - start_time
                return result
            
            # Vectorize features
            feature_vector = self._vectorize_features(features)
            
            # Make prediction
            prediction = self.model.predict(feature_vector)[0]
            probabilities = self.model.predict_proba(feature_vector)[0]
            
            # Decode prediction
            predicted_class = self.label_encoder.inverse_transform([prediction])[0]
            
            # Get confidence for malicious class
            class_names = self.label_encoder.classes_
            malicious_idx = np.where(class_names == "malicious")[0]
            
            if len(malicious_idx) > 0:
                malicious_confidence = probabilities[malicious_idx[0]]
            else:
                malicious_confidence = 0.0
            
            # Populate result
            result["is_malicious"] = predicted_class == "malicious"
            result["confidence"] = float(malicious_confidence)
            result["predicted_class"] = predicted_class
            result["probabilities"] = {
                class_names[i]: float(probabilities[i]) 
                for i in range(len(class_names))
            }
            
            # Apply confidence threshold
            if malicious_confidence < self.confidence_threshold:
                result["is_malicious"] = False
                result["predicted_class"] = "benign"
            
            # Update statistics
            processing_time = time.time() - start_time
            result["processing_time"] = processing_time
            self._update_stats(result["is_malicious"], malicious_confidence, processing_time)
            
            logger.debug(f"Classification: {predicted_class} (confidence: {malicious_confidence:.3f})")
            return result
            
        except Exception as e:
            logger.error(f"Intent classification failed: {str(e)}")
            return self._create_error_result(str(e))
    
    def _extract_features(self, intent: Dict[str, Any], context: Optional[Dict[str, Any]]) -> List[str]:
        """Extract features from intent for classification."""
        try:
            features = []
            
            # Text-based features
            raw_input = intent.get("raw_input", "")
            if raw_input:
                features.append(raw_input.lower())
            
            # Intent type features
            intent_type = intent.get("type", "unknown")
            features.append(f"intent_type:{intent_type}")
            
            # Parameter-based features
            parameters = intent.get("parameters", {})
            for param_name, param_value in parameters.items():
                if isinstance(param_value, str):
                    features.append(f"{param_name}:{param_value.lower()}")
                elif isinstance(param_value, (int, float)):
                    features.append(f"{param_name}:{param_value}")
            
            # Entity-based features
            entities = intent.get("entities", [])
            for entity in entities:
                entity_type = entity.get("type", "unknown")
                entity_value = str(entity.get("value", "")).lower()
                features.append(f"entity_{entity_type}:{entity_value}")
            
            # Confidence-based features
            confidence = intent.get("confidence", 0.0)
            if confidence < 0.3:
                features.append("low_confidence")
            elif confidence > 0.8:
                features.append("high_confidence")
            
            # Context-based features
            if context:
                # User context
                if "user_trust_score" in context:
                    trust_score = context["user_trust_score"]
                    if trust_score < 0.3:
                        features.append("low_trust_user")
                    elif trust_score > 0.7:
                        features.append("high_trust_user")
                
                # Session context
                if "session_context" in context:
                    session_ctx = context["session_context"]
                    recent_anomalies = session_ctx.get("recent_anomalies", 0)
                    if recent_anomalies > 2:
                        features.append("recent_anomalies")
                
                # Time-based features
                if "timestamp" in context:
                    timestamp = context["timestamp"]
                    hour = time.localtime(timestamp).tm_hour
                    if hour < 6 or hour > 22:
                        features.append("unusual_hour")
            
            # Input characteristics
            if raw_input:
                # Length features
                if len(raw_input) > 1000:
                    features.append("very_long_input")
                elif len(raw_input) < 10:
                    features.append("very_short_input")
                
                # Special character features
                special_chars = sum(not c.isalnum() and c != ' ' for c in raw_input)
                special_ratio = special_chars / max(len(raw_input), 1)
                if special_ratio > 0.2:
                    features.append("high_special_chars")
                
                # Suspicious patterns
                suspicious_keywords = [
                    "ignore", "override", "bypass", "admin", "root",
                    "password", "secret", "token", "key", "system"
                ]
                for keyword in suspicious_keywords:
                    if keyword in raw_input.lower():
                        features.append(f"keyword_{keyword}")
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {str(e)}")
            return []
    
    def _vectorize_features(self, features: List[str]) -> np.ndarray:
        """Vectorize features for model input."""
        try:
            # Combine features into text
            feature_text = " ".join(features)
            
            # Transform using trained vectorizer
            return self.vectorizer.transform([feature_text])
            
        except Exception as e:
            logger.error(f"Feature vectorization failed: {str(e)}")
            return np.array([[]])
    
    def train_model(self, training_data: List[Dict[str, Any]], 
                    test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train the intent classifier.
        
        Args:
            training_data: List of training examples with intents and labels
            test_size: Fraction of data to use for testing
            
        Returns:
            Training results with accuracy and metrics
        """
        try:
            logger.info(f"Starting model training with {len(training_data)} examples")
            
            # Prepare training data
            X_texts = []
            y_labels = []
            
            for example in training_data:
                intent = example.get("intent", {})
                label = example.get("label", "benign")  # Default to benign
                context = example.get("context", {})
                
                # Extract features
                features = self._extract_features(intent, context)
                feature_text = " ".join(features)
                
                X_texts.append(feature_text)
                y_labels.append(label)
            
            if len(X_texts) < 10:
                logger.error("Not enough training data (minimum 10 examples required)")
                return {"error": "Insufficient training data"}
            
            # Split data
            split_idx = int(len(X_texts) * (1 - test_size))
            X_train, X_test = X_texts[:split_idx], X_texts[split_idx:]
            y_train, y_test = y_labels[:split_idx], y_labels[split_idx:]
            
            # Initialize vectorizer
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 2),
                stop_words='english'
            )
            
            # Fit vectorizer and transform data
            X_train_vec = self.vectorizer.fit_transform(X_train)
            X_test_vec = self.vectorizer.transform(X_test)
            
            # Initialize label encoder
            self.label_encoder = LabelEncoder()
            y_train_encoded = self.label_encoder.fit_transform(y_train)
            y_test_encoded = self.label_encoder.transform(y_test)
            
            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            
            self.model.fit(X_train_vec, y_train_encoded)
            
            # Evaluate model
            y_pred = self.model.predict(X_test_vec)
            accuracy = np.mean(y_pred == y_test_encoded)
            
            # Generate classification report
            class_names = self.label_encoder.classes_
            report = classification_report(
                y_test_encoded, y_pred, 
                target_names=class_names,
                output_dict=True
            )
            
            # Update model status
            self.is_trained = True
            self.feature_names = self.vectorizer.get_feature_names_out().tolist()
            self.stats["model_accuracy"] = accuracy
            self.stats["feature_count"] = len(self.feature_names)
            
            # Save model
            if self.model_path:
                self._save_model()
            
            training_result = {
                "success": True,
                "accuracy": float(accuracy),
                "training_examples": len(X_train),
                "test_examples": len(X_test),
                "feature_count": len(self.feature_names),
                "class_report": report,
                "feature_names": self.feature_names[:20]  # Sample of features
            }
            
            logger.info(f"Model training completed: accuracy={accuracy:.3f}")
            return training_result
            
        except Exception as e:
            logger.error(f"Model training failed: {str(e)}")
            return {"error": str(e)}
    
    def _load_or_initialize_model(self) -> None:
        """Load existing model or initialize new one."""
        try:
            if self.model_path and Path(self.model_path).exists():
                self._load_model()
            else:
                # Initialize with default model
                self.model = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42
                )
                self.vectorizer = TfidfVectorizer(
                    max_features=1000,
                    ngram_range=(1, 2),
                    stop_words='english'
                )
                self.label_encoder = LabelEncoder()
                
                logger.info("Initialized new untrained model")
                
        except Exception as e:
            logger.error(f"Model initialization failed: {str(e)}")
    
    def _save_model(self) -> bool:
        """Save trained model to files."""
        try:
            if not self.model_path:
                logger.error("No model path specified for saving")
                return False
            
            model_dir = Path(self.model_path)
            model_dir.mkdir(parents=True, exist_ok=True)
            
            # Save model components
            with open(model_dir / "model.pkl", "wb") as f:
                pickle.dump(self.model, f)
            
            with open(model_dir / "vectorizer.pkl", "wb") as f:
                pickle.dump(self.vectorizer, f)
            
            with open(model_dir / "label_encoder.pkl", "wb") as f:
                pickle.dump(self.label_encoder, f)
            
            # Save metadata
            metadata = {
                "is_trained": self.is_trained,
                "confidence_threshold": self.confidence_threshold,
                "feature_count": len(self.feature_names),
                "feature_names": self.feature_names,
                "statistics": self.stats
            }
            
            with open(model_dir / "metadata.json", "w") as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Model saved to {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model: {str(e)}")
            return False
    
    def _load_model(self) -> bool:
        """Load trained model from files."""
        try:
            model_dir = Path(self.model_path)
            
            # Load model components
            with open(model_dir / "model.pkl", "rb") as f:
                self.model = pickle.load(f)
            
            with open(model_dir / "vectorizer.pkl", "rb") as f:
                self.vectorizer = pickle.load(f)
            
            with open(model_dir / "label_encoder.pkl", "rb") as f:
                self.label_encoder = pickle.load(f)
            
            # Load metadata
            with open(model_dir / "metadata.json", "r") as f:
                metadata = json.load(f)
            
            self.is_trained = metadata.get("is_trained", False)
            self.feature_names = metadata.get("feature_names", [])
            self.stats = metadata.get("statistics", {})
            
            logger.info(f"Model loaded from {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            return False
    
    def _create_error_result(self, error: str) -> Dict[str, Any]:
        """Create error result when classification fails."""
        return {
            "is_malicious": True,  # Assume malicious on error
            "confidence": 1.0,
            "predicted_class": "malicious",
            "probabilities": {},
            "features_used": 0,
            "processing_time": 0.0,
            "model_trained": self.is_trained,
            "error": error
        }
    
    def _update_stats(self, is_malicious: bool, confidence: float, processing_time: float) -> None:
        """Update classification statistics."""
        try:
            self.stats["total_classifications"] += 1
            
            if is_malicious:
                self.stats["malicious_classifications"] += 1
            
            # Update average confidence
            current_avg = self.stats["avg_confidence"]
            count = self.stats["total_classifications"]
            self.stats["avg_confidence"] = ((current_avg * (count - 1)) + confidence) / count
            
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")
    
    def set_confidence_threshold(self, threshold: float) -> None:
        """Update confidence threshold for classification."""
        if 0.0 <= threshold <= 1.0:
            self.confidence_threshold = threshold
            logger.info(f"Updated confidence threshold to {threshold}")
        else:
            logger.error(f"Invalid threshold value: {threshold}")
    
    def get_feature_importance(self, top_n: int = 20) -> Dict[str, float]:
        """Get feature importance from trained model."""
        try:
            if not self.is_trained or not hasattr(self.model, 'feature_importances_'):
                return {}
            
            importances = self.model.feature_importances_
            feature_names = self.vectorizer.get_feature_names_out()
            
            # Sort by importance
            indices = np.argsort(importances)[::-1][:top_n]
            
            importance_dict = {
                feature_names[i]: float(importances[i]) 
                for i in indices
            }
            
            return importance_dict
            
        except Exception as e:
            logger.error(f"Failed to get feature importance: {str(e)}")
            return {}
    
    def get_status(self) -> Dict[str, Any]:
        """Get classifier status."""
        return {
            "status": "active",
            "is_trained": self.is_trained,
            "confidence_threshold": self.confidence_threshold,
            "model_type": "RandomForest",
            "feature_count": len(self.feature_names),
            "statistics": self.stats.copy(),
            "classes": self.label_encoder.classes_.tolist() if self.label_encoder else []
        }
    
    def reset_statistics(self) -> None:
        """Reset classification statistics."""
        self.stats = {
            "total_classifications": 0,
            "malicious_classifications": 0,
            "avg_confidence": 0.0,
            "model_accuracy": self.stats.get("model_accuracy", 0.0),
            "feature_count": self.stats.get("feature_count", 0)
        }
        logger.info("Intent classifier statistics reset")
    
    def add_training_example(self, intent: Dict[str, Any], label: str, 
                           context: Optional[Dict[str, Any]] = None) -> bool:
        """Add a training example."""
        try:
            example = {
                "intent": intent,
                "label": label,
                "context": context or {}
            }
            
            self.training_data.append(example)
            logger.debug(f"Added training example with label: {label}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add training example: {str(e)}")
            return False
    
    def get_training_data_info(self) -> Dict[str, Any]:
        """Get information about training data."""
        if not self.training_data:
            return {"count": 0, "labels": [], "examples": []}
        
        labels = [example["label"] for example in self.training_data]
        label_counts = {}
        for label in labels:
            label_counts[label] = label_counts.get(label, 0) + 1
        
        return {
            "count": len(self.training_data),
            "labels": list(set(labels)),
            "label_distribution": label_counts,
            "sample_examples": self.training_data[:3]  # First 3 examples
        }
