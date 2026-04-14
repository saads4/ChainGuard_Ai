"""
Embedding Cache - Stores running average of normal input embeddings

Manages embedding cache for ChainGuardAI:
- LRU cache implementation
- Embedding storage and retrieval
- Reference embedding management
- Cache statistics and maintenance
"""

import json
import time
import hashlib
from typing import Dict, List, Optional, Any
from collections import OrderedDict
import numpy as np
from pathlib import Path
from loguru import logger


class EmbeddingCache:
    """LRU cache for text embeddings with reference management."""
    
    def __init__(self, max_size: int = 1000):
        """
        Initialize EmbeddingCache.
        
        Args:
            max_size: Maximum number of embeddings to cache
        """
        self.max_size = max_size
        self.embeddings: OrderedDict[str, np.ndarray] = OrderedDict()
        self.reference_embeddings: List[np.ndarray] = []
        self.last_hit = False
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "evictions": 0,
            "reference_count": 0
        }
        
        logger.info(f"Initialized EmbeddingCache with max size: {max_size}")
    
    def get_embedding(self, text: str) -> Optional[np.ndarray]:
        """
        Get embedding from cache.
        
        Args:
            text: Text to get embedding for
            
        Returns:
            Cached embedding or None if not found
        """
        try:
            self.stats["total_requests"] += 1
            
            # Generate cache key
            key = self._generate_key(text)
            
            # Check cache
            if key in self.embeddings:
                # Move to end (LRU update)
                embedding = self.embeddings.pop(key)
                self.embeddings[key] = embedding
                self.stats["cache_hits"] += 1
                self.last_hit = True
                
                logger.debug(f"Cache hit for text: {text[:50]}...")
                return embedding
            else:
                self.stats["cache_misses"] += 1
                self.last_hit = False
                return None
                
        except Exception as e:
            logger.error(f"Failed to get embedding from cache: {str(e)}")
            return None
    
    def add_embedding(self, text: str, embedding: np.ndarray, is_reference: bool = False) -> bool:
        """
        Add embedding to cache.
        
        Args:
            text: Text that generated the embedding
            embedding: Embedding vector
            is_reference: Whether this is a reference embedding
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            # Generate cache key
            key = self._generate_key(text)
            
            # Remove existing entry if present
            if key in self.embeddings:
                del self.embeddings[key]
            
            # Add new embedding
            self.embeddings[key] = embedding.copy()
            
            # Add to reference embeddings if specified
            if is_reference:
                self.reference_embeddings.append(embedding.copy())
                self.stats["reference_count"] += 1
            
            # Evict if over capacity
            if len(self.embeddings) > self.max_size:
                self._evict_oldest()
            
            logger.debug(f"Added embedding for text: {text[:50]}...")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add embedding to cache: {str(e)}")
            return False
    
    def get_reference_embeddings(self) -> List[np.ndarray]:
        """Get all reference embeddings."""
        return self.reference_embeddings.copy()
    
    def add_reference_embedding(self, embedding: np.ndarray) -> bool:
        """Add an embedding to the reference set."""
        try:
            self.reference_embeddings.append(embedding.copy())
            self.stats["reference_count"] += 1
            
            logger.debug(f"Added reference embedding (total: {len(self.reference_embeddings)})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add reference embedding: {str(e)}")
            return False
    
    def remove_reference_embedding(self, index: int) -> bool:
        """Remove a reference embedding by index."""
        try:
            if 0 <= index < len(self.reference_embeddings):
                del self.reference_embeddings[index]
                self.stats["reference_count"] -= 1
                
                logger.debug(f"Removed reference embedding at index {index}")
                return True
            else:
                logger.warning(f"Invalid reference embedding index: {index}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to remove reference embedding: {str(e)}")
            return False
    
    def clear_reference_embeddings(self) -> None:
        """Clear all reference embeddings."""
        self.reference_embeddings.clear()
        self.stats["reference_count"] = 0
        logger.info("Cleared all reference embeddings")
    
    def clear(self) -> None:
        """Clear all cached embeddings."""
        self.embeddings.clear()
        self.reference_embeddings.clear()
        self.stats["reference_count"] = 0
        logger.info("Cleared embedding cache")
    
    def _generate_key(self, text: str) -> str:
        """Generate cache key for text."""
        # Use SHA-256 hash of normalized text
        normalized_text = text.lower().strip()
        return hashlib.sha256(normalized_text.encode('utf-8')).hexdigest()
    
    def _evict_oldest(self) -> None:
        """Evict oldest embedding from cache."""
        try:
            if self.embeddings:
                # Remove oldest (first) item
                oldest_key = next(iter(self.embeddings))
                del self.embeddings[oldest_key]
                self.stats["evictions"] += 1
                
                logger.debug(f"Evicted oldest embedding from cache")
                
        except Exception as e:
            logger.error(f"Failed to evict oldest embedding: {str(e)}")
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information and statistics."""
        try:
            hit_rate = (
                self.stats["cache_hits"] / 
                max(self.stats["total_requests"], 1)
            )
            
            return {
                "size": len(self.embeddings),
                "max_size": self.max_size,
                "reference_count": len(self.reference_embeddings),
                "hit_rate": hit_rate,
                "statistics": self.stats.copy(),
                "utilization": len(self.embeddings) / self.max_size
            }
            
        except Exception as e:
            logger.error(f"Failed to get cache info: {str(e)}")
            return {"error": str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get cache status."""
        return {
            "status": "active",
            "size": len(self.embeddings),
            "max_size": self.max_size,
            "reference_count": len(self.reference_embeddings),
            "statistics": self.stats.copy()
        }
    
    def export_embeddings(self, file_path: str) -> bool:
        """Export cached embeddings to file."""
        try:
            export_data = {
                "embeddings": {},
                "reference_embeddings": [],
                "metadata": {
                    "export_time": time.time(),
                    "cache_size": len(self.embeddings),
                    "reference_count": len(self.reference_embeddings),
                    "max_size": self.max_size
                }
            }
            
            # Convert embeddings to serializable format
            for key, embedding in self.embeddings.items():
                export_data["embeddings"][key] = embedding.tolist()
            
            for embedding in self.reference_embeddings:
                export_data["reference_embeddings"].append(embedding.tolist())
            
            # Save to file
            with open(file_path, 'w') as f:
                json.dump(export_data, f)
            
            logger.info(f"Exported {len(self.embeddings)} embeddings to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export embeddings: {str(e)}")
            return False
    
    def import_embeddings(self, file_path: str) -> int:
        """Import embeddings from file."""
        try:
            with open(file_path, 'r') as f:
                import_data = json.load(f)
            
            imported_count = 0
            
            # Import regular embeddings
            embeddings_data = import_data.get("embeddings", {})
            for key, embedding_list in embeddings_data.items():
                embedding = np.array(embedding_list)
                self.embeddings[key] = embedding
                imported_count += 1
            
            # Import reference embeddings
            reference_data = import_data.get("reference_embeddings", [])
            for embedding_list in reference_data:
                embedding = np.array(embedding_list)
                self.reference_embeddings.append(embedding)
                imported_count += 1
            
            # Update statistics
            self.stats["reference_count"] = len(self.reference_embeddings)
            
            # Evict if over capacity
            while len(self.embeddings) > self.max_size:
                self._evict_oldest()
            
            logger.info(f"Imported {imported_count} embeddings from {file_path}")
            return imported_count
            
        except Exception as e:
            logger.error(f"Failed to import embeddings: {str(e)}")
            return 0
    
    def prune_reference_embeddings(self, max_references: int) -> int:
        """Prune reference embeddings to keep only the most recent ones."""
        try:
            if len(self.reference_embeddings) <= max_references:
                return 0
            
            # Keep only the most recent embeddings
            original_count = len(self.reference_embeddings)
            self.reference_embeddings = self.reference_embeddings[-max_references:]
            self.stats["reference_count"] = len(self.reference_embeddings)
            
            pruned_count = original_count - len(self.reference_embeddings)
            logger.info(f"Pruned {pruned_count} reference embeddings (kept {len(self.reference_embeddings)})")
            
            return pruned_count
            
        except Exception as e:
            logger.error(f"Failed to prune reference embeddings: {str(e)}")
            return 0
    
    def get_embedding_statistics(self) -> Dict[str, Any]:
        """Get statistical information about cached embeddings."""
        try:
            if not self.embeddings:
                return {
                    "count": 0,
                    "mean_norm": 0.0,
                    "std_norm": 0.0,
                    "mean_similarity": 0.0
                }
            
            # Calculate norms
            norms = [np.linalg.norm(emb) for emb in self.embeddings.values()]
            mean_norm = np.mean(norms)
            std_norm = np.std(norms)
            
            # Calculate mean similarity (sample for performance)
            embedding_list = list(self.embeddings.values())
            similarities = []
            
            if len(embedding_list) > 1:
                # Sample pairs for similarity calculation
                sample_size = min(100, len(embedding_list))
                for i in range(sample_size):
                    for j in range(i + 1, min(i + 10, len(embedding_list))):
                        from sklearn.metrics.pairwise import cosine_similarity
                        sim = cosine_similarity(
                            embedding_list[i].reshape(1, -1),
                            embedding_list[j].reshape(1, -1)
                        )[0][0]
                        similarities.append(sim)
            
            mean_similarity = np.mean(similarities) if similarities else 0.0
            
            return {
                "count": len(self.embeddings),
                "mean_norm": float(mean_norm),
                "std_norm": float(std_norm),
                "mean_similarity": float(mean_similarity),
                "sampled_similarities": len(similarities)
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate embedding statistics: {str(e)}")
            return {"error": str(e)}
    
    def reset_statistics(self) -> None:
        """Reset cache statistics."""
        self.stats = {
            "total_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "evictions": 0,
            "reference_count": len(self.reference_embeddings)
        }
        logger.info("Embedding cache statistics reset")
    
    def optimize_cache(self) -> Dict[str, Any]:
        """Optimize cache performance."""
        try:
            optimization_result = {
                "original_size": len(self.embeddings),
                "optimized_size": len(self.embeddings),
                "removed_entries": 0,
                "reference_embeddings_pruned": 0
            }
            
            # Remove duplicate embeddings
            unique_embeddings = {}
            duplicates_removed = 0
            
            for key, embedding in self.embeddings.items():
                # Check for duplicates (exact match)
                is_duplicate = False
                for existing_key, existing_embedding in unique_embeddings.items():
                    if np.array_equal(embedding, existing_embedding):
                        is_duplicate = True
                        duplicates_removed += 1
                        break
                
                if not is_duplicate:
                    unique_embeddings[key] = embedding
            
            # Update cache with unique embeddings
            self.embeddings = OrderedDict(unique_embeddings)
            optimization_result["removed_entries"] = duplicates_removed
            optimization_result["optimized_size"] = len(self.embeddings)
            
            # Prune reference embeddings if too many
            max_references = self.max_size // 2  # Keep at most half cache size as references
            if len(self.reference_embeddings) > max_references:
                pruned = self.prune_reference_embeddings(max_references)
                optimization_result["reference_embeddings_pruned"] = pruned
            
            logger.info(f"Cache optimization completed: removed {duplicates_removed} duplicates")
            return optimization_result
            
        except Exception as e:
            logger.error(f"Cache optimization failed: {str(e)}")
            return {"error": str(e)}
