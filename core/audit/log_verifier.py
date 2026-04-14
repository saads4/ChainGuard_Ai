"""
Log Verifier - Verifies chain integrity (detects tampering)

Handles audit log verification for ChainGuardAI:
- Chain integrity verification
- Tampering detection
- Signature validation
- Comprehensive audit reporting
"""

import json
import time
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from loguru import logger
from .hash_chain import HashChain
from .log_signer import LogSigner


class LogVerifier:
    """Verifies the integrity and authenticity of audit logs."""
    
    def __init__(self, log_file_path: str = "./core/audit/logs/audit_chain.jsonl",
                 public_key_path: str = "./keys/audit_public_key.pem"):
        """
        Initialize LogVerifier.
        
        Args:
            log_file_path: Path to the audit log file
            public_key_path: Path to public key for signature verification
        """
        self.log_file_path = Path(log_file_path)
        self.public_key_path = public_key_path
        
        # Initialize components
        self.hash_chain = HashChain()
        self.log_signer = LogSigner(public_key_path, is_private=False)
        
        # Verification configuration
        self.config = {
            "verify_signatures": True,
            "verify_hash_chain": True,
            "strict_mode": False,  # Fail on any issue if True
            "max_verification_time": 300,  # 5 minutes
            "batch_size": 1000  # Process in batches for large logs
        }
        
        # Statistics
        self.stats = {
            "total_verifications": 0,
            "successful_verifications": 0,
            "failed_verifications": 0,
            "tampering_detected": 0,
            "signature_failures": 0,
            "hash_chain_failures": 0,
            "avg_verification_time": 0.0
        }
        
        logger.info(f"Initialized LogVerifier for {log_file_path}")
    
    def verify_log(self, check_signatures: bool = None, check_hash_chain: bool = None) -> Dict[str, Any]:
        """
        Verify the entire audit log.
        
        Args:
            check_signatures: Whether to verify signatures
            check_hash_chain: Whether to verify hash chain
            
        Returns:
            Comprehensive verification result
        """
        try:
            start_time = time.time()
            
            # Use config defaults if not specified
            check_signatures = check_signatures if check_signatures is not None else self.config["verify_signatures"]
            check_hash_chain = check_hash_chain if check_hash_chain is not None else self.config["verify_hash_chain"]
            
            result = {
                "verified": False,
                "verification_time": 0.0,
                "issues": [],
                "warnings": [],
                "statistics": {},
                "detailed_results": {},
                "tampering_detected": False,
                "signature_status": "not_checked",
                "hash_chain_status": "not_checked"
            }
            
            # Check if log file exists
            if not self.log_file_path.exists():
                result["issues"].append("Log file does not exist")
                self.stats["failed_verifications"] += 1
                return result
            
            # Load all entries
            entries = self._load_all_entries()
            if not entries:
                result["issues"].append("No entries found in log file")
                self.stats["failed_verifications"] += 1
                return result
            
            # Verify hash chain
            if check_hash_chain:
                hash_result = self._verify_hash_chain(entries)
                result["detailed_results"]["hash_chain"] = hash_result
                result["hash_chain_status"] = "passed" if hash_result["verified"] else "failed"
                
                if not hash_result["verified"]:
                    result["tampering_detected"] = True
                    result["issues"].extend(hash_result["issues"])
                    self.stats["hash_chain_failures"] += 1
                    if self.config["strict_mode"]:
                        self.stats["failed_verifications"] += 1
                        result["verification_time"] = time.time() - start_time
                        return result
                else:
                    result["warnings"].extend(hash_result.get("warnings", []))
            
            # Verify signatures
            if check_signatures:
                signature_result = self._verify_signatures(entries)
                result["detailed_results"]["signatures"] = signature_result
                result["signature_status"] = "passed" if signature_result["verified"] else "failed"
                
                if not signature_result["verified"]:
                    result["issues"].extend(signature_result["issues"])
                    self.stats["signature_failures"] += 1
                    if self.config["strict_mode"]:
                        self.stats["failed_verifications"] += 1
                        result["verification_time"] = time.time() - start_time
                        return result
                else:
                    result["warnings"].extend(signature_result.get("warnings", []))
            
            # Additional checks
            additional_result = self._perform_additional_checks(entries)
            result["detailed_results"]["additional"] = additional_result
            result["issues"].extend(additional_result.get("issues", []))
            result["warnings"].extend(additional_result.get("warnings", []))
            
            # Final determination
            result["verified"] = len(result["issues"]) == 0
            result["verification_time"] = time.time() - start_time
            
            # Update statistics
            self._update_verification_stats(result)
            
            # Create statistics summary
            result["statistics"] = {
                "total_entries": len(entries),
                "verified_entries": len(entries) - len(result["issues"]),
                "verification_time": result["verification_time"],
                "checks_performed": ["hash_chain"] if check_hash_chain else [] + ["signatures"] if check_signatures else []
            }
            
            logger.info(f"Log verification completed: {'VERIFIED' if result['verified'] else 'FAILED'}")
            return result
            
        except Exception as e:
            logger.error(f"Log verification failed: {str(e)}")
            self.stats["failed_verifications"] += 1
            return {
                "verified": False,
                "verification_time": 0.0,
                "issues": [f"Verification error: {str(e)}"],
                "warnings": [],
                "tampering_detected": True,
                "statistics": {},
                "detailed_results": {}
            }
    
    def _load_all_entries(self) -> List[Dict[str, Any]]:
        """Load all entries from the log file."""
        try:
            entries = []
            
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        entry = json.loads(line.strip())
                        entries.append(entry)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse line {line_num}: {str(e)}")
                        continue
            
            logger.info(f"Loaded {len(entries)} entries from log file")
            return entries
            
        except Exception as e:
            logger.error(f"Failed to load entries: {str(e)}")
            return []
    
    def _verify_hash_chain(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify the hash chain integrity."""
        try:
            start_time = time.time()
            
            result = {
                "verified": False,
                "issues": [],
                "warnings": [],
                "verification_time": 0.0,
                "entries_checked": len(entries),
                "broken_links": []
            }
            
            # Use hash chain verifier
            is_valid, issues = self.hash_chain.verify_chain(entries)
            
            result["verified"] = is_valid
            result["issues"] = issues
            
            # Find broken links for detailed reporting
            for i, entry in enumerate(entries):
                if i == 0:
                    continue
                
                previous_hash = entry.get("previous_hash", "")
                expected_previous = entries[i-1].get("entry_hash", "")
                
                if previous_hash != expected_previous:
                    result["broken_links"].append({
                        "entry_index": i,
                        "entry_id": entry.get("entry_id", "unknown"),
                        "expected_previous": expected_previous,
                        "actual_previous": previous_hash
                    })
            
            result["verification_time"] = time.time() - start_time
            
            if is_valid:
                logger.info(f"Hash chain verification passed: {len(entries)} entries")
            else:
                logger.warning(f"Hash chain verification failed: {len(issues)} issues")
                self.stats["tampering_detected"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Hash chain verification failed: {str(e)}")
            return {
                "verified": False,
                "issues": [f"Hash chain verification error: {str(e)}"],
                "warnings": [],
                "verification_time": 0.0,
                "entries_checked": 0,
                "broken_links": []
            }
    
    def _verify_signatures(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify digital signatures on entries."""
        try:
            start_time = time.time()
            
            result = {
                "verified": False,
                "issues": [],
                "warnings": [],
                "verification_time": 0.0,
                "entries_checked": len(entries),
                "signature_failures": [],
                "missing_signatures": []
            }
            
            if not self.log_signer.is_available():
                result["warnings"].append("Signature verification not available - no public key")
                result["verified"] = True  # Don't fail if signatures can't be checked
                return result
            
            valid_signatures = 0
            total_signatures = 0
            
            for i, entry in enumerate(entries):
                signature = entry.get("signature", "")
                entry_id = entry.get("entry_id", f"entry_{i}")
                
                if not signature:
                    result["missing_signatures"].append(entry_id)
                    continue
                
                total_signatures += 1
                
                # Verify signature
                if self.log_signer.verify_entry(entry):
                    valid_signatures += 1
                else:
                    result["signature_failures"].append(entry_id)
                    result["issues"].append(f"Invalid signature for entry: {entry_id}")
            
            # Determine overall result
            if total_signatures == 0:
                result["verified"] = True
                result["warnings"].append("No signatures found to verify")
            elif valid_signatures == total_signatures:
                result["verified"] = True
            else:
                result["verified"] = False
            
            result["verification_time"] = time.time() - start_time
            
            logger.info(f"Signature verification: {valid_signatures}/{total_signatures} valid")
            return result
            
        except Exception as e:
            logger.error(f"Signature verification failed: {str(e)}")
            return {
                "verified": False,
                "issues": [f"Signature verification error: {str(e)}"],
                "warnings": [],
                "verification_time": 0.0,
                "entries_checked": 0,
                "signature_failures": [],
                "missing_signatures": []
            }
    
    def _perform_additional_checks(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform additional integrity checks."""
        try:
            result = {
                "verified": True,
                "issues": [],
                "warnings": [],
                "checks_performed": []
            }
            
            # Check 1: Timestamp consistency
            timestamp_result = self._check_timestamp_consistency(entries)
            result["checks_performed"].append("timestamp_consistency")
            result["issues"].extend(timestamp_result["issues"])
            result["warnings"].extend(timestamp_result["warnings"])
            
            # Check 2: Entry ID uniqueness
            id_result = self._check_entry_id_uniqueness(entries)
            result["checks_performed"].append("id_uniqueness")
            result["issues"].extend(id_result["issues"])
            result["warnings"].extend(id_result["warnings"])
            
            # Check 3: Data structure consistency
            structure_result = self._check_data_structure_consistency(entries)
            result["checks_performed"].append("structure_consistency")
            result["issues"].extend(structure_result["issues"])
            result["warnings"].extend(structure_result["warnings"])
            
            # Check 4: Sequence consistency
            sequence_result = self._check_sequence_consistency(entries)
            result["checks_performed"].append("sequence_consistency")
            result["issues"].extend(sequence_result["issues"])
            result["warnings"].extend(sequence_result["warnings"])
            
            result["verified"] = len(result["issues"]) == 0
            
            return result
            
        except Exception as e:
            logger.error(f"Additional checks failed: {str(e)}")
            return {
                "verified": False,
                "issues": [f"Additional checks error: {str(e)}"],
                "warnings": [],
                "checks_performed": []
            }
    
    def _check_timestamp_consistency(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check timestamp consistency across entries."""
        result = {"issues": [], "warnings": []}
        
        try:
            if len(entries) < 2:
                return result
            
            timestamps = []
            for entry in entries:
                timestamp = entry.get("timestamp", 0)
                timestamps.append(timestamp)
            
            # Check for out-of-order timestamps
            for i in range(1, len(timestamps)):
                if timestamps[i] < timestamps[i-1]:
                    result["issues"].append(f"Timestamp out of order at entry {i}")
            
            # Check for duplicate timestamps
            timestamp_counts = {}
            for i, timestamp in enumerate(timestamps):
                if timestamp in timestamp_counts:
                    result["warnings"].append(f"Duplicate timestamp at entry {i} (same as entry {timestamp_counts[timestamp]})")
                else:
                    timestamp_counts[timestamp] = i
            
            # Check for large time gaps
            for i in range(1, len(timestamps)):
                gap = timestamps[i] - timestamps[i-1]
                if gap > 3600:  # More than 1 hour gap
                    result["warnings"].append(f"Large time gap ({gap}s) between entries {i-1} and {i}")
            
            return result
            
        except Exception as e:
            result["issues"].append(f"Timestamp consistency check error: {str(e)}")
            return result
    
    def _check_entry_id_uniqueness(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check for duplicate entry IDs."""
        result = {"issues": [], "warnings": []}
        
        try:
            entry_ids = []
            for entry in entries:
                entry_id = entry.get("entry_id", "")
                entry_ids.append(entry_id)
            
            # Check for duplicates
            id_counts = {}
            for i, entry_id in enumerate(entry_ids):
                if entry_id in id_counts:
                    result["issues"].append(f"Duplicate entry ID '{entry_id}' at entry {i} (first seen at entry {id_counts[entry_id]})")
                else:
                    id_counts[entry_id] = i
            
            # Check for empty IDs
            for i, entry_id in enumerate(entry_ids):
                if not entry_id:
                    result["warnings"].append(f"Empty entry ID at entry {i}")
            
            return result
            
        except Exception as e:
            result["issues"].append(f"Entry ID uniqueness check error: {str(e)}")
            return result
    
    def _check_data_structure_consistency(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check data structure consistency across entries."""
        result = {"issues": [], "warnings": []}
        
        try:
            required_fields = ["entry_id", "timestamp", "event_type", "entry_hash", "previous_hash"]
            
            for i, entry in enumerate(entries):
                # Check required fields
                for field in required_fields:
                    if field not in entry:
                        result["issues"].append(f"Missing required field '{field}' in entry {i}")
                
                # Check data types
                if "timestamp" in entry and not isinstance(entry["timestamp"], (int, float)):
                    result["issues"].append(f"Invalid timestamp type in entry {i}")
                
                if "event_data" in entry and not isinstance(entry["event_data"], dict):
                    result["warnings"].append(f"Invalid event_data type in entry {i}")
            
            return result
            
        except Exception as e:
            result["issues"].append(f"Data structure consistency check error: {str(e)}")
            return result
    
    def _check_sequence_consistency(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check sequence consistency in metadata."""
        result = {"issues": [], "warnings": []}
        
        try:
            for i, entry in enumerate(entries):
                metadata = entry.get("metadata", {})
                
                # Check entry number consistency
                expected_number = i + 1
                entry_number = metadata.get("entry_number", 0)
                if entry_number != expected_number:
                    result["warnings"].append(f"Entry number mismatch at entry {i}: expected {expected_number}, got {entry_number}")
            
            return result
            
        except Exception as e:
            result["issues"].append(f"Sequence consistency check error: {str(e)}")
            return result
    
    def verify_entry_range(self, start_index: int, end_index: int) -> Dict[str, Any]:
        """Verify a specific range of entries."""
        try:
            entries = self._load_all_entries()
            
            if start_index < 0 or end_index >= len(entries) or start_index > end_index:
                return {
                    "verified": False,
                    "issues": [f"Invalid range: {start_index}-{end_index} (total entries: {len(entries)})"],
                    "warnings": []
                }
            
            range_entries = entries[start_index:end_index + 1]
            
            # Verify the range
            result = self._verify_hash_chain(range_entries)
            result["range"] = f"{start_index}-{end_index}"
            result["entries_in_range"] = len(range_entries)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to verify entry range: {str(e)}")
            return {
                "verified": False,
                "issues": [f"Range verification error: {str(e)}"],
                "warnings": []
            }
    
    def get_verification_report(self) -> Dict[str, Any]:
        """Get a comprehensive verification report."""
        try:
            # Perform full verification
            verification_result = self.verify_log()
            
            # Create report
            report = {
                "report_timestamp": time.time(),
                "log_file": str(self.log_file_path),
                "verification_result": verification_result,
                "statistics": self.stats.copy(),
                "recommendations": self._generate_recommendations(verification_result),
                "health_score": self._calculate_health_score(verification_result)
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate verification report: {str(e)}")
            return {"error": str(e)}
    
    def _generate_recommendations(self, verification_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on verification results."""
        recommendations = []
        
        if verification_result["verified"]:
            recommendations.append("Log integrity verified - no action needed")
        else:
            recommendations.append("Log integrity compromised - investigate immediately")
            
            if verification_result["tampering_detected"]:
                recommendations.append("Tampering detected - secure the log file and investigate")
                recommendations.append("Consider restoring from backup if available")
            
            if verification_result["signature_status"] == "failed":
                recommendations.append("Signature verification failed - check key management")
                recommendations.append("Verify signing process is working correctly")
            
            if verification_result["hash_chain_status"] == "failed":
                recommendations.append("Hash chain broken - indicates possible tampering")
                recommendations.append("Review all recent entries for anomalies")
        
        # Performance recommendations
        if verification_result["verification_time"] > 60:
            recommendations.append("Verification taking long time - consider log rotation")
        
        return recommendations
    
    def _calculate_health_score(self, verification_result: Dict[str, Any]) -> float:
        """Calculate a health score (0-100) for the audit log."""
        try:
            score = 100.0
            
            # Deduct points for issues
            score -= len(verification_result["issues"]) * 10
            score -= len(verification_result["warnings"]) * 2
            
            # Deduct points for tampering
            if verification_result["tampering_detected"]:
                score -= 50
            
            # Deduct points for failed checks
            if verification_result["signature_status"] == "failed":
                score -= 20
            
            if verification_result["hash_chain_status"] == "failed":
                score -= 30
            
            # Deduct points for slow verification
            if verification_result["verification_time"] > 60:
                score -= 10
            
            return max(0.0, min(100.0, score))
            
        except Exception:
            return 0.0
    
    def _update_verification_stats(self, result: Dict[str, Any]) -> None:
        """Update verification statistics."""
        try:
            self.stats["total_verifications"] += 1
            
            if result["verified"]:
                self.stats["successful_verifications"] += 1
            else:
                self.stats["failed_verifications"] += 1
            
            if result["tampering_detected"]:
                self.stats["tampering_detected"] += 1
            
            # Update average verification time
            current_avg = self.stats["avg_verification_time"]
            count = self.stats["total_verifications"]
            new_time = result["verification_time"]
            self.stats["avg_verification_time"] = ((current_avg * (count - 1)) + new_time) / count
            
        except Exception as e:
            logger.error(f"Failed to update verification stats: {str(e)}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get verifier statistics."""
        return self.stats.copy()
    
    def get_status(self) -> Dict[str, Any]:
        """Get verifier status."""
        return {
            "status": "active",
            "log_file_path": str(self.log_file_path),
            "public_key_path": self.public_key_path,
            "configuration": self.config.copy(),
            "statistics": self.get_statistics(),
            "log_signer_status": self.log_signer.get_status()
        }
    
    def reset_statistics(self) -> None:
        """Reset verifier statistics."""
        self.stats = {
            "total_verifications": 0,
            "successful_verifications": 0,
            "failed_verifications": 0,
            "tampering_detected": 0,
            "signature_failures": 0,
            "hash_chain_failures": 0,
            "avg_verification_time": 0.0
        }
        logger.info("Log verifier statistics reset")
