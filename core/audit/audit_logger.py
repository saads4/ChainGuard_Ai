"""
Audit Logger - Appends events to the hash-chain log

Handles audit logging for ChainGuardAI:
- Hash-chained log entry creation
- Event logging and tracking
- Log rotation and management
- Performance-optimized logging
"""

import json
import time
import threading
from typing import Dict, Any, List, Optional
from pathlib import Path
from loguru import logger
from .hash_chain import HashChain
from .log_signer import LogSigner


class AuditLogger:
    """Manages hash-chained audit logging for ChainGuardAI."""
    
    def __init__(self, log_file_path: str = "./core/audit/logs/audit_chain.jsonl",
                 private_key_path: str = "./keys/audit_private_key.pem",
                 signing_enabled: bool = True):
        """
        Initialize AuditLogger.
        
        Args:
            log_file_path: Path to the audit log file
            private_key_path: Path to private key for signing
            signing_enabled: Whether to enable log signing
        """
        self.log_file_path = Path(log_file_path)
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.private_key_path = private_key_path
        self.signing_enabled = signing_enabled
        
        # Initialize components
        self.hash_chain = HashChain()
        self.log_signer = LogSigner(private_key_path) if signing_enabled else None
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Log buffer for batch writing
        self.log_buffer = []
        self.buffer_size = 100
        self.flush_interval = 60  # seconds
        self.last_flush = time.time()
        
        # Statistics
        self.stats = {
            "total_entries": 0,
            "signed_entries": 0,
            "buffered_entries": 0,
            "flush_count": 0,
            "avg_write_time": 0.0,
            "log_file_size": 0
        }
        
        # Load existing chain state
        self._load_chain_state()
        
        logger.info(f"Initialized AuditLogger with log file: {log_file_path}")
    
    def log_event(self, event_type: str, event_data: Dict[str, Any], 
                  agent_id: str = None, session_id: str = None) -> str:
        """
        Log an event to the audit chain.
        
        Args:
            event_type: Type of event (e.g., "action", "detection", "escalation")
            event_data: Event data dictionary
            agent_id: ID of the agent performing the action
            session_id: Session ID for correlation
            
        Returns:
            Entry ID of the logged event
        """
        try:
            with self.lock:
                # Create log entry
                entry = self._create_log_entry(event_type, event_data, agent_id, session_id)
                
                # Add to buffer
                self.log_buffer.append(entry)
                self.stats["buffered_entries"] += 1
                
                # Check if we should flush
                if (len(self.log_buffer) >= self.buffer_size or
                    time.time() - self.last_flush > self.flush_interval):
                    self._flush_buffer()
                
                self.stats["total_entries"] += 1
                
                logger.debug(f"Logged event: {event_type} (entry_id: {entry['entry_id']})")
                return entry["entry_id"]
                
        except Exception as e:
            logger.error(f"Failed to log event: {str(e)}")
            return ""
    
    def _create_log_entry(self, event_type: str, event_data: Dict[str, Any],
                        agent_id: str = None, session_id: str = None) -> Dict[str, Any]:
        """Create a log entry with hash chaining."""
        try:
            # Get previous hash
            previous_hash = self.hash_chain.get_last_hash()
            
            # Create entry
            entry = {
                "entry_id": f"entry_{int(time.time() * 1000000)}_{self.stats['total_entries']}",
                "timestamp": time.time(),
                "event_type": event_type,
                "agent_id": agent_id or "unknown",
                "session_id": session_id or "unknown",
                "event_data": event_data,
                "previous_hash": previous_hash,
                "entry_hash": "",  # Will be calculated
                "signature": "",   # Will be added if signing enabled
                "metadata": {
                    "logger_version": "1.0",
                    "entry_number": self.stats["total_entries"] + 1
                }
            }
            
            # Calculate entry hash
            entry["entry_hash"] = self.hash_chain.create_link(previous_hash, entry)
            
            # Sign entry if enabled
            if self.signing_enabled and self.log_signer:
                entry["signature"] = self.log_signer.sign_entry(entry)
                self.stats["signed_entries"] += 1
            
            return entry
            
        except Exception as e:
            logger.error(f"Failed to create log entry: {str(e)}")
            raise
    
    def _flush_buffer(self) -> None:
        """Flush the log buffer to file."""
        try:
            if not self.log_buffer:
                return
            
            start_time = time.time()
            
            # Write entries to file
            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                for entry in self.log_buffer:
                    json_line = json.dumps(entry, separators=(',', ':'))
                    f.write(json_line + '\n')
            
            # Update statistics
            write_time = time.time() - start_time
            self.stats["flush_count"] += 1
            self.stats["buffered_entries"] -= len(self.log_buffer)
            
            # Update average write time
            current_avg = self.stats["avg_write_time"]
            count = self.stats["flush_count"]
            self.stats["avg_write_time"] = ((current_avg * (count - 1)) + write_time) / count
            
            # Update file size
            self.stats["log_file_size"] = self.log_file_path.stat().st_size
            
            # Clear buffer
            self.log_buffer.clear()
            self.last_flush = time.time()
            
            logger.debug(f"Flushed {len(self.log_buffer)} entries to audit log")
            
        except Exception as e:
            logger.error(f"Failed to flush log buffer: {str(e)}")
    
    def force_flush(self) -> bool:
        """Force flush the buffer to file."""
        try:
            with self.lock:
                self._flush_buffer()
                return True
        except Exception as e:
            logger.error(f"Failed to force flush: {str(e)}")
            return False
    
    def get_recent_entries(self, count: int = 100, event_type: str = None) -> List[Dict[str, Any]]:
        """Get recent entries from the log file."""
        try:
            entries = []
            
            if not self.log_file_path.exists():
                return entries
            
            # Read file from the end
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Process lines in reverse order
            for line in reversed(lines[-count*2:]):  # Read more lines in case of filtering
                try:
                    entry = json.loads(line.strip())
                    
                    # Filter by event type if specified
                    if event_type is None or entry.get("event_type") == event_type:
                        entries.append(entry)
                    
                    if len(entries) >= count:
                        break
                        
                except json.JSONDecodeError:
                    continue
            
            # Reverse to get chronological order
            entries.reverse()
            
            return entries
            
        except Exception as e:
            logger.error(f"Failed to get recent entries: {str(e)}")
            return []
    
    def search_entries(self, query: Dict[str, Any], limit: int = 1000) -> List[Dict[str, Any]]:
        """Search entries based on criteria."""
        try:
            matching_entries = []
            
            if not self.log_file_path.exists():
                return matching_entries
            
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Check if entry matches query
                        if self._entry_matches_query(entry, query):
                            matching_entries.append(entry)
                        
                        if len(matching_entries) >= limit:
                            break
                            
                    except json.JSONDecodeError:
                        continue
            
            return matching_entries
            
        except Exception as e:
            logger.error(f"Failed to search entries: {str(e)}")
            return []
    
    def _entry_matches_query(self, entry: Dict[str, Any], query: Dict[str, Any]) -> bool:
        """Check if an entry matches the search query."""
        try:
            for key, value in query.items():
                if key == "event_type" and entry.get("event_type") != value:
                    return False
                elif key == "agent_id" and entry.get("agent_id") != value:
                    return False
                elif key == "session_id" and entry.get("session_id") != value:
                    return False
                elif key == "time_range":
                    start_time, end_time = value
                    entry_time = entry.get("timestamp", 0)
                    if not (start_time <= entry_time <= end_time):
                        return False
                elif key == "contains_text":
                    text = value.lower()
                    entry_text = json.dumps(entry).lower()
                    if text not in entry_text:
                        return False
            
            return True
            
        except Exception:
            return False
    
    def get_entry_by_id(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific entry by ID."""
        try:
            if not self.log_file_path.exists():
                return None
            
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if entry.get("entry_id") == entry_id:
                            return entry
                    except json.JSONDecodeError:
                        continue
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get entry by ID: {str(e)}")
            return None
    
    def _load_chain_state(self) -> None:
        """Load the hash chain state from existing log."""
        try:
            if not self.log_file_path.exists():
                self.hash_chain.initialize_chain()
                return
            
            # Get the last entry to extract the hash
            last_entry = None
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if lines:
                    try:
                        last_entry = json.loads(lines[-1].strip())
                    except json.JSONDecodeError:
                        pass
            
            if last_entry and "entry_hash" in last_entry:
                self.hash_chain.set_last_hash(last_entry["entry_hash"])
                self.hash_chain.entry_count = last_entry.get("metadata", {}).get("entry_number", 0)
            else:
                self.hash_chain.initialize_chain()
            
            logger.info(f"Loaded chain state with {self.hash_chain.entry_count} entries")
            
        except Exception as e:
            logger.error(f"Failed to load chain state: {str(e)}")
            self.hash_chain.initialize_chain()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit logger statistics."""
        try:
            # Update file size
            if self.log_file_path.exists():
                self.stats["log_file_size"] = self.log_file_path.stat().st_size
            
            return {
                "total_entries": self.stats["total_entries"],
                "signed_entries": self.stats["signed_entries"],
                "buffered_entries": len(self.log_buffer),
                "flush_count": self.stats["flush_count"],
                "avg_write_time": self.stats["avg_write_time"],
                "log_file_size": self.stats["log_file_size"],
                "signing_enabled": self.signing_enabled,
                "chain_state": {
                    "entry_count": self.hash_chain.entry_count,
                    "last_hash": self.hash_chain.get_last_hash()
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {str(e)}")
            return {"error": str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get audit logger status."""
        return {
            "status": "active",
            "log_file_path": str(self.log_file_path),
            "signing_enabled": self.signing_enabled,
            "buffer_size": len(self.log_buffer),
            "statistics": self.get_statistics(),
            "hash_chain_status": self.hash_chain.get_status(),
            "log_signer_status": self.log_signer.get_status() if self.log_signer else None
        }
    
    def rotate_log(self, archive_path: str = None) -> bool:
        """Rotate the current log file."""
        try:
            if not self.log_file_path.exists():
                logger.warning("Log file does not exist, cannot rotate")
                return False
            
            # Force flush buffer first
            self.force_flush()
            
            # Create archive path if not provided
            if not archive_path:
                timestamp = int(time.time())
                archive_path = self.log_file_path.parent / f"audit_chain_{timestamp}.jsonl"
            
            # Move current log to archive
            import shutil
            shutil.move(str(self.log_file_path), str(archive_path))
            
            # Reinitialize chain
            self.hash_chain.initialize_chain()
            
            logger.info(f"Rotated log to {archive_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate log: {str(e)}")
            return False
    
    def export_entries(self, output_path: str, query: Dict[str, Any] = None) -> int:
        """Export entries to a file."""
        try:
            if query:
                entries = self.search_entries(query, limit=10000)
            else:
                entries = self.get_recent_entries(10000)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                for entry in entries:
                    json_line = json.dumps(entry, indent=2)
                    f.write(json_line + '\n')
            
            logger.info(f"Exported {len(entries)} entries to {output_path}")
            return len(entries)
            
        except Exception as e:
            logger.error(f"Failed to export entries: {str(e)}")
            return 0
    
    def cleanup_old_entries(self, retention_days: int = 365) -> int:
        """Clean up old entries based on retention policy."""
        try:
            if not self.log_file_path.exists():
                return 0
            
            cutoff_time = time.time() - (retention_days * 24 * 60 * 60)
            removed_count = 0
            
            # Read all entries and filter
            valid_entries = []
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if entry.get("timestamp", 0) >= cutoff_time:
                            valid_entries.append(entry)
                        else:
                            removed_count += 1
                    except json.JSONDecodeError:
                        continue
            
            # Write back valid entries
            if removed_count > 0:
                # Create backup first
                backup_path = self.log_file_path.with_suffix('.backup')
                import shutil
                shutil.copy2(self.log_file_path, backup_path)
                
                # Write filtered entries
                with open(self.log_file_path, 'w', encoding='utf-8') as f:
                    for entry in valid_entries:
                        json_line = json.dumps(entry, separators=(',', ':'))
                        f.write(json_line + '\n')
                
                # Reinitialize chain state
                if valid_entries:
                    last_entry = valid_entries[-1]
                    self.hash_chain.set_last_hash(last_entry.get("entry_hash", ""))
                    self.hash_chain.entry_count = last_entry.get("metadata", {}).get("entry_number", 0)
                else:
                    self.hash_chain.initialize_chain()
            
            logger.info(f"Cleaned up {removed_count} old entries")
            return removed_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old entries: {str(e)}")
            return 0
    
    def reset_statistics(self) -> None:
        """Reset audit logger statistics."""
        self.stats = {
            "total_entries": self.hash_chain.entry_count,
            "signed_entries": 0,
            "buffered_entries": len(self.log_buffer),
            "flush_count": 0,
            "avg_write_time": 0.0,
            "log_file_size": 0
        }
        logger.info("Audit logger statistics reset")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure buffer is flushed."""
        self.force_flush()
