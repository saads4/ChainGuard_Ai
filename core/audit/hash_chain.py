"""
Hash Chain - SHA-256 chaining logic: each entry hashes previous

Implements hash-chained logging for ChainGuardAI:
- SHA-256 hash chain creation
- Chain integrity verification
- Link validation
- Chain state management
"""

import json
import hashlib
import time
from typing import Dict, Any, List, Optional, Tuple
from loguru import logger


class HashChain:
    """Manages SHA-256 hash chaining for audit logs."""
    
    def __init__(self):
        """Initialize HashChain."""
        self.last_hash = ""
        self.entry_count = 0
        self.chain_initialized = False
        
        # Genesis hash
        self.genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        
        logger.info("Initialized HashChain")
    
    def initialize_chain(self) -> None:
        """Initialize the hash chain with genesis block."""
        try:
            self.last_hash = self.genesis_hash
            self.entry_count = 0
            self.chain_initialized = True
            
            # Create genesis entry
            genesis_entry = {
                "entry_id": "genesis",
                "timestamp": time.time(),
                "previous_hash": self.genesis_hash,
                "entry_hash": self.genesis_hash,
                "data": "genesis_block",
                "metadata": {
                    "chain_version": "1.0",
                    "algorithm": "SHA-256"
                }
            }
            
            logger.info("Hash chain initialized with genesis block")
            
        except Exception as e:
            logger.error(f"Failed to initialize hash chain: {str(e)}")
            raise
    
    def create_link(self, previous_hash: str, data: Dict[str, Any]) -> str:
        """
        Create a hash chain link.
        
        Args:
            previous_hash: Hash of the previous entry
            data: Data to include in this entry
            
        Returns:
            New hash value
        """
        try:
            # Create chain data
            chain_data = {
                "previous_hash": previous_hash,
                "data": data,
                "timestamp": time.time()
            }
            
            # Create hash
            hash_input = json.dumps(chain_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
            new_hash = hashlib.sha256(hash_input).hexdigest()
            
            # Update chain state
            self.last_hash = new_hash
            self.entry_count += 1
            
            return new_hash
            
        except Exception as e:
            logger.error(f"Failed to create hash chain link: {str(e)}")
            raise
    
    def verify_link(self, entry: Dict[str, Any], expected_previous_hash: str) -> bool:
        """
        Verify a hash chain link.
        
        Args:
            entry: Entry to verify
            expected_previous_hash: Expected previous hash
            
        Returns:
            True if link is valid, False otherwise
        """
        try:
            # Recreate the hash
            chain_data = {
                "previous_hash": expected_previous_hash,
                "data": entry.get("data", {}),
                "timestamp": entry.get("timestamp", 0)
            }
            
            hash_input = json.dumps(chain_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
            calculated_hash = hashlib.sha256(hash_input).hexdigest()
            
            # Compare with entry hash
            entry_hash = entry.get("entry_hash", "")
            
            return calculated_hash == entry_hash
            
        except Exception as e:
            logger.error(f"Failed to verify hash chain link: {str(e)}")
            return False
    
    def verify_chain(self, entries: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of a hash chain.
        
        Args:
            entries: List of entries to verify
            
        Returns:
            Tuple of (is_valid, list of issues)
        """
        try:
            if not entries:
                return True, []
            
            issues = []
            
            # Verify genesis block
            if entries[0].get("entry_id") == "genesis":
                if entries[0].get("entry_hash") != self.genesis_hash:
                    issues.append("Genesis block hash mismatch")
            else:
                # First entry should link to genesis
                if entries[0].get("previous_hash") != self.genesis_hash:
                    issues.append("First entry does not link to genesis")
            
            # Verify each link
            for i, entry in enumerate(entries):
                if i == 0 and entry.get("entry_id") == "genesis":
                    continue
                
                previous_hash = entry.get("previous_hash", "")
                expected_previous = entries[i-1].get("entry_hash", "") if i > 0 else self.genesis_hash
                
                if previous_hash != expected_previous:
                    issues.append(f"Entry {i} previous hash mismatch")
                
                # Verify the hash
                if not self.verify_link(entry, previous_hash):
                    issues.append(f"Entry {i} hash verification failed")
            
            is_valid = len(issues) == 0
            
            if not is_valid:
                logger.warning(f"Chain verification failed: {issues}")
            else:
                logger.info("Chain verification passed")
            
            return is_valid, issues
            
        except Exception as e:
            logger.error(f"Failed to verify hash chain: {str(e)}")
            return False, [f"Verification error: {str(e)}"]
    
    def get_last_hash(self) -> str:
        """Get the last hash in the chain."""
        return self.last_hash
    
    def set_last_hash(self, last_hash: str) -> None:
        """Set the last hash in the chain."""
        self.last_hash = last_hash
        self.chain_initialized = True
    
    def get_entry_count(self) -> int:
        """Get the number of entries in the chain."""
        return self.entry_count
    
    def set_entry_count(self, count: int) -> None:
        """Set the entry count."""
        self.entry_count = count
    
    def create_proof_of_inclusion(self, entry_id: str, entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Create a Merkle-like proof of inclusion for an entry.
        
        Args:
            entry_id: ID of the entry to create proof for
            entries: List of all entries in the chain
            
        Returns:
            Proof dictionary or None if entry not found
        """
        try:
            # Find the entry
            entry_index = None
            for i, entry in enumerate(entries):
                if entry.get("entry_id") == entry_id:
                    entry_index = i
                    break
            
            if entry_index is None:
                return None
            
            # Create proof (simplified - in production, use proper Merkle tree)
            proof = {
                "entry_id": entry_id,
                "entry_index": entry_index,
                "entry_hash": entries[entry_index].get("entry_hash"),
                "previous_hash": entries[entry_index].get("previous_hash"),
                "next_hash": entries[entry_index + 1].get("entry_hash") if entry_index + 1 < len(entries) else None,
                "chain_root": entries[-1].get("entry_hash") if entries else None,
                "total_entries": len(entries)
            }
            
            return proof
            
        except Exception as e:
            logger.error(f"Failed to create proof of inclusion: {str(e)}")
            return None
    
    def verify_proof_of_inclusion(self, proof: Dict[str, Any], entries: List[Dict[str, Any]]) -> bool:
        """
        Verify a proof of inclusion.
        
        Args:
            proof: Proof dictionary
            entries: List of entries in the chain
            
        Returns:
            True if proof is valid, False otherwise
        """
        try:
            entry_index = proof.get("entry_index")
            
            if entry_index is None or entry_index >= len(entries):
                return False
            
            entry = entries[entry_index]
            
            # Verify entry hash matches
            if entry.get("entry_hash") != proof.get("entry_hash"):
                return False
            
            # Verify previous hash matches
            if entry_index > 0:
                expected_previous = entries[entry_index - 1].get("entry_hash")
                if entry.get("previous_hash") != expected_previous:
                    return False
            else:
                if entry.get("previous_hash") != self.genesis_hash:
                    return False
            
            # Verify chain integrity (simplified)
            if entries[-1].get("entry_hash") != proof.get("chain_root"):
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify proof of inclusion: {str(e)}")
            return False
    
    def get_chain_summary(self) -> Dict[str, Any]:
        """Get a summary of the hash chain."""
        return {
            "entry_count": self.entry_count,
            "last_hash": self.last_hash,
            "chain_initialized": self.chain_initialized,
            "genesis_hash": self.genesis_hash,
            "algorithm": "SHA-256",
            "chain_length": self.entry_count
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get hash chain status."""
        return {
            "status": "active",
            "chain_summary": self.get_chain_summary(),
            "last_updated": time.time()
        }
    
    def reset_chain(self) -> None:
        """Reset the hash chain to initial state."""
        self.last_hash = ""
        self.entry_count = 0
        self.chain_initialized = False
        logger.info("Hash chain reset")
    
    def export_chain_state(self) -> Dict[str, Any]:
        """Export the current chain state."""
        return {
            "last_hash": self.last_hash,
            "entry_count": self.entry_count,
            "chain_initialized": self.chain_initialized,
            "genesis_hash": self.genesis_hash,
            "export_timestamp": time.time()
        }
    
    def import_chain_state(self, state: Dict[str, Any]) -> bool:
        """Import chain state from exported data."""
        try:
            self.last_hash = state.get("last_hash", "")
            self.entry_count = state.get("entry_count", 0)
            self.chain_initialized = state.get("chain_initialized", False)
            
            # Validate genesis hash
            if state.get("genesis_hash") != self.genesis_hash:
                logger.warning("Genesis hash mismatch during import")
            
            logger.info(f"Imported chain state with {self.entry_count} entries")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import chain state: {str(e)}")
            return False
    
    def create_chain_checkpoint(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a checkpoint of the chain state."""
        try:
            if not entries:
                return {"error": "No entries to checkpoint"}
            
            checkpoint = {
                "checkpoint_id": f"checkpoint_{int(time.time())}",
                "timestamp": time.time(),
                "entry_count": len(entries),
                "last_hash": entries[-1].get("entry_hash"),
                "first_hash": entries[0].get("entry_hash"),
                "chain_root": entries[-1].get("entry_hash"),
                "merkle_root": self._calculate_merkle_root(entries)
            }
            
            return checkpoint
            
        except Exception as e:
            logger.error(f"Failed to create chain checkpoint: {str(e)}")
            return {"error": str(e)}
    
    def _calculate_merkle_root(self, entries: List[Dict[str, Any]]) -> str:
        """Calculate a simple Merkle root for the entries."""
        try:
            if not entries:
                return self.genesis_hash
            
            # Collect all entry hashes
            hashes = [entry.get("entry_hash", "") for entry in entries]
            
            # Build Merkle tree (simplified)
            while len(hashes) > 1:
                new_hashes = []
                
                for i in range(0, len(hashes), 2):
                    if i + 1 < len(hashes):
                        # Combine two hashes
                        combined = hashes[i] + hashes[i + 1]
                    else:
                        # Odd number, duplicate last hash
                        combined = hashes[i] + hashes[i]
                    
                    new_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
                    new_hashes.append(new_hash)
                
                hashes = new_hashes
            
            return hashes[0] if hashes else self.genesis_hash
            
        except Exception as e:
            logger.error(f"Failed to calculate Merkle root: {str(e)}")
            return self.genesis_hash
