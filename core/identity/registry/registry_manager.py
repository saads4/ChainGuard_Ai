"""
Registry Manager - CRUD operations for agent registry

Manages the agent registry for ChainGuardAI:
- Agent registration and discovery
- Public key storage and retrieval
- Registry encryption and security
- Registry backup and recovery
"""

import json
import os
import time
import threading
from typing import Dict, Any, List, Optional
from pathlib import Path
from cryptography.fernet import Fernet
from loguru import logger
from ..key_manager import KeyManager, ed25519


class RegistryManager:
    """Manages the agent registry with CRUD operations."""
    
    def __init__(self, registry_path: str, encryption_key: Optional[bytes] = None):
        """
        Initialize RegistryManager.
        
        Args:
            registry_path: Path to the registry file
            encryption_key: Encryption key for registry (optional)
        """
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.encryption_key = encryption_key
        self.cipher = Fernet(encryption_key) if encryption_key else None
        
        self.registry = {}
        self.lock = threading.RLock()
        
        # Load existing registry
        self._load_registry()
    
    def _load_registry(self) -> None:
        """Load registry from file."""
        try:
            if not self.registry_path.exists():
                logger.info("Registry file not found, creating new registry")
                self.registry = {
                    "version": "1.0",
                    "created_at": time.time(),
                    "agents": {},
                    "last_updated": time.time()
                }
                self._save_registry()
                return
            
            with open(self.registry_path, 'rb') as f:
                data = f.read()
            
            # Decrypt if encryption is enabled
            if self.cipher:
                data = self.cipher.decrypt(data)
            
            self.registry = json.loads(data.decode('utf-8'))
            logger.info(f"Loaded registry with {len(self.registry.get('agents', {}))} agents")
            
        except Exception as e:
            logger.error(f"Failed to load registry: {str(e)}")
            self.registry = {
                "version": "1.0",
                "created_at": time.time(),
                "agents": {},
                "last_updated": time.time()
            }
    
    def _save_registry(self) -> bool:
        """Save registry to file."""
        try:
            self.registry["last_updated"] = time.time()
            
            data = json.dumps(self.registry, indent=2).encode('utf-8')
            
            # Encrypt if encryption is enabled
            if self.cipher:
                data = self.cipher.encrypt(data)
            
            # Write to temporary file first
            temp_path = self.registry_path.with_suffix('.tmp')
            with open(temp_path, 'wb') as f:
                f.write(data)
            
            # Move temporary file to final location
            temp_path.replace(self.registry_path)
            
            logger.debug("Registry saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save registry: {str(e)}")
            return False
    
    def register_agent(self, agent_did: str, public_key: ed25519.Ed25519PublicKey,
                      metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Register a new agent in the registry.
        
        Args:
            agent_did: DID of the agent
            public_key: Agent's public key
            metadata: Additional agent metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                if agent_did in self.registry["agents"]:
                    logger.warning(f"Agent already registered: {agent_did}")
                    return False
                
                # Get public key in base64 format
                key_manager = KeyManager()
                public_key_b64 = key_manager.get_public_key_base64(public_key)
                
                # Create agent entry
                agent_entry = {
                    "did": agent_did,
                    "public_key": public_key_b64,
                    "registered_at": time.time(),
                    "last_seen": time.time(),
                    "status": "active",
                    "metadata": metadata or {}
                }
                
                # Add to registry
                self.registry["agents"][agent_did] = agent_entry
                
                # Save registry
                success = self._save_registry()
                
                if success:
                    logger.info(f"Registered agent: {agent_did}")
                else:
                    # Rollback if save failed
                    del self.registry["agents"][agent_did]
                
                return success
                
        except Exception as e:
            logger.error(f"Failed to register agent {agent_did}: {str(e)}")
            return False
    
    def update_agent(self, agent_did: str, updates: Dict[str, Any]) -> bool:
        """
        Update agent information in the registry.
        
        Args:
            agent_did: DID of the agent
            updates: Dictionary of updates to apply
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                if agent_did not in self.registry["agents"]:
                    logger.warning(f"Agent not found for update: {agent_did}")
                    return False
                
                agent_entry = self.registry["agents"][agent_did]
                
                # Update allowed fields
                allowed_fields = ["last_seen", "status", "metadata"]
                for field, value in updates.items():
                    if field in allowed_fields:
                        if field == "metadata" and isinstance(value, dict):
                            agent_entry[field].update(value)
                        else:
                            agent_entry[field] = value
                    else:
                        logger.warning(f"Attempted to update restricted field: {field}")
                
                # Save registry
                success = self._save_registry()
                
                if success:
                    logger.info(f"Updated agent: {agent_did}")
                
                return success
                
        except Exception as e:
            logger.error(f"Failed to update agent {agent_did}: {str(e)}")
            return False
    
    def get_agent(self, agent_did: str) -> Optional[Dict[str, Any]]:
        """
        Get agent information from the registry.
        
        Args:
            agent_did: DID of the agent
            
        Returns:
            Agent entry dictionary or None if not found
        """
        try:
            with self.lock:
                agent_entry = self.registry["agents"].get(agent_did)
                
                if agent_entry:
                    # Update last_seen
                    agent_entry["last_seen"] = time.time()
                    self._save_registry()
                    logger.debug(f"Retrieved agent: {agent_did}")
                    return agent_entry.copy()
                else:
                    logger.warning(f"Agent not found: {agent_did}")
                    return None
                    
        except Exception as e:
            logger.error(f"Failed to get agent {agent_did}: {str(e)}")
            return None
    
    def get_agent_public_key(self, agent_did: str) -> Optional[ed25519.Ed25519PublicKey]:
        """
        Get an agent's public key from the registry.
        
        Args:
            agent_did: DID of the agent
            
        Returns:
            Ed25519 public key or None if not found
        """
        try:
            agent_entry = self.get_agent(agent_did)
            if not agent_entry:
                return None
            
            public_key_b64 = agent_entry.get("public_key")
            if not public_key_b64:
                logger.error(f"No public key found for agent: {agent_did}")
                return None
            
            # Convert base64 to Ed25519 public key
            import base64
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.backends import default_backend
            
            key_bytes = base64.b64decode(public_key_b64)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            
            logger.debug(f"Retrieved public key for agent: {agent_did}")
            return public_key
            
        except Exception as e:
            logger.error(f"Failed to get public key for {agent_did}: {str(e)}")
            return None
    
    def list_agents(self, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all agents in the registry.
        
        Args:
            status_filter: Filter by agent status (optional)
            
        Returns:
            List of agent entries
        """
        try:
            with self.lock:
                agents = []
                
                for agent_did, agent_entry in self.registry["agents"].items():
                    if status_filter and agent_entry.get("status") != status_filter:
                        continue
                    
                    agents.append(agent_entry.copy())
                
                logger.info(f"Listed {len(agents)} agents")
                return agents
                
        except Exception as e:
            logger.error(f"Failed to list agents: {str(e)}")
            return []
    
    def deregister_agent(self, agent_did: str) -> bool:
        """
        Remove an agent from the registry.
        
        Args:
            agent_did: DID of the agent to remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                if agent_did not in self.registry["agents"]:
                    logger.warning(f"Agent not found for deregistration: {agent_did}")
                    return False
                
                # Remove from registry
                del self.registry["agents"][agent_did]
                
                # Save registry
                success = self._save_registry()
                
                if success:
                    logger.info(f"Deregistered agent: {agent_did}")
                
                return success
                
        except Exception as e:
            logger.error(f"Failed to deregister agent {agent_did}: {str(e)}")
            return False
    
    def update_agent_status(self, agent_did: str, status: str) -> bool:
        """
        Update an agent's status.
        
        Args:
            agent_did: DID of the agent
            status: New status (active, inactive, suspended)
            
        Returns:
            True if successful, False otherwise
        """
        valid_statuses = ["active", "inactive", "suspended"]
        
        if status not in valid_statuses:
            logger.error(f"Invalid status: {status}")
            return False
        
        return self.update_agent(agent_did, {"status": status})
    
    def search_agents(self, query: str, search_fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Search agents by metadata.
        
        Args:
            query: Search query string
            search_fields: Fields to search in (default: all metadata)
            
        Returns:
            List of matching agent entries
        """
        try:
            if search_fields is None:
                search_fields = ["did", "metadata"]
            
            matching_agents = []
            query_lower = query.lower()
            
            for agent_did, agent_entry in self.registry["agents"].items():
                # Search in DID
                if "did" in search_fields and query_lower in agent_did.lower():
                    matching_agents.append(agent_entry.copy())
                    continue
                
                # Search in metadata
                if "metadata" in search_fields:
                    metadata = agent_entry.get("metadata", {})
                    for key, value in metadata.items():
                        if isinstance(value, str) and query_lower in value.lower():
                            matching_agents.append(agent_entry.copy())
                            break
            
            logger.info(f"Found {len(matching_agents)} agents matching query: {query}")
            return matching_agents
            
        except Exception as e:
            logger.error(f"Failed to search agents: {str(e)}")
            return []
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics.
        
        Returns:
            Registry statistics dictionary
        """
        try:
            with self.lock:
                agents = self.registry["agents"]
                
                stats = {
                    "total_agents": len(agents),
                    "active_agents": sum(1 for a in agents.values() if a.get("status") == "active"),
                    "inactive_agents": sum(1 for a in agents.values() if a.get("status") == "inactive"),
                    "suspended_agents": sum(1 for a in agents.values() if a.get("status") == "suspended"),
                    "registry_version": self.registry.get("version", "unknown"),
                    "created_at": self.registry.get("created_at"),
                    "last_updated": self.registry.get("last_updated")
                }
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get registry stats: {str(e)}")
            return {}
    
    def backup_registry(self, backup_path: str) -> bool:
        """
        Create a backup of the registry.
        
        Args:
            backup_path: Path for the backup file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                backup_data = {
                    "backup_timestamp": time.time(),
                    "registry": self.registry.copy()
                }
                
                with open(backup_path, 'w') as f:
                    json.dump(backup_data, f, indent=2)
                
                logger.info(f"Created registry backup: {backup_path}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to backup registry: {str(e)}")
            return False
    
    def restore_registry(self, backup_path: str) -> bool:
        """
        Restore registry from backup.
        
        Args:
            backup_path: Path to the backup file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(backup_path, 'r') as f:
                backup_data = json.load(f)
            
            restored_registry = backup_data.get("registry")
            if not restored_registry:
                logger.error("Invalid backup file format")
                return False
            
            with self.lock:
                # Create backup of current registry
                current_backup_path = self.registry_path.with_suffix('.backup')
                self.backup_registry(str(current_backup_path))
                
                # Restore registry
                self.registry = restored_registry
                success = self._save_registry()
                
                if success:
                    logger.info(f"Restored registry from backup: {backup_path}")
                else:
                    # Restore from backup if restore failed
                    self._load_registry()
                
                return success
                
        except Exception as e:
            logger.error(f"Failed to restore registry: {str(e)}")
            return False
    
    def cleanup_inactive_agents(self, inactive_days: int = 30) -> int:
        """
        Remove agents that have been inactive for too long.
        
        Args:
            inactive_days: Number of days of inactivity before removal
            
        Returns:
            Number of agents removed
        """
        try:
            with self.lock:
                current_time = time.time()
                inactive_threshold = inactive_days * 24 * 60 * 60  # Convert to seconds
                
                agents_to_remove = []
                
                for agent_did, agent_entry in self.registry["agents"].items():
                    last_seen = agent_entry.get("last_seen", 0)
                    if current_time - last_seen > inactive_threshold:
                        agents_to_remove.append(agent_did)
                
                # Remove inactive agents
                for agent_did in agents_to_remove:
                    del self.registry["agents"][agent_did]
                
                # Save registry
                if agents_to_remove:
                    self._save_registry()
                
                logger.info(f"Cleaned up {len(agents_to_remove)} inactive agents")
                return len(agents_to_remove)
                
        except Exception as e:
            logger.error(f"Failed to cleanup inactive agents: {str(e)}")
            return 0
    
    def export_registry(self, export_path: str, include_private_data: bool = False) -> bool:
        """
        Export registry to file.
        
        Args:
            export_path: Path for the export file
            include_private_data: Whether to include sensitive data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                export_data = self.registry.copy()
                
                if not include_private_data:
                    # Remove sensitive data
                    for agent_entry in export_data["agents"].values():
                        agent_entry.pop("public_key", None)
                
                with open(export_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                logger.info(f"Exported registry to: {export_path}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to export registry: {str(e)}")
            return False
