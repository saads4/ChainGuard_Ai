"""
Key Manager - Ed25519 Keypair Generation and Storage

Handles cryptographic key operations for ChainGuardAI agents:
- Ed25519 keypair generation
- Secure key storage and retrieval
- Key serialization and deserialization
- Key rotation and management
"""

import os
import json
import base64
from typing import Optional, Tuple, Dict, Any
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from loguru import logger


class KeyManager:
    """Manages Ed25519 cryptographic keys for agents."""
    
    def __init__(self, keys_directory: str = "./keys"):
        """
        Initialize KeyManager.
        
        Args:
            keys_directory: Directory to store key files
        """
        self.keys_directory = Path(keys_directory)
        self.keys_directory.mkdir(parents=True, exist_ok=True)
        self.backend = default_backend()
        
    def generate_keypair(self, agent_id: str) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """
        Generate a new Ed25519 keypair for an agent.
        
        Args:
            agent_id: Unique identifier for the agent
            
        Returns:
            Tuple of (private_key, public_key)
        """
        try:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            logger.info(f"Generated keypair for agent: {agent_id}")
            return private_key, public_key
            
        except Exception as e:
            logger.error(f"Failed to generate keypair for {agent_id}: {str(e)}")
            raise
    
    def save_keypair(self, agent_id: str, private_key: ed25519.Ed25519PrivateKey, 
                     public_key: ed25519.Ed25519PublicKey, encrypt: bool = True) -> bool:
        """
        Save keypair to encrypted files.
        
        Args:
            agent_id: Agent identifier
            private_key: Ed25519 private key
            public_key: Ed25519 public key
            encrypt: Whether to encrypt the private key
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption() if not encrypt else serialization.BestAvailableEncryption(b"chainguard_ai_default")
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save to files
            private_key_path = self.keys_directory / f"{agent_id}_private.pem"
            public_key_path = self.keys_directory / f"{agent_id}_public.pem"
            
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            os.chmod(private_key_path, 0o600)  # Restrict permissions
            
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            
            logger.info(f"Saved keypair for agent: {agent_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save keypair for {agent_id}: {str(e)}")
            return False
    
    def load_private_key(self, agent_id: str, password: Optional[bytes] = None) -> Optional[ed25519.Ed25519PrivateKey]:
        """
        Load private key from file.
        
        Args:
            agent_id: Agent identifier
            password: Password for encrypted key (optional)
            
        Returns:
            Ed25519 private key or None if failed
        """
        try:
            private_key_path = self.keys_directory / f"{agent_id}_private.pem"
            
            if not private_key_path.exists():
                logger.warning(f"Private key not found for agent: {agent_id}")
                return None
            
            with open(private_key_path, 'rb') as f:
                private_pem = f.read()
            
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=password,
                backend=self.backend
            )
            
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Loaded key is not Ed25519 private key")
            
            logger.info(f"Loaded private key for agent: {agent_id}")
            return private_key
            
        except Exception as e:
            logger.error(f"Failed to load private key for {agent_id}: {str(e)}")
            return None
    
    def load_public_key(self, agent_id: str) -> Optional[ed25519.Ed25519PublicKey]:
        """
        Load public key from file.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Ed25519 public key or None if failed
        """
        try:
            public_key_path = self.keys_directory / f"{agent_id}_public.pem"
            
            if not public_key_path.exists():
                logger.warning(f"Public key not found for agent: {agent_id}")
                return None
            
            with open(public_key_path, 'rb') as f:
                public_pem = f.read()
            
            public_key = serialization.load_pem_public_key(
                public_pem,
                backend=self.backend
            )
            
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise ValueError("Loaded key is not Ed25519 public key")
            
            logger.info(f"Loaded public key for agent: {agent_id}")
            return public_key
            
        except Exception as e:
            logger.error(f"Failed to load public key for {agent_id}: {str(e)}")
            return None
    
    def get_public_key_bytes(self, public_key: ed25519.Ed25519PublicKey) -> bytes:
        """
        Get raw bytes of public key.
        
        Args:
            public_key: Ed25519 public key
            
        Returns:
            Raw bytes of the public key
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_public_key_base64(self, public_key: ed25519.Ed25519PublicKey) -> str:
        """
        Get base64 encoded public key.
        
        Args:
            public_key: Ed25519 public key
            
        Returns:
            Base64 encoded public key string
        """
        key_bytes = self.get_public_key_bytes(public_key)
        return base64.b64encode(key_bytes).decode('utf-8')
    
    def rotate_keypair(self, agent_id: str, old_password: Optional[bytes] = None, 
                      new_password: Optional[bytes] = None) -> bool:
        """
        Rotate keypair for an agent.
        
        Args:
            agent_id: Agent identifier
            old_password: Password for old private key
            new_password: Password for new private key
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Load old private key
            old_private_key = self.load_private_key(agent_id, old_password)
            if not old_private_key:
                logger.error(f"Cannot rotate keys - old key not found for {agent_id}")
                return False
            
            # Generate new keypair
            new_private_key, new_public_key = self.generate_keypair(agent_id)
            
            # Backup old keys
            self._backup_old_keys(agent_id)
            
            # Save new keys
            success = self.save_keypair(agent_id, new_private_key, new_public_key, 
                                      encrypt=bool(new_password))
            
            if success:
                logger.info(f"Successfully rotated keypair for agent: {agent_id}")
            else:
                # Restore backup if rotation failed
                self._restore_backup_keys(agent_id)
                logger.error(f"Failed to rotate keys for {agent_id}, restored backup")
            
            return success
            
        except Exception as e:
            logger.error(f"Key rotation failed for {agent_id}: {str(e)}")
            return False
    
    def delete_keypair(self, agent_id: str) -> bool:
        """
        Delete keypair for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            private_key_path = self.keys_directory / f"{agent_id}_private.pem"
            public_key_path = self.keys_directory / f"{agent_id}_public.pem"
            
            deleted_files = []
            
            if private_key_path.exists():
                private_key_path.unlink()
                deleted_files.append(str(private_key_path))
            
            if public_key_path.exists():
                public_key_path.unlink()
                deleted_files.append(str(public_key_path))
            
            if deleted_files:
                logger.info(f"Deleted key files for agent {agent_id}: {deleted_files}")
                return True
            else:
                logger.warning(f"No key files found to delete for agent: {agent_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to delete keys for {agent_id}: {str(e)}")
            return False
    
    def list_agents(self) -> list:
        """
        List all agents with stored keys.
        
        Returns:
            List of agent IDs
        """
        agents = []
        
        try:
            for file_path in self.keys_directory.glob("*_public.pem"):
                agent_id = file_path.stem.replace("_public", "")
                agents.append(agent_id)
            
            logger.info(f"Found {len(agents)} agents with stored keys")
            return sorted(agents)
            
        except Exception as e:
            logger.error(f"Failed to list agents: {str(e)}")
            return []
    
    def _backup_old_keys(self, agent_id: str) -> bool:
        """Create backup of existing keys."""
        try:
            backup_dir = self.keys_directory / "backups"
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = int(os.path.getmtime())
            
            private_key_path = self.keys_directory / f"{agent_id}_private.pem"
            public_key_path = self.keys_directory / f"{agent_id}_public.pem"
            
            if private_key_path.exists():
                backup_path = backup_dir / f"{agent_id}_private_{timestamp}.pem"
                private_key_path.rename(backup_path)
            
            if public_key_path.exists():
                backup_path = backup_dir / f"{agent_id}_public_{timestamp}.pem"
                public_key_path.rename(backup_path)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to backup keys for {agent_id}: {str(e)}")
            return False
    
    def _restore_backup_keys(self, agent_id: str) -> bool:
        """Restore most recent backup of keys."""
        try:
            backup_dir = self.keys_directory / "backups"
            
            # Find most recent backup
            private_backups = list(backup_dir.glob(f"{agent_id}_private_*.pem"))
            public_backups = list(backup_dir.glob(f"{agent_id}_public_*.pem"))
            
            if not private_backups or not public_backups:
                return False
            
            # Get most recent backup
            latest_private = max(private_backups, key=os.path.getmtime)
            latest_public = max(public_backups, key=os.path.getmtime)
            
            # Restore to main directory
            private_key_path = self.keys_directory / f"{agent_id}_private.pem"
            public_key_path = self.keys_directory / f"{agent_id}_public.pem"
            
            latest_private.rename(private_key_path)
            latest_public.rename(public_key_path)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore backup keys for {agent_id}: {str(e)}")
            return False
