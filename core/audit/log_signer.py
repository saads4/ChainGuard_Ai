"""
Log Signer - Signs each log entry with ChainGuardAI's private key

Handles cryptographic signing of audit log entries for ChainGuardAI:
- Ed25519 digital signatures
- Entry signing and verification
- Key management
- Signature validation
"""

import json
import base64
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from loguru import logger


class LogSigner:
    """Handles cryptographic signing of audit log entries."""
    
    def __init__(self, key_path: str, is_private: bool = True):
        """
        Initialize LogSigner.
        
        Args:
            key_path: Path to the key file
            is_private: Whether this is a private key (True) or public key (False)
        """
        self.key_path = Path(key_path)
        self.is_private = is_private
        self.key = None
        self.key_available = False
        
        # Load key
        self._load_key()
        
        logger.info(f"Initialized LogSigner with {'private' if is_private else 'public'} key: {key_path}")
    
    def _load_key(self) -> None:
        """Load the cryptographic key."""
        try:
            if not self.key_path.exists():
                logger.warning(f"Key file not found: {self.key_path}")
                return
            
            with open(self.key_path, 'rb') as f:
                key_data = f.read()
            
            if self.is_private:
                self.key = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )
                
                if not isinstance(self.key, ed25519.Ed25519PrivateKey):
                    logger.error("Loaded key is not Ed25519 private key")
                    return
            else:
                self.key = serialization.load_pem_public_key(
                    key_data,
                    backend=default_backend()
                )
                
                if not isinstance(self.key, ed25519.Ed25519PublicKey):
                    logger.error("Loaded key is not Ed25519 public key")
                    return
            
            self.key_available = True
            logger.debug(f"Successfully loaded {'private' if self.is_private else 'public'} key")
            
        except Exception as e:
            logger.error(f"Failed to load key: {str(e)}")
    
    def sign_entry(self, entry: Dict[str, Any]) -> str:
        """
        Sign an audit log entry.
        
        Args:
            entry: Entry to sign
            
        Returns:
            Base64 encoded signature
        """
        try:
            if not self.key_available or not self.is_private:
                logger.error("Private key not available for signing")
                return ""
            
            # Create canonical representation of entry
            canonical_entry = self._create_canonical_entry(entry)
            
            # Sign the canonical entry
            signature_bytes = self.key.sign(canonical_entry.encode('utf-8'))
            
            # Return base64 encoded signature
            signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
            
            logger.debug(f"Signed entry: {entry.get('entry_id', 'unknown')}")
            return signature_b64
            
        except Exception as e:
            logger.error(f"Failed to sign entry: {str(e)}")
            return ""
    
    def verify_entry(self, entry: Dict[str, Any]) -> bool:
        """
        Verify the signature of an audit log entry.
        
        Args:
            entry: Entry to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if not self.key_available or self.is_private:
                logger.error("Public key not available for verification")
                return False
            
            # Get signature from entry
            signature_b64 = entry.get("signature", "")
            if not signature_b64:
                logger.warning("No signature found in entry")
                return False
            
            # Decode signature
            try:
                signature_bytes = base64.b64decode(signature_b64)
            except Exception as e:
                logger.error(f"Failed to decode signature: {str(e)}")
                return False
            
            # Create canonical representation of entry
            canonical_entry = self._create_canonical_entry(entry)
            
            # Verify signature
            try:
                self.key.verify(signature_bytes, canonical_entry.encode('utf-8'))
                logger.debug(f"Verified entry: {entry.get('entry_id', 'unknown')}")
                return True
            except Exception:
                logger.warning(f"Invalid signature for entry: {entry.get('entry_id', 'unknown')}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to verify entry: {str(e)}")
            return False
    
    def _create_canonical_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a canonical representation of an entry for signing.
        
        Args:
            entry: Original entry
            
        Returns:
            Canonical entry dictionary
        """
        try:
            # Create a copy without signature
            canonical = entry.copy()
            canonical.pop("signature", None)
            
            # Sort keys for consistent ordering
            canonical_sorted = {}
            for key in sorted(canonical.keys()):
                value = canonical[key]
                
                # Handle nested dictionaries
                if isinstance(value, dict):
                    canonical_sorted[key] = self._sort_dict_keys(value)
                # Handle lists
                elif isinstance(value, list):
                    canonical_sorted[key] = self._process_list(value)
                else:
                    canonical_sorted[key] = value
            
            return canonical_sorted
            
        except Exception as e:
            logger.error(f"Failed to create canonical entry: {str(e)}")
            return entry
    
    def _sort_dict_keys(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sort dictionary keys."""
        try:
            sorted_dict = {}
            for key in sorted(d.keys()):
                value = d[key]
                if isinstance(value, dict):
                    sorted_dict[key] = self._sort_dict_keys(value)
                elif isinstance(value, list):
                    sorted_dict[key] = self._process_list(value)
                else:
                    sorted_dict[key] = value
            return sorted_dict
        except Exception:
            return d
    
    def _process_list(self, lst: list) -> list:
        """Process list items for canonical representation."""
        try:
            processed = []
            for item in lst:
                if isinstance(item, dict):
                    processed.append(self._sort_dict_keys(item))
                elif isinstance(item, list):
                    processed.append(self._process_list(item))
                else:
                    processed.append(item)
            return processed
        except Exception:
            return lst
    
    def sign_data(self, data: Dict[str, Any]) -> str:
        """
        Sign arbitrary data.
        
        Args:
            data: Data to sign
            
        Returns:
            Base64 encoded signature
        """
        try:
            if not self.key_available or not self.is_private:
                logger.error("Private key not available for signing")
                return ""
            
            # Create canonical representation
            canonical_data = self._sort_dict_keys(data)
            
            # Sign the canonical data
            signature_bytes = self.key.sign(json.dumps(canonical_data, separators=(',', ':')).encode('utf-8'))
            
            # Return base64 encoded signature
            signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
            
            return signature_b64
            
        except Exception as e:
            logger.error(f"Failed to sign data: {str(e)}")
            return ""
    
    def verify_data(self, data: Dict[str, Any], signature_b64: str) -> bool:
        """
        Verify signature on arbitrary data.
        
        Args:
            data: Original data
            signature_b64: Base64 encoded signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if not self.key_available or self.is_private:
                logger.error("Public key not available for verification")
                return False
            
            # Decode signature
            signature_bytes = base64.b64decode(signature_b64)
            
            # Create canonical representation
            canonical_data = self._sort_dict_keys(data)
            
            # Verify signature
            try:
                self.key.verify(signature_bytes, json.dumps(canonical_data, separators=(',', ':')).encode('utf-8'))
                return True
            except Exception:
                return False
                
        except Exception as e:
            logger.error(f"Failed to verify data: {str(e)}")
            return False
    
    def create_key_pair(self, output_dir: str = "./keys") -> Tuple[str, str]:
        """
        Create a new Ed25519 key pair.
        
        Args:
            output_dir: Directory to save keys
            
        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Generate key pair
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            # Save private key
            private_key_path = output_path / "audit_private_key.pem"
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            
            # Save public key
            public_key_path = output_path / "audit_public_key.pem"
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            
            # Set file permissions
            import os
            os.chmod(private_key_path, 0o600)
            os.chmod(public_key_path, 0o644)
            
            logger.info(f"Created key pair: {private_key_path}, {public_key_path}")
            return str(private_key_path), str(public_key_path)
            
        except Exception as e:
            logger.error(f"Failed to create key pair: {str(e)}")
            return "", ""
    
    def get_key_info(self) -> Dict[str, Any]:
        """Get information about the loaded key."""
        try:
            if not self.key_available:
                return {"available": False}
            
            info = {
                "available": True,
                "type": "private" if self.is_private else "public",
                "algorithm": "Ed25519",
                "key_path": str(self.key_path)
            }
            
            if self.is_private:
                public_key = self.key.public_key()
                key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                info["public_key_bytes"] = base64.b64encode(key_bytes).decode('utf-8')
            else:
                key_bytes = self.key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                info["public_key_bytes"] = base64.b64encode(key_bytes).decode('utf-8')
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get key info: {str(e)}")
            return {"available": False, "error": str(e)}
    
    def is_available(self) -> bool:
        """Check if the key is available for use."""
        return self.key_available
    
    def get_status(self) -> Dict[str, Any]:
        """Get signer status."""
        return {
            "status": "active",
            "key_available": self.key_available,
            "key_type": "private" if self.is_private else "public",
            "key_path": str(self.key_path),
            "key_info": self.get_key_info()
        }
    
    def reload_key(self) -> bool:
        """Reload the key from file."""
        try:
            self._load_key()
            logger.info(f"Reloaded key from {self.key_path}")
            return self.key_available
        except Exception as e:
            logger.error(f"Failed to reload key: {str(e)}")
            return False
    
    def export_public_key(self, output_path: str) -> bool:
        """Export public key to file."""
        try:
            if not self.key_available or self.is_private:
                logger.error("Private key not available for public key export")
                return False
            
            public_key = self.key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(output_path, 'wb') as f:
                f.write(public_pem)
            
            logger.info(f"Exported public key to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export public key: {str(e)}")
            return False
    
    def verify_key_pair(self, private_key_path: str, public_key_path: str) -> bool:
        """Verify that a key pair matches."""
        try:
            # Load keys
            with open(private_key_path, 'rb') as f:
                private_pem = f.read()
            
            with open(public_key_path, 'rb') as f:
                public_pem = f.read()
            
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            
            loaded_public_key = serialization.load_pem_public_key(
                public_pem,
                backend=default_backend()
            )
            
            # Check if keys match
            derived_public_key = private_key.public_key()
            
            # Compare public keys
            derived_bytes = derived_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            loaded_bytes = loaded_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            return derived_bytes == loaded_bytes
            
        except Exception as e:
            logger.error(f"Failed to verify key pair: {str(e)}")
            return False
