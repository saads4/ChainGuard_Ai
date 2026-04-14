"""
DID Manager - Creates and Manages Decentralized Identifiers

Handles DID operations for ChainGuardAI agents:
- DID creation and resolution
- DID document management
- DID method implementation (did:web)
- DID authentication and verification
"""

import json
import hashlib
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
from pathlib import Path
from loguru import logger
from .key_manager import KeyManager, ed25519


class DIDManager:
    """Manages Decentralized Identifiers for agents."""
    
    def __init__(self, key_manager: KeyManager, did_method: str = "did:web"):
        """
        Initialize DIDManager.
        
        Args:
            key_manager: KeyManager instance for cryptographic operations
            did_method: DID method to use (default: did:web)
        """
        self.key_manager = key_manager
        self.did_method = did_method
        self.did_documents = {}  # In-memory cache
        
    def create_did(self, agent_id: str, domain: str, 
                   public_key: ed25519.Ed25519PublicKey) -> str:
        """
        Create a DID for an agent.
        
        Args:
            agent_id: Unique identifier for the agent
            domain: Domain for did:web method
            public_key: Agent's public key
            
        Returns:
            DID string
        """
        try:
            if self.did_method == "did:web":
                did = f"did:web:{domain}:agent:{agent_id}"
            else:
                raise ValueError(f"Unsupported DID method: {self.did_method}")
            
            # Create DID document
            did_document = self._create_did_document(did, public_key)
            
            # Store in cache
            self.did_documents[did] = did_document
            
            logger.info(f"Created DID for agent {agent_id}: {did}")
            return did
            
        except Exception as e:
            logger.error(f"Failed to create DID for {agent_id}: {str(e)}")
            raise
    
    def _create_did_document(self, did: str, public_key: ed25519.Ed25519PublicKey) -> Dict[str, Any]:
        """
        Create a DID document for the agent.
        
        Args:
            did: The DID string
            public_key: Agent's public key
            
        Returns:
            DID document dictionary
        """
        # Get public key in base64 format
        public_key_b64 = self.key_manager.get_public_key_base64(public_key)
        
        # Create key ID
        key_id = f"{did}#key-1"
        
        did_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/v1"
            ],
            "id": did,
            "verificationMethod": [
                {
                    "id": key_id,
                    "type": "Ed25519VerificationKey2018",
                    "controller": did,
                    "publicKeyBase64": public_key_b64
                }
            ],
            "authentication": [key_id],
            "assertionMethod": [key_id],
            "capabilityInvocation": [key_id],
            "capabilityDelegation": [key_id]
        }
        
        return did_document
    
    def resolve_did(self, did: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a DID to its document.
        
        Args:
            did: DID string to resolve
            
        Returns:
            DID document or None if not found
        """
        try:
            # Check cache first
            if did in self.did_documents:
                logger.debug(f"Resolved DID from cache: {did}")
                return self.did_documents[did]
            
            # For did:web, try to resolve from domain
            if did.startswith("did:web:"):
                document = self._resolve_web_did(did)
                if document:
                    self.did_documents[did] = document
                    return document
            
            logger.warning(f"DID not found: {did}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to resolve DID {did}: {str(e)}")
            return None
    
    def _resolve_web_did(self, did: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a did:web DID.
        
        Args:
            did: did:web DID string
            
        Returns:
            DID document or None if not found
        """
        try:
            # Parse did:web format
            parts = did.replace("did:web:", "").split(":")
            domain = parts[0]
            path = "/".join(parts[1:]) if len(parts) > 1 else ""
            
            # For now, return a placeholder document
            # In production, this would fetch from the actual domain
            logger.warning(f"Web DID resolution not implemented for domain: {domain}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to resolve web DID {did}: {str(e)}")
            return None
    
    def verify_did_ownership(self, did: str, message: bytes, 
                           signature: bytes) -> bool:
        """
        Verify that a DID owner signed a message.
        
        Args:
            did: DID of the supposed signer
            message: Original message bytes
            signature: Signature bytes
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Resolve DID document
            did_document = self.resolve_did(did)
            if not did_document:
                logger.error(f"Cannot verify ownership - DID not found: {did}")
                return False
            
            # Extract public key
            public_key = self._extract_public_key_from_document(did_document)
            if not public_key:
                logger.error(f"Cannot extract public key from DID document: {did}")
                return False
            
            # Verify signature
            try:
                public_key.verify(signature, message)
                logger.info(f"Verified DID ownership: {did}")
                return True
            except Exception:
                logger.warning(f"Invalid signature for DID: {did}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to verify DID ownership for {did}: {str(e)}")
            return False
    
    def _extract_public_key_from_document(self, did_document: Dict[str, Any]) -> Optional[ed25519.Ed25519PublicKey]:
        """
        Extract Ed25519 public key from DID document.
        
        Args:
            did_document: DID document dictionary
            
        Returns:
            Ed25519 public key or None if not found
        """
        try:
            verification_methods = did_document.get("verificationMethod", [])
            
            for vm in verification_methods:
                if vm.get("type") == "Ed25519VerificationKey2018":
                    public_key_b64 = vm.get("publicKeyBase64")
                    if public_key_b64:
                        import base64
                        from cryptography.hazmat.primitives.asymmetric import ed25519
                        from cryptography.hazmat.primitives import serialization
                        from cryptography.hazmat.backends import default_backend
                        
                        # Decode base64 public key
                        key_bytes = base64.b64decode(public_key_b64)
                        
                        # Create Ed25519 public key from bytes
                        public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
                        
                        return public_key
            
            logger.error("No Ed25519 verification method found in DID document")
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract public key from DID document: {str(e)}")
            return None
    
    def update_did_document(self, did: str, new_document: Dict[str, Any]) -> bool:
        """
        Update a DID document.
        
        Args:
            did: DID string
            new_document: New DID document
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate document structure
            if not self._validate_did_document(new_document):
                logger.error(f"Invalid DID document structure for {did}")
                return False
            
            # Update cache
            self.did_documents[did] = new_document
            
            logger.info(f"Updated DID document: {did}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update DID document for {did}: {str(e)}")
            return False
    
    def _validate_did_document(self, document: Dict[str, Any]) -> bool:
        """
        Validate DID document structure.
        
        Args:
            document: DID document to validate
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ["@context", "id", "verificationMethod"]
        
        for field in required_fields:
            if field not in document:
                logger.error(f"Missing required field in DID document: {field}")
                return False
        
        # Check verification methods
        verification_methods = document.get("verificationMethod", [])
        if not verification_methods:
            logger.error("No verification methods in DID document")
            return False
        
        # Check each verification method
        for vm in verification_methods:
            vm_required = ["id", "type", "controller"]
            for field in vm_required:
                if field not in vm:
                    logger.error(f"Missing required field in verification method: {field}")
                    return False
        
        return True
    
    def deactivate_did(self, did: str) -> bool:
        """
        Deactivate a DID.
        
        Args:
            did: DID string to deactivate
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if did not in self.did_documents:
                logger.warning(f"DID not found for deactivation: {did}")
                return False
            
            # Remove from cache
            del self.did_documents[did]
            
            logger.info(f"Deactivated DID: {did}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deactivate DID {did}: {str(e)}")
            return False
    
    def list_active_dids(self) -> List[str]:
        """
        List all active DIDs.
        
        Returns:
            List of DID strings
        """
        return list(self.did_documents.keys())
    
    def get_did_methods(self) -> List[str]:
        """
        Get supported DID methods.
        
        Returns:
            List of supported DID method strings
        """
        return ["did:web"]
    
    def export_did_document(self, did: str, file_path: str) -> bool:
        """
        Export DID document to file.
        
        Args:
            did: DID string
            file_path: Path to save the document
            
        Returns:
            True if successful, False otherwise
        """
        try:
            document = self.resolve_did(did)
            if not document:
                logger.error(f"Cannot export - DID not found: {did}")
                return False
            
            with open(file_path, 'w') as f:
                json.dump(document, f, indent=2)
            
            logger.info(f"Exported DID document to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export DID document for {did}: {str(e)}")
            return False
    
    def import_did_document(self, file_path: str) -> Optional[str]:
        """
        Import DID document from file.
        
        Args:
            file_path: Path to the document file
            
        Returns:
            DID string if successful, None otherwise
        """
        try:
            with open(file_path, 'r') as f:
                document = json.load(f)
            
            did = document.get("id")
            if not did:
                logger.error("No DID found in document")
                return None
            
            if not self._validate_did_document(document):
                logger.error("Invalid DID document structure")
                return None
            
            self.did_documents[did] = document
            logger.info(f"Imported DID document: {did}")
            return did
            
        except Exception as e:
            logger.error(f"Failed to import DID document: {str(e)}")
            return None
