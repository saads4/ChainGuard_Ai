"""
Signature Utils - Sign and verify message signatures

Handles cryptographic signature operations for ChainGuardAI:
- Ed25519 message signing and verification
- JSON-LD signature creation and verification
- Message integrity verification
- Key-based authentication
"""

import json
import hashlib
import time
from typing import Dict, Any, Optional, Union, List, Tuple
from datetime import datetime
from loguru import logger
from .key_manager import KeyManager, ed25519


class SignatureUtils:
    """Utility class for cryptographic signature operations."""
    
    def __init__(self, key_manager: KeyManager):
        """
        Initialize SignatureUtils.
        
        Args:
            key_manager: KeyManager instance for key operations
        """
        self.key_manager = key_manager
    
    def sign_message(self, private_key: ed25519.Ed25519PrivateKey, 
                     message: Union[str, bytes, Dict[str, Any]]) -> bytes:
        """
        Sign a message with Ed25519 private key.
        
        Args:
            private_key: Ed25519 private key
            message: Message to sign (string, bytes, or dict)
            
        Returns:
            Signature bytes
        """
        try:
            # Convert message to bytes
            if isinstance(message, dict):
                message_bytes = json.dumps(message, sort_keys=True).encode('utf-8')
            elif isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message
            
            # Sign the message
            signature = private_key.sign(message_bytes)
            
            logger.debug(f"Signed message of {len(message_bytes)} bytes")
            return signature
            
        except Exception as e:
            logger.error(f"Failed to sign message: {str(e)}")
            raise
    
    def verify_message(self, public_key: ed25519.Ed25519PublicKey, 
                      message: Union[str, bytes, Dict[str, Any]], 
                      signature: bytes) -> bool:
        """
        Verify a message signature.
        
        Args:
            public_key: Ed25519 public key
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Convert message to bytes
            if isinstance(message, dict):
                message_bytes = json.dumps(message, sort_keys=True).encode('utf-8')
            elif isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message
            
            # Verify signature
            public_key.verify(signature, message_bytes)
            
            logger.debug(f"Verified message signature of {len(message_bytes)} bytes")
            return True
            
        except Exception as e:
            logger.warning(f"Signature verification failed: {str(e)}")
            return False
    
    def sign_json_ld(self, private_key: ed25519.Ed25519PrivateKey, 
                    data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign JSON-LD data using Linked Data Signatures.
        
        Args:
            private_key: Ed25519 private key
            data: JSON-LD data to sign
            
        Returns:
            Signed JSON-LD data with proof
        """
        try:
            # Create a copy of the data
            signed_data = data.copy()
            
            # Create proof object
            proof = {
                "@context": "https://w3id.org/security/v1",
                "type": "Ed25519Signature2018",
                "created": datetime.utcnow().isoformat() + "Z",
                "verificationMethod": f"{data.get('issuer', 'unknown')}#key-1",
                "proofPurpose": "assertionMethod"
            }
            
            # Create normalized data for signing
            # For simplicity, we'll use a basic canonicalization
            # In production, use proper JSON-LD canonicalization
            canonical_data = self._canonicalize_json_ld(data)
            
            # Sign the canonical data
            signature = self.sign_message(private_key, canonical_data)
            
            # Add signature to proof
            import base64
            proof["jws"] = base64.b64encode(signature).decode('utf-8')
            
            # Add proof to signed data
            signed_data["proof"] = proof
            
            logger.info("Created JSON-LD signature")
            return signed_data
            
        except Exception as e:
            logger.error(f"Failed to sign JSON-LD data: {str(e)}")
            raise
    
    def verify_json_ld_signature(self, signed_data: Dict[str, Any], 
                               issuer_did: Optional[str] = None) -> bool:
        """
        Verify JSON-LD signature.
        
        Args:
            signed_data: Signed JSON-LD data
            issuer_did: Expected issuer DID (optional)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Extract proof
            proof = signed_data.get("proof")
            if not proof:
                logger.error("No proof found in signed data")
                return False
            
            # Extract signature
            jws = proof.get("jws")
            if not jws:
                logger.error("No signature found in proof")
                return False
            
            import base64
            signature = base64.b64decode(jws)
            
            # Get verification method
            verification_method = proof.get("verificationMethod")
            if not verification_method:
                logger.error("No verification method found in proof")
                return False
            
            # Extract issuer DID from verification method
            if issuer_did is None:
                issuer_did = verification_method.split("#")[0]
            
            # Get public key for issuer
            # This would typically involve resolving the DID
            # For now, we'll assume the key manager can get it
            issuer_id = issuer_did.split(":")[-1]  # Extract agent ID
            public_key = self.key_manager.load_public_key(issuer_id)
            
            if not public_key:
                logger.error(f"Cannot load public key for issuer: {issuer_did}")
                return False
            
            # Create copy of data without proof
            unsigned_data = signed_data.copy()
            del unsigned_data["proof"]
            
            # Canonicalize the unsigned data
            canonical_data = self._canonicalize_json_ld(unsigned_data)
            
            # Verify signature
            return self.verify_message(public_key, canonical_data, signature)
            
        except Exception as e:
            logger.error(f"Failed to verify JSON-LD signature: {str(e)}")
            return False
    
    def _canonicalize_json_ld(self, data: Dict[str, Any]) -> str:
        """
        Create canonical representation of JSON-LD data.
        
        Args:
            data: JSON-LD data to canonicalize
            
        Returns:
            Canonical string representation
        """
        try:
            # Simple canonicalization - sort keys and remove whitespace
            # In production, use proper JSON-LD canonicalization algorithm
            canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
            return canonical
            
        except Exception as e:
            logger.error(f"Failed to canonicalize JSON-LD: {str(e)}")
            raise
    
    def create_message_signature(self, agent_did: str, private_key: ed25519.Ed25519PrivateKey,
                               message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a signed message for inter-agent communication.
        
        Args:
            agent_did: DID of the signing agent
            private_key: Agent's private key
            message: Message content
            
        Returns:
            Signed message dictionary
        """
        try:
            # Create signed message structure
            signed_message = {
                "id": f"msg:{int(time.time())}:{hash(str(message)) % 10000}",
                "type": "AgentMessage",
                "sender": agent_did,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "content": message
            }
            
            # Sign the message
            signature = self.sign_message(private_key, signed_message)
            
            # Add signature
            import base64
            signed_message["signature"] = base64.b64encode(signature).decode('utf-8')
            
            logger.info(f"Created signed message from agent: {agent_did}")
            return signed_message
            
        except Exception as e:
            logger.error(f"Failed to create message signature: {str(e)}")
            raise
    
    def verify_message_signature(self, signed_message: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Verify a signed message.
        
        Args:
            signed_message: Signed message dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Extract required fields
            sender_did = signed_message.get("sender")
            signature_b64 = signed_message.get("signature")
            content = signed_message.get("content")
            
            if not all([sender_did, signature_b64, content is not None]):
                return False, "Missing required fields in signed message"
            
            # Get sender's public key
            sender_id = sender_did.split(":")[-1]
            public_key = self.key_manager.load_public_key(sender_id)
            
            if not public_key:
                return False, f"Cannot load public key for sender: {sender_did}"
            
            # Create message copy without signature
            unsigned_message = signed_message.copy()
            del unsigned_message["signature"]
            
            # Verify signature
            import base64
            signature = base64.b64decode(signature_b64)
            
            is_valid = self.verify_message(public_key, unsigned_message, signature)
            
            if is_valid:
                logger.info(f"Verified message signature from: {sender_did}")
                return True, None
            else:
                return False, "Invalid signature"
                
        except Exception as e:
            logger.error(f"Failed to verify message signature: {str(e)}")
            return False, f"Verification error: {str(e)}"
    
    def create_hash_chain_link(self, previous_hash: str, data: Dict[str, Any]) -> str:
        """
        Create a hash chain link for audit logging.
        
        Args:
            previous_hash: Hash of previous entry
            data: Data to include in this entry
            
        Returns:
            New hash value
        """
        try:
            # Create chain data
            chain_data = {
                "previous_hash": previous_hash,
                "data": data,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            # Create hash
            hash_input = json.dumps(chain_data, sort_keys=True).encode('utf-8')
            new_hash = hashlib.sha256(hash_input).hexdigest()
            
            logger.debug(f"Created hash chain link: {new_hash[:16]}...")
            return new_hash
            
        except Exception as e:
            logger.error(f"Failed to create hash chain link: {str(e)}")
            raise
    
    def verify_hash_chain(self, entries: List[Dict[str, Any]]) -> bool:
        """
        Verify integrity of a hash chain.
        
        Args:
            entries: List of hash chain entries
            
        Returns:
            True if chain is valid, False otherwise
        """
        try:
            if not entries:
                logger.warning("Empty hash chain")
                return True
            
            # Verify each link in the chain
            for i, entry in enumerate(entries):
                expected_hash = entry.get("hash")
                previous_hash = entry.get("previous_hash", "")
                data = entry.get("data", {})
                
                # Recalculate hash
                calculated_hash = self.create_hash_chain_link(previous_hash, data)
                
                if calculated_hash != expected_hash:
                    logger.error(f"Hash chain broken at entry {i}")
                    return False
            
            logger.info("Hash chain verification successful")
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify hash chain: {str(e)}")
            return False
    
    def create_key_fingerprint(self, public_key: ed25519.Ed25519PublicKey) -> str:
        """
        Create a fingerprint for a public key.
        
        Args:
            public_key: Ed25519 public key
            
        Returns:
            Key fingerprint string
        """
        try:
            # Get public key bytes
            key_bytes = self.key_manager.get_public_key_bytes(public_key)
            
            # Create SHA-256 hash
            fingerprint = hashlib.sha256(key_bytes).hexdigest()
            
            # Return first 16 characters as fingerprint
            return fingerprint[:16]
            
        except Exception as e:
            logger.error(f"Failed to create key fingerprint: {str(e)}")
            raise
    
    def sign_batch(self, private_key: ed25519.Ed25519PrivateKey, 
                  messages: List[Union[str, bytes, Dict[str, Any]]]) -> List[bytes]:
        """
        Sign multiple messages efficiently.
        
        Args:
            private_key: Ed25519 private key
            messages: List of messages to sign
            
        Returns:
            List of signatures
        """
        try:
            signatures = []
            
            for message in messages:
                signature = self.sign_message(private_key, message)
                signatures.append(signature)
            
            logger.info(f"Signed batch of {len(messages)} messages")
            return signatures
            
        except Exception as e:
            logger.error(f"Failed to sign batch: {str(e)}")
            raise
    
    def verify_batch(self, public_key: ed25519.Ed25519PublicKey,
                    messages: List[Union[str, bytes, Dict[str, Any]]],
                    signatures: List[bytes]) -> List[bool]:
        """
        Verify multiple message signatures.
        
        Args:
            public_key: Ed25519 public key
            messages: List of original messages
            signatures: List of signatures to verify
            
        Returns:
            List of verification results
        """
        try:
            if len(messages) != len(signatures):
                raise ValueError("Messages and signatures must have same length")
            
            results = []
            
            for message, signature in zip(messages, signatures):
                is_valid = self.verify_message(public_key, message, signature)
                results.append(is_valid)
            
            valid_count = sum(results)
            logger.info(f"Verified batch: {valid_count}/{len(messages)} valid")
            return results
            
        except Exception as e:
            logger.error(f"Failed to verify batch: {str(e)}")
            raise
