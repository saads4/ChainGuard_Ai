"""
VC Verifier - Verifies VCs on every inter-agent message

Handles Verifiable Credential verification for ChainGuardAI:
- VC signature verification
- Credential validation and expiration checking
- Capability verification
- Trust score assessment
"""

import json
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from loguru import logger
from .did_manager import DIDManager
from .signature_utils import SignatureUtils


class VCVerifier:
    """Verifies Verifiable Credentials for inter-agent communication."""
    
    def __init__(self, did_manager: DIDManager, signature_utils: SignatureUtils):
        """
        Initialize VCVerifier.
        
        Args:
            did_manager: DIDManager for resolving DIDs
            signature_utils: SignatureUtils for signature verification
        """
        self.did_manager = did_manager
        self.signature_utils = signature_utils
        self.verified_credentials_cache = {}  # Cache for verified credentials
        
    def verify_credential(self, credential: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Verify a Verifiable Credential.
        
        Args:
            credential: Verifiable credential dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Check credential structure
            if not self._validate_credential_structure(credential):
                return False, "Invalid credential structure"
            
            # Check expiration
            if not self._check_expiration(credential):
                return False, "Credential has expired"
            
            # Check revocation
            if credential.get("revoked", False):
                return False, "Credential has been revoked"
            
            # Verify signature
            if not self._verify_credential_signature(credential):
                return False, "Invalid credential signature"
            
            # Verify issuer
            if not self._verify_issuer(credential):
                return False, "Invalid issuer"
            
            logger.info("Credential verification successful")
            return True, None
            
        except Exception as e:
            logger.error(f"Credential verification failed: {str(e)}")
            return False, f"Verification error: {str(e)}"
    
    def _validate_credential_structure(self, credential: Dict[str, Any]) -> bool:
        """Validate basic credential structure."""
        required_fields = ["@context", "id", "type", "issuer", "issuanceDate", "credentialSubject"]
        
        for field in required_fields:
            if field not in credential:
                logger.error(f"Missing required field in credential: {field}")
                return False
        
        # Check credential subject structure
        subject = credential.get("credentialSubject", {})
        if "id" not in subject:
            logger.error("Missing subject ID in credential")
            return False
        
        return True
    
    def _check_expiration(self, credential: Dict[str, Any]) -> bool:
        """Check if credential has expired."""
        expiration_date = credential.get("expirationDate")
        if not expiration_date:
            # No expiration date means it doesn't expire
            return True
        
        try:
            exp_datetime = datetime.fromisoformat(expiration_date.replace("Z", "+00:00"))
            return datetime.utcnow() <= exp_datetime
        except Exception as e:
            logger.error(f"Failed to parse expiration date: {str(e)}")
            return False
    
    def _verify_credential_signature(self, credential: Dict[str, Any]) -> bool:
        """Verify the credential's signature."""
        try:
            # Get issuer DID
            issuer_did = credential.get("issuer")
            if not issuer_did:
                logger.error("No issuer found in credential")
                return False
            
            # Get proof from credential
            proof = credential.get("proof")
            if not proof:
                logger.error("No proof found in credential")
                return False
            
            # Verify signature using signature utils
            return self.signature_utils.verify_json_ld_signature(credential, issuer_did)
            
        except Exception as e:
            logger.error(f"Signature verification failed: {str(e)}")
            return False
    
    def _verify_issuer(self, credential: Dict[str, Any]) -> bool:
        """Verify the issuer's DID."""
        try:
            issuer_did = credential.get("issuer")
            if not issuer_did:
                logger.error("No issuer DID found")
                return False
            
            # Resolve issuer DID
            did_document = self.did_manager.resolve_did(issuer_did)
            if not did_document:
                logger.error(f"Cannot resolve issuer DID: {issuer_did}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Issuer verification failed: {str(e)}")
            return False
    
    def verify_agent_capabilities(self, agent_did: str, credentials: List[Dict[str, Any]],
                                 required_capabilities: List[str]) -> Tuple[bool, List[str], Optional[str]]:
        """
        Verify that an agent has the required capabilities.
        
        Args:
            agent_did: DID of the agent
            credentials: List of credentials to verify
            required_capabilities: List of required capabilities
            
        Returns:
            Tuple of (has_capabilities, missing_capabilities, error_message)
        """
        try:
            # Verify all credentials
            valid_credentials = []
            for credential in credentials:
                is_valid, error = self.verify_credential(credential)
                if is_valid:
                    valid_credentials.append(credential)
                else:
                    logger.warning(f"Invalid credential: {error}")
            
            # Extract capabilities from valid credentials
            agent_capabilities = set()
            for credential in valid_credentials:
                subject = credential.get("credentialSubject", {})
                capabilities = subject.get("capabilities", [])
                agent_capabilities.update(capabilities)
            
            # Check if all required capabilities are present
            missing_capabilities = []
            for capability in required_capabilities:
                if capability not in agent_capabilities:
                    missing_capabilities.append(capability)
            
            has_all_capabilities = len(missing_capabilities) == 0
            
            if has_all_capabilities:
                logger.info(f"Agent {agent_did} has all required capabilities")
            else:
                logger.warning(f"Agent {agent_did} missing capabilities: {missing_capabilities}")
            
            return has_all_capabilities, missing_capabilities, None
            
        except Exception as e:
            logger.error(f"Capability verification failed: {str(e)}")
            return False, [], f"Verification error: {str(e)}"
    
    def verify_agent_role(self, agent_did: str, credentials: List[Dict[str, Any]],
                        expected_role: str) -> Tuple[bool, Optional[str]]:
        """
        Verify that an agent has the expected role.
        
        Args:
            agent_did: DID of the agent
            credentials: List of credentials to verify
            expected_role: Expected agent role
            
        Returns:
            Tuple of (has_role, error_message)
        """
        try:
            # Verify all credentials
            valid_credentials = []
            for credential in credentials:
                is_valid, error = self.verify_credential(credential)
                if is_valid:
                    valid_credentials.append(credential)
                else:
                    logger.warning(f"Invalid credential: {error}")
            
            # Check for role credential
            for credential in valid_credentials:
                credential_types = credential.get("type", [])
                if "AgentRoleCredential" in credential_types:
                    subject = credential.get("credentialSubject", {})
                    agent_role = subject.get("role")
                    
                    if agent_role == expected_role:
                        logger.info(f"Agent {agent_did} has required role: {expected_role}")
                        return True, None
                    else:
                        logger.warning(f"Agent {agent_did} has role {agent_role}, expected {expected_role}")
                        return False, f"Role mismatch: expected {expected_role}, got {agent_role}"
            
            return False, f"No role credential found for agent {agent_did}"
            
        except Exception as e:
            logger.error(f"Role verification failed: {str(e)}")
            return False, f"Verification error: {str(e)}"
    
    def verify_agent_trust(self, agent_did: str, credentials: List[Dict[str, Any]],
                          min_trust_level: str = "medium", min_trust_score: float = 0.5) -> Tuple[bool, float, Optional[str]]:
        """
        Verify an agent's trust level and score.
        
        Args:
            agent_did: DID of the agent
            credentials: List of credentials to verify
            min_trust_level: Minimum required trust level
            min_trust_score: Minimum required trust score
            
        Returns:
            Tuple of (is_trusted, trust_score, error_message)
        """
        try:
            # Verify all credentials
            valid_credentials = []
            for credential in credentials:
                is_valid, error = self.verify_credential(credential)
                if is_valid:
                    valid_credentials.append(credential)
                else:
                    logger.warning(f"Invalid credential: {error}")
            
            # Find trust credential
            trust_score = 0.0
            trust_level = "low"
            
            for credential in valid_credentials:
                credential_types = credential.get("type", [])
                if "AgentTrustCredential" in credential_types:
                    subject = credential.get("credentialSubject", {})
                    trust_score = subject.get("trustScore", 0.0)
                    trust_level = subject.get("trustLevel", "low")
                    break
            
            # Check trust level hierarchy
            trust_hierarchy = {"low": 1, "medium": 2, "high": 3}
            agent_level = trust_hierarchy.get(trust_level, 0)
            required_level = trust_hierarchy.get(min_trust_level, 0)
            
            is_trusted = (agent_level >= required_level) and (trust_score >= min_trust_score)
            
            if is_trusted:
                logger.info(f"Agent {agent_did} meets trust requirements: level={trust_level}, score={trust_score}")
            else:
                logger.warning(f"Agent {agent_did} fails trust requirements: level={trust_level}, score={trust_score}")
            
            return is_trusted, trust_score, None
            
        except Exception as e:
            logger.error(f"Trust verification failed: {str(e)}")
            return False, 0.0, f"Verification error: {str(e)}"
    
    def verify_message_credentials(self, message: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Verify credentials attached to a message.
        
        Args:
            message: Message dictionary with credentials
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Check if message has credentials
            credentials = message.get("credentials", [])
            if not credentials:
                return False, "No credentials attached to message"
            
            # Verify sender's DID
            sender_did = message.get("sender")
            if not sender_did:
                return False, "No sender DID in message"
            
            # Verify all credentials
            for credential in credentials:
                is_valid, error = self.verify_credential(credential)
                if not is_valid:
                    return False, f"Invalid credential: {error}"
                
                # Check if credential belongs to sender
                subject_id = credential.get("credentialSubject", {}).get("id")
                if subject_id != sender_did:
                    return False, f"Credential subject {subject_id} doesn't match sender {sender_did}"
            
            logger.info(f"Message credentials verified for sender: {sender_did}")
            return True, None
            
        except Exception as e:
            logger.error(f"Message credential verification failed: {str(e)}")
            return False, f"Verification error: {str(e)}"
    
    def get_credential_summary(self, credentials: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get a summary of an agent's credentials.
        
        Args:
            credentials: List of credentials to summarize
            
        Returns:
            Credential summary dictionary
        """
        try:
            summary = {
                "total_credentials": len(credentials),
                "valid_credentials": 0,
                "capabilities": set(),
                "roles": set(),
                "trust_level": "low",
                "trust_score": 0.0,
                "issuers": set(),
                "expiration_dates": []
            }
            
            for credential in credentials:
                # Verify credential
                is_valid, error = self.verify_credential(credential)
                if is_valid:
                    summary["valid_credentials"] += 1
                    
                    # Extract capabilities
                    subject = credential.get("credentialSubject", {})
                    capabilities = subject.get("capabilities", [])
                    summary["capabilities"].update(capabilities)
                    
                    # Extract role
                    role = subject.get("role")
                    if role:
                        summary["roles"].add(role)
                    
                    # Extract trust info
                    trust_level = subject.get("trustLevel")
                    trust_score = subject.get("trustScore")
                    if trust_level and trust_score is not None:
                        summary["trust_level"] = trust_level
                        summary["trust_score"] = trust_score
                    
                    # Extract issuer
                    issuer = credential.get("issuer")
                    if issuer:
                        summary["issuers"].add(issuer)
                    
                    # Extract expiration
                    expiration = credential.get("expirationDate")
                    if expiration:
                        summary["expiration_dates"].append(expiration)
            
            # Convert sets to lists for JSON serialization
            summary["capabilities"] = list(summary["capabilities"])
            summary["roles"] = list(summary["roles"])
            summary["issuers"] = list(summary["issuers"])
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to create credential summary: {str(e)}")
            return {}
    
    def cache_verification_result(self, credential_id: str, is_valid: bool, 
                                cache_duration: int = 300) -> None:
        """
        Cache verification result to avoid repeated verification.
        
        Args:
            credential_id: ID of the credential
            is_valid: Whether the credential is valid
            cache_duration: Cache duration in seconds
        """
        self.verified_credentials_cache[credential_id] = {
            "is_valid": is_valid,
            "timestamp": time.time(),
            "cache_duration": cache_duration
        }
    
    def is_cached_valid(self, credential_id: str) -> Optional[bool]:
        """
        Check if credential verification result is cached and still valid.
        
        Args:
            credential_id: ID of the credential
            
        Returns:
            True if cached and valid, False if cached and invalid, None if not cached
        """
        if credential_id not in self.verified_credentials_cache:
            return None
        
        cached_result = self.verified_credentials_cache[credential_id]
        current_time = time.time()
        
        # Check if cache is still valid
        if current_time - cached_result["timestamp"] > cached_result["cache_duration"]:
            del self.verified_credentials_cache[credential_id]
            return None
        
        return cached_result["is_valid"]
    
    def clear_cache(self) -> int:
        """
        Clear expired entries from verification cache.
        
        Returns:
            Number of entries cleared
        """
        cleared_count = 0
        current_time = time.time()
        expired_entries = []
        
        for credential_id, cached_result in self.verified_credentials_cache.items():
            if current_time - cached_result["timestamp"] > cached_result["cache_duration"]:
                expired_entries.append(credential_id)
        
        for credential_id in expired_entries:
            del self.verified_credentials_cache[credential_id]
            cleared_count += 1
        
        logger.info(f"Cleared {cleared_count} expired cache entries")
        return cleared_count
