"""
VC Issuer - Issues Verifiable Credentials (capability tokens)

Handles Verifiable Credential operations for ChainGuardAI:
- VC creation and signing
- Capability token management
- Credential templates
- Revocation and expiration
"""

import json
import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from loguru import logger
from .key_manager import KeyManager, ed25519
from .signature_utils import SignatureUtils


class VCIssuer:
    """Issues Verifiable Credentials for agent capabilities."""
    
    def __init__(self, key_manager: KeyManager, signature_utils: SignatureUtils):
        """
        Initialize VCIssuer.
        
        Args:
            key_manager: KeyManager instance for cryptographic operations
            signature_utils: SignatureUtils for signing credentials
        """
        self.key_manager = key_manager
        self.signature_utils = signature_utils
        self.issuer_did = None  # Will be set when issuer is initialized
        self.credentials = {}  # In-memory credential store
        
    def set_issuer_did(self, issuer_did: str):
        """Set the issuer's DID."""
        self.issuer_did = issuer_did
        logger.info(f"Set issuer DID: {issuer_did}")
    
    def issue_capability_credential(self, agent_did: str, capabilities: List[str],
                                   expires_in_days: int = 365, 
                                   constraints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Issue a capability credential for an agent.
        
        Args:
            agent_did: DID of the agent receiving the credential
            capabilities: List of allowed capabilities
            expires_in_days: Number of days until expiration
            constraints: Additional constraints on capabilities
            
        Returns:
            Verifiable Credential dictionary
        """
        try:
            if not self.issuer_did:
                raise ValueError("Issuer DID not set")
            
            # Load issuer's private key
            issuer_id = self.issuer_did.split(":")[-1]  # Extract agent ID from DID
            private_key = self.key_manager.load_private_key(issuer_id)
            if not private_key:
                raise ValueError(f"Cannot load private key for issuer: {issuer_id}")
            
            # Create credential
            credential = self._create_credential_template(
                agent_did=agent_did,
                capabilities=capabilities,
                expires_in_days=expires_in_days,
                constraints=constraints
            )
            
            # Sign the credential
            signed_credential = self.signature_utils.sign_json_ld(
                private_key, credential
            )
            
            # Store credential
            credential_id = signed_credential["id"]
            self.credentials[credential_id] = signed_credential
            
            logger.info(f"Issued capability credential for agent: {agent_did}")
            return signed_credential
            
        except Exception as e:
            logger.error(f"Failed to issue capability credential: {str(e)}")
            raise
    
    def _create_credential_template(self, agent_did: str, capabilities: List[str],
                                   expires_in_days: int, 
                                   constraints: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a credential template."""
        credential_id = f"urn:uuid:{uuid.uuid4()}"
        issuance_date = datetime.utcnow().isoformat() + "Z"
        expiration_date = (datetime.utcnow() + timedelta(days=expires_in_days)).isoformat() + "Z"
        
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/v1"
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", "AgentCapabilityCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
            "credentialSubject": {
                "id": agent_did,
                "type": "Agent",
                "capabilities": capabilities,
                "agentType": "default"
            }
        }
        
        # Add constraints if provided
        if constraints:
            credential["credentialSubject"]["constraints"] = constraints
        
        return credential
    
    def issue_role_credential(self, agent_did: str, role: str, 
                            scope: List[str], expires_in_days: int = 365) -> Dict[str, Any]:
        """
        Issue a role-based credential for an agent.
        
        Args:
            agent_did: DID of the agent
            role: Agent role (e.g., "finance_agent", "marketing_agent")
            scope: List of allowed operations within the role
            expires_in_days: Number of days until expiration
            
        Returns:
            Verifiable Credential dictionary
        """
        try:
            if not self.issuer_did:
                raise ValueError("Issuer DID not set")
            
            # Load issuer's private key
            issuer_id = self.issuer_did.split(":")[-1]
            private_key = self.key_manager.load_private_key(issuer_id)
            if not private_key:
                raise ValueError(f"Cannot load private key for issuer: {issuer_id}")
            
            # Create role credential
            credential = self._create_role_credential_template(
                agent_did=agent_did,
                role=role,
                scope=scope,
                expires_in_days=expires_in_days
            )
            
            # Sign the credential
            signed_credential = self.signature_utils.sign_json_ld(
                private_key, credential
            )
            
            # Store credential
            credential_id = signed_credential["id"]
            self.credentials[credential_id] = signed_credential
            
            logger.info(f"Issued role credential '{role}' for agent: {agent_did}")
            return signed_credential
            
        except Exception as e:
            logger.error(f"Failed to issue role credential: {str(e)}")
            raise
    
    def _create_role_credential_template(self, agent_did: str, role: str,
                                       scope: List[str], expires_in_days: int) -> Dict[str, Any]:
        """Create a role credential template."""
        credential_id = f"urn:uuid:{uuid.uuid4()}"
        issuance_date = datetime.utcnow().isoformat() + "Z"
        expiration_date = (datetime.utcnow() + timedelta(days=expires_in_days)).isoformat() + "Z"
        
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/v1"
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", "AgentRoleCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
            "credentialSubject": {
                "id": agent_did,
                "type": "Agent",
                "role": role,
                "scope": scope,
                "permissions": {
                    "canExecute": scope,
                    "canRead": True,
                    "canWrite": True
                }
            }
        }
        
        return credential
    
    def issue_trust_credential(self, agent_did: str, trust_level: str,
                              trust_score: float, expires_in_days: int = 365) -> Dict[str, Any]:
        """
        Issue a trust credential for an agent.
        
        Args:
            agent_did: DID of the agent
            trust_level: Trust level (e.g., "high", "medium", "low")
            trust_score: Numerical trust score (0.0-1.0)
            expires_in_days: Number of days until expiration
            
        Returns:
            Verifiable Credential dictionary
        """
        try:
            if not self.issuer_did:
                raise ValueError("Issuer DID not set")
            
            # Load issuer's private key
            issuer_id = self.issuer_did.split(":")[-1]
            private_key = self.key_manager.load_private_key(issuer_id)
            if not private_key:
                raise ValueError(f"Cannot load private key for issuer: {issuer_id}")
            
            # Create trust credential
            credential = self._create_trust_credential_template(
                agent_did=agent_did,
                trust_level=trust_level,
                trust_score=trust_score,
                expires_in_days=expires_in_days
            )
            
            # Sign the credential
            signed_credential = self.signature_utils.sign_json_ld(
                private_key, credential
            )
            
            # Store credential
            credential_id = signed_credential["id"]
            self.credentials[credential_id] = signed_credential
            
            logger.info(f"Issued trust credential for agent: {agent_did}")
            return signed_credential
            
        except Exception as e:
            logger.error(f"Failed to issue trust credential: {str(e)}")
            raise
    
    def _create_trust_credential_template(self, agent_did: str, trust_level: str,
                                        trust_score: float, expires_in_days: int) -> Dict[str, Any]:
        """Create a trust credential template."""
        credential_id = f"urn:uuid:{uuid.uuid4()}"
        issuance_date = datetime.utcnow().isoformat() + "Z"
        expiration_date = (datetime.utcnow() + timedelta(days=expires_in_days)).isoformat() + "Z"
        
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/v1"
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", "AgentTrustCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
            "credentialSubject": {
                "id": agent_did,
                "type": "Agent",
                "trustLevel": trust_level,
                "trustScore": trust_score,
                "lastVerified": datetime.utcnow().isoformat() + "Z"
            }
        }
        
        return credential
    
    def revoke_credential(self, credential_id: str, reason: str = "Revoked by issuer") -> bool:
        """
        Revoke a credential.
        
        Args:
            credential_id: ID of the credential to revoke
            reason: Reason for revocation
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if credential_id not in self.credentials:
                logger.warning(f"Credential not found for revocation: {credential_id}")
                return False
            
            credential = self.credentials[credential_id]
            
            # Add revocation information
            credential["revoked"] = True
            credential["revocationDate"] = datetime.utcnow().isoformat() + "Z"
            credential["revocationReason"] = reason
            
            logger.info(f"Revoked credential: {credential_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke credential {credential_id}: {str(e)}")
            return False
    
    def is_credential_valid(self, credential: Dict[str, Any]) -> bool:
        """
        Check if a credential is valid (not expired or revoked).
        
        Args:
            credential: Verifiable credential dictionary
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Check if revoked
            if credential.get("revoked", False):
                logger.warning("Credential is revoked")
                return False
            
            # Check expiration
            expiration_date = credential.get("expirationDate")
            if expiration_date:
                exp_datetime = datetime.fromisoformat(expiration_date.replace("Z", "+00:00"))
                if datetime.utcnow() > exp_datetime:
                    logger.warning("Credential has expired")
                    return False
            
            # Check issuance date
            issuance_date = credential.get("issuanceDate")
            if issuance_date:
                issue_datetime = datetime.fromisoformat(issuance_date.replace("Z", "+00:00"))
                if datetime.utcnow() < issue_datetime:
                    logger.warning("Credential is not yet valid")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate credential: {str(e)}")
            return False
    
    def get_credentials_by_agent(self, agent_did: str) -> List[Dict[str, Any]]:
        """
        Get all credentials issued to an agent.
        
        Args:
            agent_did: DID of the agent
            
        Returns:
            List of credentials
        """
        agent_credentials = []
        
        for credential in self.credentials.values():
            subject_id = credential.get("credentialSubject", {}).get("id")
            if subject_id == agent_did:
                agent_credentials.append(credential)
        
        logger.info(f"Found {len(agent_credentials)} credentials for agent: {agent_did}")
        return agent_credentials
    
    def export_credential(self, credential_id: str, file_path: str) -> bool:
        """
        Export a credential to file.
        
        Args:
            credential_id: ID of the credential
            file_path: Path to save the credential
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if credential_id not in self.credentials:
                logger.error(f"Credential not found: {credential_id}")
                return False
            
            credential = self.credentials[credential_id]
            
            with open(file_path, 'w') as f:
                json.dump(credential, f, indent=2)
            
            logger.info(f"Exported credential to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export credential: {str(e)}")
            return False
    
    def import_credential(self, file_path: str) -> Optional[str]:
        """
        Import a credential from file.
        
        Args:
            file_path: Path to the credential file
            
        Returns:
            Credential ID if successful, None otherwise
        """
        try:
            with open(file_path, 'r') as f:
                credential = json.load(f)
            
            credential_id = credential.get("id")
            if not credential_id:
                logger.error("No credential ID found in file")
                return None
            
            self.credentials[credential_id] = credential
            logger.info(f"Imported credential: {credential_id}")
            return credential_id
            
        except Exception as e:
            logger.error(f"Failed to import credential: {str(e)}")
            return None
    
    def list_credentials(self) -> List[str]:
        """
        List all credential IDs.
        
        Returns:
            List of credential IDs
        """
        return list(self.credentials.keys())
    
    def cleanup_expired_credentials(self) -> int:
        """
        Remove expired credentials from memory.
        
        Returns:
            Number of credentials removed
        """
        removed_count = 0
        expired_credentials = []
        
        for credential_id, credential in self.credentials.items():
            if not self.is_credential_valid(credential):
                expired_credentials.append(credential_id)
        
        for credential_id in expired_credentials:
            del self.credentials[credential_id]
            removed_count += 1
        
        logger.info(f"Cleaned up {removed_count} expired credentials")
        return removed_count
