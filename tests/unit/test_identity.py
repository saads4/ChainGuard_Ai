"""
Unit Tests for Identity Layer

Tests for identity management components:
- Key manager tests
- DID manager tests
- VC issuer and verifier tests
- Signature utils tests
"""

import pytest
import tempfile
import os
from pathlib import Path
import time

from core.identity.key_manager import KeyManager
from core.identity.did_manager import DIDManager
from core.identity.vc_issuer import VCIssuer
from core.identity.vc_verifier import VCVerifier
from core.identity.signature_utils import SignatureUtils


class TestKeyManager:
    """Test cases for KeyManager."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager(keys_directory=self.temp_dir)
    
    def teardown_method(self):
        """Cleanup test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_generate_keypair(self):
        """Test Ed25519 keypair generation."""
        # Note: Original test had different return type than current implementation
        # Current KeyManager.generate_keypair returns (private_key, public_key)
        private_key, public_key = self.key_manager.generate_keypair("test_agent")
        assert private_key is not None
        assert public_key is not None
    
    def test_store_and_load_keypair(self):
        """Test storing and loading keypairs."""
        agent_id = "test_agent_1"
        private_key, public_key = self.key_manager.generate_keypair(agent_id)
        
        # Store keypair
        success = self.key_manager.save_keypair(agent_id, private_key, public_key)
        assert success
        
        # Load keys
        loaded_private = self.key_manager.load_private_key(agent_id)
        loaded_public = self.key_manager.load_public_key(agent_id)
        
        assert loaded_private is not None
        assert loaded_public is not None
    
    def test_key_rotation(self):
        """Test key rotation."""
        agent_id = "test_agent_rot"
        private_key_1, public_key_1 = self.key_manager.generate_keypair(agent_id)
        self.key_manager.save_keypair(agent_id, private_key_1, public_key_1, encrypt=False)
        
        # Rotate key
        success = self.key_manager.rotate_keypair(agent_id)
        assert success
        
        # Verify keys changed
        public_key_2 = self.key_manager.load_public_key(agent_id)
        assert public_key_2 is not None
        # Public keys should be different
        assert self.key_manager.get_public_key_bytes(public_key_1) != self.key_manager.get_public_key_bytes(public_key_2)
    
    def test_list_agents(self):
        """Test listing agents with keys."""
        agents = ["agent1", "agent2", "agent3"]
        for agent_id in agents:
            priv, pub = self.key_manager.generate_keypair(agent_id)
            self.key_manager.save_keypair(agent_id, priv, pub)
        
        found_agents = self.key_manager.list_agents()
        for agent_id in agents:
            assert agent_id in found_agents
    
    def test_delete_keypair(self):
        """Test key deletion."""
        agent_id = "agent_to_delete"
        priv, pub = self.key_manager.generate_keypair(agent_id)
        self.key_manager.save_keypair(agent_id, priv, pub)
        
        assert self.key_manager.load_public_key(agent_id) is not None
        
        success = self.key_manager.delete_keypair(agent_id)
        assert success
        assert self.key_manager.load_public_key(agent_id) is None


class TestDIDManager:
    """Test cases for DIDManager."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager(keys_directory=self.temp_dir)
        self.did_manager = DIDManager(self.key_manager)
    
    def teardown_method(self):
        """Cleanup test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_create_did(self):
        """Test DID creation."""
        agent_id = "test_agent"
        private_key, public_key = self.key_manager.generate_keypair(agent_id)
        self.key_manager.save_keypair(agent_id, private_key, public_key)
        
        did = self.did_manager.create_did(agent_id)
        assert did.startswith("did:chainguard_ai:")
        assert agent_id in did
    
    def test_resolve_did(self):
        """Test DID resolution."""
        agent_id = "test_agent"
        private_key, public_key = self.key_manager.generate_keypair(agent_id)
        self.key_manager.save_keypair(agent_id, private_key, public_key)
        did = self.did_manager.create_did(agent_id)
        
        resolved_public_key = self.did_manager.resolve_did_to_public_key(did)
        assert resolved_public_key is not None
        
        # Verify public keys match
        orig_bytes = self.key_manager.get_public_key_bytes(public_key)
        resolved_bytes = self.key_manager.get_public_key_bytes(resolved_public_key)
        assert orig_bytes == resolved_bytes


class TestVCIssuer:
    """Test cases for VCIssuer."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager(keys_directory=self.temp_dir)
        self.did_manager = DIDManager(self.key_manager)
        self.vc_issuer = VCIssuer(self.key_manager, self.did_manager)
    
    def teardown_method(self):
        """Cleanup test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_issue_credential(self):
        """Test VC issuance."""
        agent_id = "test_agent"
        private_key, public_key = self.key_manager.generate_keypair(agent_id)
        self.key_manager.save_keypair(agent_id, private_key, public_key)
        did = self.did_manager.create_did(agent_id)
        
        capabilities = ["read", "write"]
        vc = self.vc_issuer.issue_verifiable_credential(
            subject_did=did,
            capabilities=capabilities,
            issuer_agent_id="master" # we generated 'master' in setup of real scripts usually
        )
        
        # If master doesn't exist in temp, create it or use subject
        if not vc:
            # Re-generate with subject as issuer for test simplicity
            vc = self.vc_issuer.issue_verifiable_credential(
                subject_did=did,
                capabilities=capabilities,
                issuer_agent_id=agent_id
            )
            
        assert vc is not None
        assert vc["credentialSubject"]["id"] == did
        assert vc["credentialSubject"]["capabilities"] == capabilities


class TestVCVerifier:
    """Test cases for VCVerifier."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager(keys_directory=self.temp_dir)
        self.did_manager = DIDManager(self.key_manager)
        self.vc_issuer = VCIssuer(self.key_manager, self.did_manager)
        self.vc_verifier = VCVerifier(self.did_manager)
    
    def teardown_method(self):
        """Cleanup test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_verify_valid_credential(self):
        """Test verification of valid credential."""
        agent_id = "test_agent"
        private_key, public_key = self.key_manager.generate_keypair(agent_id)
        self.key_manager.save_keypair(agent_id, private_key, public_key)
        did = self.did_manager.create_did(agent_id)
        
        vc = self.vc_issuer.issue_verifiable_credential(
            subject_did=did,
            capabilities=["read"],
            issuer_agent_id=agent_id
        )
        
        is_valid = self.vc_verifier.verify_verifiable_credential(vc)
        assert is_valid is True


class TestSignatureUtils:
    """Test cases for SignatureUtils."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager(keys_directory=self.temp_dir)
        self.signature_utils = SignatureUtils(self.key_manager)
    
    def teardown_method(self):
        """Cleanup test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_sign_and_verify_message(self):
        """Test message signing and verification."""
        agent_id = "test_agent"
        private_key, public_key = self.key_manager.generate_keypair(agent_id)
        self.key_manager.save_keypair(agent_id, private_key, public_key)
        
        message = "Secure message for ChainGuardAI"
        signature = self.signature_utils.sign_message(agent_id, message)
        
        assert signature is not None
        
        is_valid = self.signature_utils.verify_signature(public_key, message, signature)
        assert is_valid is True
