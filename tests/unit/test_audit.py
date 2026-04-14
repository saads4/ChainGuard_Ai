"""
Unit Tests for Audit Layer

Tests for audit components:
- Audit logger tests
- Hash chain tests
- Log signer and verifier tests
"""

import pytest
import tempfile
import json
import os
import time
from core.audit.audit_logger import AuditLogger
from core.audit.hash_chain import HashChain
from core.audit.log_signer import LogSigner
from core.audit.log_verifier import LogVerifier


class TestHashChain:
    """Test cases for HashChain."""
    
    def setup_method(self):
        self.chain = HashChain()
    
    def test_initialize_chain(self):
        """Test chain initialization with genesis block."""
        self.chain.initialize_chain()
        last_hash = self.chain.get_last_hash()
        assert last_hash is not None
        assert len(last_hash) > 0
    
    def test_create_link(self):
        """Test creating a new link in the chain."""
        self.chain.initialize_chain()
        prev_hash = self.chain.get_last_hash()
        
        data = {"event": "test", "value": 123}
        new_hash = self.chain.create_link(prev_hash, data)
        
        assert new_hash != prev_hash
        assert len(new_hash) > 0


class TestAuditLogger:
    """Test cases for AuditLogger."""
    
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "audit.jsonl")
        # In actual code, signing might require keys, so we disable it for basic tests
        self.logger = AuditLogger(log_file_path=self.log_file, signing_enabled=False)
    
    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_log_event(self):
        """Test logging an event."""
        event_data = {"action": "PAYMENT", "amount": 100}
        entry_id = self.logger.log_event("action", event_data, agent_id="agent_1")
        
        assert entry_id.startswith("entry_")
        
        # Flush to ensure it's written to file
        self.logger.force_flush()
        
        # Verify file content
        with open(self.log_file, 'r') as f:
            line = f.readline()
            entry = json.loads(line)
            assert entry["event_type"] == "action"
            assert entry["event_data"]["amount"] == 100
    
    def test_get_recent_entries(self):
        """Test retrieving recent entries."""
        for i in range(5):
            self.logger.log_event("test", {"val": i})
        
        self.logger.force_flush()
        entries = self.logger.get_recent_entries(count=3)
        assert len(entries) == 3
        assert entries[-1]["event_data"]["val"] == 4


class TestLogVerifier:
    """Test cases for LogVerifier."""
    
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "audit.jsonl")
        self.logger = AuditLogger(log_file_path=self.log_file, signing_enabled=False)
        self.verifier = LogVerifier()
    
    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_verify_chain_integrity(self):
        """Test verification of a valid hash chain."""
        # Log some events
        self.logger.log_event("event1", {"d": 1})
        self.logger.log_event("event2", {"d": 2})
        self.logger.force_flush()
        
        # Verify
        is_valid = self.verifier.verify_chain(self.log_file)
        assert is_valid is True
    
    def test_verify_broken_chain(self):
        """Test verification of a tampered hash chain."""
        self.logger.log_event("event1", {"d": 1})
        self.logger.log_event("event2", {"d": 2})
        self.logger.force_flush()
        
        # Tamper with the file
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
        
        # Modify data in the first entry
        entry = json.loads(lines[0])
        entry["event_data"]["d"] = 999 
        lines[0] = json.dumps(entry) + "\n"
        
        with open(self.log_file, 'w') as f:
            f.writelines(lines)
            
        # Verify should fail
        is_valid = self.verifier.verify_chain(self.log_file)
        assert is_valid is False
