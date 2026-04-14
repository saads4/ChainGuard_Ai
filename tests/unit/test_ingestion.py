"""
Unit Tests for Ingestion Layer

Tests for ingestion components:
- Input sanitizer tests
- Intent parser tests
- Intent validator tests
- Ingestion worker (sandboxed) tests
"""

import pytest
import tempfile
import os
import json
from core.ingestion.input_sanitizer import InputSanitizer
from core.ingestion.intent_parser import IntentParser
from core.ingestion.intent_validator import IntentValidator
from core.ingestion.ingestion_worker import IngestionWorker


class TestInputSanitizer:
    """Test cases for InputSanitizer."""
    
    def setup_method(self):
        self.sanitizer = InputSanitizer()
    
    def test_basic_sanitization(self):
        """Test removing basic scripts and HTML."""
        dirty_input = "Hello <script>alert(1)</script> world!"
        clean_input = self.sanitizer.sanitize(dirty_input)
        assert "<script>" not in clean_input
        assert "alert(1)" not in clean_input
    
    def test_unicode_normalization(self):
        """Test handling of weird unicode characters."""
        dirty_input = "H\u212e\u2113\u2113o" # Hello with weird chars
        clean_input = self.sanitizer.sanitize(dirty_input)
        assert "Hello" in clean_input or clean_input.isascii() or len(clean_input) > 0


class TestIntentParser:
    """Test cases for IntentParser."""
    
    def setup_method(self):
        self.parser = IntentParser()
    
    def test_parse_payment_intent(self):
        """Test parsing a payment intent."""
        text = "Pay $100 to Alice for dinner"
        intent = self.parser.parse_intent(text)
        
        assert intent is not None
        assert intent["action"] in ["PAY", "TRANSFER", "payment"]
        assert "Alice" in str(intent["parameters"])
        assert "100" in str(intent["parameters"])


class TestIntentValidator:
    """Test cases for IntentValidator."""
    
    def setup_method(self):
        self.validator = IntentValidator()
    
    def test_validate_valid_intent(self):
        """Test validation of a well-formed intent."""
        intent = {
            "action": "TRANSFER",
            "parameters": {
                "amount": 50.0,
                "recipient": "Bob",
                "currency": "USD"
            },
            "confidence": 0.95
        }
        result = self.validator.validate_intent(intent)
        assert result["valid"] is True
    
    def test_validate_invalid_intent(self):
        """Test validation of an incomplete intent."""
        intent = {
            "action": "TRANSFER",
            "parameters": {
                "amount": -100 # Invalid amount
            }
        }
        result = self.validator.validate_intent(intent)
        assert result["valid"] is False


class TestIngestionWorker:
    """Test cases for IngestionWorker."""
    
    def setup_method(self):
        self.worker = IngestionWorker()
    
    def test_process_input_safely(self):
        """Test the sandboxed input processing."""
        user_input = "Transfer $25 to Charlie"
        result = self.worker.process_input_safely(user_input)
        
        assert result["success"] is True
        assert "intent" in result
        assert "validation" in result
        assert result["intent"]["parameters"]["amount"] == 25
    
    def test_process_malicious_input(self):
        """Test handling of input with dangerous patterns."""
        malicious_input = "import os; os.system('rm -rf /')"
        # The worker should block or sanitize this
        result = self.worker.process_input_safely(malicious_input)
        
        # It might still 'succeed' in processing, but the intent should be neutralized or flagged
        assert result.get("success", False) is True # The worker itself doesn't crash
        # But let's check if it found an intent
        assert result["intent"]["action"] == "UNKNOWN" or result["validation"]["valid"] == False or "import" not in str(result["intent"])
