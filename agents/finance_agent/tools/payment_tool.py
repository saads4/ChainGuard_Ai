"""
Payment processing tool for finance agent.
Handles payment processing, validation, and recording.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class PaymentTool:
    """Tool for processing financial payments."""
    
    def __init__(self):
        self.max_transaction_amount = 10000.0
        self.supported_currencies = ["USD", "EUR", "GBP"]
    
    def process_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a payment transaction.
        
        Args:
            payment_data: Dictionary containing payment information
                - amount: float
                - currency: str
                - recipient: str
                - description: str
        
        Returns:
            Dict containing payment result
        """
        try:
            # Validate payment data
            validation_result = self._validate_payment(payment_data)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": validation_result["error"],
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Process payment
            payment_id = self._generate_payment_id()
            payment_record = {
                "payment_id": payment_id,
                "amount": payment_data["amount"],
                "currency": payment_data["currency"],
                "recipient": payment_data["recipient"],
                "description": payment_data.get("description", ""),
                "status": "processed",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Payment processed: {payment_id}")
            
            return {
                "success": True,
                "payment_id": payment_id,
                "payment_record": payment_record,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Payment processing error: {str(e)}")
            return {
                "success": False,
                "error": f"Payment processing failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def _validate_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate payment data."""
        # Check required fields
        required_fields = ["amount", "currency", "recipient"]
        for field in required_fields:
            if field not in payment_data:
                return {"valid": False, "error": f"Missing required field: {field}"}
        
        # Validate amount
        try:
            amount = float(payment_data["amount"])
            if amount <= 0:
                return {"valid": False, "error": "Amount must be positive"}
            if amount > self.max_transaction_amount:
                return {"valid": False, "error": f"Amount exceeds maximum limit of {self.max_transaction_amount}"}
        except (ValueError, TypeError):
            return {"valid": False, "error": "Invalid amount format"}
        
        # Validate currency
        if payment_data["currency"] not in self.supported_currencies:
            return {"valid": False, "error": f"Unsupported currency: {payment_data['currency']}"}
        
        return {"valid": True}
    
    def _generate_payment_id(self) -> str:
        """Generate unique payment ID."""
        import uuid
        return f"PAY_{uuid.uuid4().hex[:12].upper()}"
    
    def get_payment_status(self, payment_id: str) -> Dict[str, Any]:
        """Get status of a payment."""
        # In a real implementation, this would query a database
        return {
            "payment_id": payment_id,
            "status": "processed",
            "timestamp": datetime.utcnow().isoformat()
        }
