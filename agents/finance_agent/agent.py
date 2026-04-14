"""
Finance Agent - Finance agent logic (wrapped with ChainGuardAI)

Example finance agent that handles financial transactions with ChainGuardAI protection:
- Payment processing
- Money transfers
- Balance checking
- Transaction reporting
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from decimal import Decimal, InvalidOperation
from loguru import logger
from ..base_agent import BaseAgent


class FinanceAgent(BaseAgent):
    """Finance agent with ChainGuardAI protection for handling financial operations."""
    
    def __init__(self, agent_id: str = None, config: Dict[str, Any] = None):
        """
        Initialize FinanceAgent.
        
        Args:
            agent_id: Unique identifier for the agent
            config: Agent configuration
        """
        if agent_id is None:
            agent_id = f"finance_agent_{uuid.uuid4().hex[:8]}"
        
        super().__init__(agent_id, "finance_agent", config)
        
        # Finance-specific configuration
        self.max_transaction_amount = self.config.get("max_transaction_amount", 50000)
        self.daily_limit = self.config.get("daily_limit", 200000)
        self.supported_currencies = self.config.get("supported_currencies", ["USD", "EUR", "GBP"])
        
        # Account database (simplified for example)
        self.accounts = {
            "demo_account_1": {
                "balance": Decimal("10000.00"),
                "currency": "USD",
                "owner": "Demo User 1",
                "transactions": []
            },
            "demo_account_2": {
                "balance": Decimal("5000.00"),
                "currency": "USD",
                "owner": "Demo User 2",
                "transactions": []
            }
        }
        
        # Transaction tracking
        self.daily_transaction_total = Decimal("0.00")
        self.daily_transaction_count = 0
        self.last_reset_date = time.strftime("%Y-%m-%d")
        
        logger.info(f"FinanceAgent initialized: {agent_id}")
    
    def get_capabilities(self) -> List[str]:
        """Get finance agent capabilities."""
        return [
            "payment",
            "transfer",
            "balance_check",
            "transaction_history",
            "account_info",
            "currency_conversion"
        ]
    
    def handle_request(self, request: str) -> str:
        """
        Handle finance-related requests.
        
        Args:
            request: User request string
            
        Returns:
            Response string
        """
        try:
            request_lower = request.lower().strip()
            
            # Parse request type
            if "payment" in request_lower or "pay" in request_lower:
                return self._handle_payment_request(request)
            elif "transfer" in request_lower or "send" in request_lower:
                return self._handle_transfer_request(request)
            elif "balance" in request_lower:
                return self._handle_balance_request(request)
            elif "history" in request_lower or "transactions" in request_lower:
                return self._handle_history_request(request)
            elif "account" in request_lower:
                return self._handle_account_info_request(request)
            elif "convert" in request_lower:
                return self._handle_currency_conversion_request(request)
            else:
                return self._handle_general_request(request)
                
        except Exception as e:
            logger.error(f"Error handling request: {str(e)}")
            return f"Error processing request: {str(e)}"
    
    def _handle_payment_request(self, request: str) -> str:
        """Handle payment requests."""
        try:
            # Extract payment details (simplified parsing)
            amount = self._extract_amount(request)
            recipient = self._extract_recipient(request)
            currency = self._extract_currency(request) or "USD"
            
            if not amount:
                return "Please specify an amount for the payment."
            
            if not recipient:
                return "Please specify a recipient for the payment."
            
            # Validate payment
            validation_result = self._validate_transaction(amount, currency)
            if not validation_result["valid"]:
                return validation_result["message"]
            
            # Process payment
            payment_result = self._process_payment(amount, recipient, currency)
            
            if payment_result["success"]:
                self.increment_transaction_count()
                return f"Payment successful: {currency} {amount} to {recipient}. Transaction ID: {payment_result['transaction_id']}"
            else:
                return f"Payment failed: {payment_result['message']}"
                
        except Exception as e:
            logger.error(f"Error in payment request: {str(e)}")
            return f"Error processing payment: {str(e)}"
    
    def _handle_transfer_request(self, request: str) -> str:
        """Handle transfer requests."""
        try:
            # Extract transfer details
            amount = self._extract_amount(request)
            from_account = self._extract_from_account(request)
            to_account = self._extract_to_account(request)
            
            if not amount:
                return "Please specify an amount for the transfer."
            
            if not from_account:
                return "Please specify the source account."
            
            if not to_account:
                return "Please specify the destination account."
            
            # Process transfer
            transfer_result = self._process_transfer(amount, from_account, to_account)
            
            if transfer_result["success"]:
                self.increment_transaction_count()
                return f"Transfer successful: {amount} from {from_account} to {to_account}. Transaction ID: {transfer_result['transaction_id']}"
            else:
                return f"Transfer failed: {transfer_result['message']}"
                
        except Exception as e:
            logger.error(f"Error in transfer request: {str(e)}")
            return f"Error processing transfer: {str(e)}"
    
    def _handle_balance_request(self, request: str) -> str:
        """Handle balance check requests."""
        try:
            account = self._extract_account(request) or "demo_account_1"
            
            if account not in self.accounts:
                return f"Account '{account}' not found."
            
            account_info = self.accounts[account]
            balance = account_info["balance"]
            currency = account_info["currency"]
            
            return f"Balance for {account}: {currency} {balance:.2f}"
            
        except Exception as e:
            logger.error(f"Error in balance request: {str(e)}")
            return f"Error checking balance: {str(e)}"
    
    def _handle_history_request(self, request: str) -> str:
        """Handle transaction history requests."""
        try:
            account = self._extract_account(request) or "demo_account_1"
            
            if account not in self.accounts:
                return f"Account '{account}' not found."
            
            transactions = self.accounts[account]["transactions"]
            
            if not transactions:
                return f"No transactions found for {account}."
            
            # Get recent transactions (last 10)
            recent_transactions = transactions[-10:]
            
            history = f"Recent transactions for {account}:\n"
            for tx in recent_transactions:
                history += f"- {tx['type']}: {tx['currency']} {tx['amount']} ({tx['timestamp']})\n"
            
            return history.strip()
            
        except Exception as e:
            logger.error(f"Error in history request: {str(e)}")
            return f"Error retrieving history: {str(e)}"
    
    def _handle_account_info_request(self, request: str) -> str:
        """Handle account information requests."""
        try:
            account = self._extract_account(request) or "demo_account_1"
            
            if account not in self.accounts:
                return f"Account '{account}' not found."
            
            account_info = self.accounts[account]
            
            info = f"Account Information for {account}:\n"
            info += f"Owner: {account_info['owner']}\n"
            info += f"Balance: {account_info['currency']} {account_info['balance']:.2f}\n"
            info += f"Transaction Count: {len(account_info['transactions'])}"
            
            return info
            
        except Exception as e:
            logger.error(f"Error in account info request: {str(e)}")
            return f"Error retrieving account info: {str(e)}"
    
    def _handle_currency_conversion_request(self, request: str) -> str:
        """Handle currency conversion requests."""
        try:
            amount = self._extract_amount(request)
            from_currency = self._extract_from_currency(request)
            to_currency = self._extract_to_currency(request)
            
            if not amount:
                return "Please specify an amount to convert."
            
            if not from_currency:
                return "Please specify the source currency."
            
            if not to_currency:
                return "Please specify the target currency."
            
            # Simple conversion rates (in production, use real API)
            conversion_rates = {
                "USD": {"EUR": 0.85, "GBP": 0.73},
                "EUR": {"USD": 1.18, "GBP": 0.86},
                "GBP": {"USD": 1.37, "EUR": 1.16}
            }
            
            if from_currency not in conversion_rates:
                return f"Conversion from {from_currency} not supported."
            
            if to_currency not in conversion_rates[from_currency]:
                return f"Conversion to {to_currency} not supported."
            
            rate = conversion_rates[from_currency][to_currency]
            converted_amount = amount * rate
            
            return f"{amount} {from_currency} = {converted_amount:.2f} {to_currency}"
            
        except Exception as e:
            logger.error(f"Error in conversion request: {str(e)}")
            return f"Error converting currency: {str(e)}"
    
    def _handle_general_request(self, request: str) -> str:
        """Handle general finance-related requests."""
        help_text = """
I can help you with the following financial operations:
- Make payments: "Pay $100 to John Doe"
- Transfer money: "Transfer $50 from account1 to account2"
- Check balance: "What's the balance of account1?"
- View transaction history: "Show transactions for account1"
- Get account info: "Account details for account1"
- Currency conversion: "Convert 100 USD to EUR"

Available accounts: demo_account_1, demo_account_2
        """.strip()
        
        return help_text
    
    def _extract_amount(self, request: str) -> Optional[Decimal]:
        """Extract monetary amount from request."""
        try:
            import re
            
            # Look for dollar amounts
            dollar_pattern = r'\$(\d+(?:\.\d{2})?|\d+(?:\.\d{2})?\s*dollar'
            dollar_match = re.search(dollar_pattern, request, re.IGNORECASE)
            
            if dollar_match:
                amount_str = re.sub(r'[^0-9.]', '', dollar_match.group())
                return Decimal(amount_str)
            
            # Look for numeric amounts
            number_pattern = r'\b\d+(?:\.\d{2})?\b'
            number_match = re.search(number_pattern, request)
            
            if number_match:
                return Decimal(number_match.group())
            
            return None
            
        except (ValueError, InvalidOperation):
            return None
    
    def _extract_recipient(self, request: str) -> Optional[str]:
        """Extract recipient from request."""
        try:
            import re
            
            # Look for "to X" pattern
            to_pattern = r'to\s+([A-Za-z\s]+)'
            to_match = re.search(to_pattern, request, re.IGNORECASE)
            
            if to_match:
                return to_match.group(1).strip()
            
            return None
            
        except Exception:
            return None
    
    def _extract_from_account(self, request: str) -> Optional[str]:
        """Extract source account from request."""
        try:
            import re
            
            # Look for "from X" pattern
            from_pattern = r'from\s+([A-Za-z0-9_]+)'
            from_match = re.search(from_pattern, request, re.IGNORECASE)
            
            if from_match:
                return from_match.group(1).strip()
            
            return None
            
        except Exception:
            return None
    
    def _extract_to_account(self, request: str) -> Optional[str]:
        """Extract destination account from request."""
        try:
            import re
            
            # Look for "to X" pattern
            to_pattern = r'to\s+([A-Za-z0-9_]+)'
            to_match = re.search(to_pattern, request, re.IGNORECASE)
            
            if to_match:
                return to_match.group(1).strip()
            
            return None
            
        except Exception:
            return None
    
    def _extract_account(self, request: str) -> Optional[str]:
        """Extract account name from request."""
        try:
            import re
            
            # Look for account names
            account_pattern = r'(demo_account_\d+|account\d+)'
            match = re.search(account_pattern, request, re.IGNORECASE)
            
            if match:
                return match.group(1).lower()
            
            return None
            
        except Exception:
            return None
    
    def _extract_currency(self, request: str) -> Optional[str]:
        """Extract currency from request."""
        try:
            import re
            
            # Look for currency codes
            currency_pattern = r'\b(USD|EUR|GBP)\b'
            match = re.search(currency_pattern, request, re.IGNORECASE)
            
            if match:
                return match.group(1).upper()
            
            return None
            
        except Exception:
            return None
    
    def _extract_from_currency(self, request: str) -> Optional[str]:
        """Extract source currency from request."""
        try:
            import re
            
            # Look for "X to Y" pattern
            pattern = r'(\w+)\s+to\s+\w+'
            match = re.search(pattern, request, re.IGNORECASE)
            
            if match:
                currency = match.group(1).upper()
                if currency in self.supported_currencies:
                    return currency
            
            return None
            
        except Exception:
            return None
    
    def _extract_to_currency(self, request: str) -> Optional[str]:
        """Extract target currency from request."""
        try:
            import re
            
            # Look for "X to Y" pattern
            pattern = r'\w+\s+to\s+(\w+)'
            match = re.search(pattern, request, re.IGNORECASE)
            
            if match:
                currency = match.group(1).upper()
                if currency in self.supported_currencies:
                    return currency
            
            return None
            
        except Exception:
            return None
    
    def _validate_transaction(self, amount: Decimal, currency: str) -> Dict[str, Any]:
        """Validate transaction parameters."""
        try:
            result = {"valid": True, "message": ""}
            
            # Check currency support
            if currency not in self.supported_currencies:
                result["valid"] = False
                result["message"] = f"Currency {currency} not supported."
                return result
            
            # Check amount limits
            if amount > self.max_transaction_amount:
                result["valid"] = False
                result["message"] = f"Amount {amount} exceeds maximum limit of {self.max_transaction_amount}."
                return result
            
            # Check daily limit
            if self.daily_transaction_total + amount > self.daily_limit:
                result["valid"] = False
                result["message"] = f"Transaction would exceed daily limit of {self.daily_limit}."
                return result
            
            return result
            
        except Exception as e:
            logger.error(f"Error validating transaction: {str(e)}")
            return {"valid": False, "message": f"Validation error: {str(e)}"}
    
    def _process_payment(self, amount: Decimal, recipient: str, currency: str) -> Dict[str, Any]:
        """Process a payment transaction."""
        try:
            transaction_id = f"txn_{int(time.time() * 1000000)}"
            
            # Create transaction record
            transaction = {
                "id": transaction_id,
                "type": "payment",
                "amount": amount,
                "currency": currency,
                "recipient": recipient,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "completed"
            }
            
            # Update daily totals
            self.daily_transaction_total += amount
            self._check_daily_reset()
            
            # Add to account transactions (simplified)
            for account in self.accounts.values():
                account["transactions"].append(transaction)
            
            return {"success": True, "transaction_id": transaction_id}
            
        except Exception as e:
            logger.error(f"Error processing payment: {str(e)}")
            return {"success": False, "message": str(e)}
    
    def _process_transfer(self, amount: Decimal, from_account: str, to_account: str) -> Dict[str, Any]:
        """Process a transfer between accounts."""
        try:
            if from_account not in self.accounts:
                return {"success": False, "message": f"Source account '{from_account}' not found."}
            
            if to_account not in self.accounts:
                return {"success": False, "message": f"Destination account '{to_account}' not found."}
            
            from_account_info = self.accounts[from_account]
            to_account_info = self.accounts[to_account]
            
            # Check sufficient funds
            if from_account_info["balance"] < amount:
                return {"success": False, "message": "Insufficient funds in source account."}
            
            # Perform transfer
            transaction_id = f"txn_{int(time.time() * 1000000)}"
            
            # Update balances
            from_account_info["balance"] -= amount
            to_account_info["balance"] += amount
            
            # Create transaction records
            transaction = {
                "id": transaction_id,
                "type": "transfer",
                "amount": amount,
                "currency": from_account_info["currency"],
                "from_account": from_account,
                "to_account": to_account,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "completed"
            }
            
            # Add to both accounts
            from_account_info["transactions"].append(transaction)
            to_account_info["transactions"].append(transaction.copy())
            
            # Update daily totals
            self.daily_transaction_total += amount
            self._check_daily_reset()
            
            return {"success": True, "transaction_id": transaction_id}
            
        except Exception as e:
            logger.error(f"Error processing transfer: {str(e)}")
            return {"success": False, "message": str(e)}
    
    def _check_daily_reset(self) -> None:
        """Check and reset daily transaction totals."""
        try:
            current_date = time.strftime("%Y-%m-%d")
            
            if current_date != self.last_reset_date:
                self.daily_transaction_total = Decimal("0.00")
                self.daily_transaction_count = 0
                self.last_reset_date = current_date
                logger.info("Daily transaction totals reset")
                
        except Exception as e:
            logger.error(f"Error checking daily reset: {str(e)}")
    
    def get_financial_summary(self) -> Dict[str, Any]:
        """Get financial summary for all accounts."""
        try:
            summary = {
                "total_accounts": len(self.accounts),
                "total_balance": Decimal("0.00"),
                "total_transactions": 0,
                "accounts": {},
                "daily_stats": {
                    "total_amount": float(self.daily_transaction_total),
                    "transaction_count": self.daily_transaction_count,
                    "last_reset": self.last_reset_date
                }
            }
            
            for account_id, account_info in self.accounts.items():
                summary["total_balance"] += account_info["balance"]
                summary["total_transactions"] += len(account_info["transactions"])
                
                summary["accounts"][account_id] = {
                    "owner": account_info["owner"],
                    "balance": float(account_info["balance"]),
                    "currency": account_info["currency"],
                    "transaction_count": len(account_info["transactions"])
                }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating financial summary: {str(e)}")
            return {}
