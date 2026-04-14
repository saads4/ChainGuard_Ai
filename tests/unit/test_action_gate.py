"""
Unit Tests for Action Gate Layer

Tests for action gate components:
- Scope check tests
- Safety check tests
- Gate controller tests
- Policy engine tests
"""

import pytest
import time
from core.action_gate.gate_controller import GateController
from core.action_gate.policy_engine import PolicyEngine
from core.action_gate.model_a_scope_check import ScopeCheck
from core.action_gate.model_b_safety_check import SafetyCheck


class TestPolicyEngine:
    """Test cases for PolicyEngine."""
    
    def setup_method(self):
        self.engine = PolicyEngine()
    
    def test_get_policy_for_role(self):
        """Test retrieving policy by role."""
        policy = self.engine.get_policy_for_role("finance_agent")
        assert policy is not None
        assert "TRANSFER" in str(policy) or "allowed_actions" in str(policy)


class TestScopeCheck:
    """Test cases for ScopeCheck."""
    
    def setup_method(self):
        self.engine = PolicyEngine()
        self.scope_check = ScopeCheck(self.engine)
    
    def test_check_in_scope_action(self):
        """Test an action that is within agent scope."""
        action = {"type": "TRANSFER", "amount": 100}
        agent_context = {"role": "finance_agent", "agent_id": "finance_1"}
        
        result = self.scope_check.check_scope(action, agent_context)
        assert result["passed"] is True
        assert result["confidence"] > 0.8
    
    def test_check_out_of_scope_action(self):
        """Test an action that is outside agent scope."""
        action = {"type": "DELETE_DATABASE", "target": "production"}
        agent_context = {"role": "marketing_agent", "agent_id": "marketing_1"}
        
        result = self.scope_check.check_scope(action, agent_context)
        assert result["passed"] is False


class TestSafetyCheck:
    """Test cases for SafetyCheck."""
    
    def setup_method(self):
        self.engine = PolicyEngine()
        self.safety_check = SafetyCheck(self.engine)
    
    def test_check_safe_action(self):
        """Test a safe action."""
        action = {"type": "SEND_EMAIL", "recipient": "customer@example.com"}
        agent_context = {"role": "marketing_agent"}
        
        result = self.safety_check.check_safety(action, agent_context)
        assert result["passed"] is True
    
    def test_check_unsafe_action(self):
        """Test an unsafe action (e.g. high amount)."""
        action = {"type": "TRANSFER", "amount": 1000000} # Very high amount
        agent_context = {"role": "finance_agent"}
        
        result = self.safety_check.check_safety(action, agent_context)
        assert result["passed"] is False or result["requires_escalation"] is True


class TestGateController:
    """Test cases for GateController."""
    
    def setup_method(self):
        self.controller = GateController()
    
    def test_evaluate_action_approval(self):
        """Test evaluating and approving an action."""
        action = {"type": "TRANSFER", "amount": 50, "id": "test_001"}
        agent_context = {"role": "finance_agent", "agent_id": "finance_1"}
        
        result = self.controller.evaluate_action(action, agent_context)
        
        assert result["approved"] is True
        assert "checks" in result
        assert "scope" in result["checks"]
        assert "safety" in result["checks"]
    
    def test_evaluate_action_denial(self):
        """Test evaluating and denying an action."""
        action = {"type": "UNAUTHORIZED_ACTION", "id": "test_002"}
        agent_context = {"role": "marketing_agent", "agent_id": "marketing_1"}
        
        result = self.controller.evaluate_action(action, agent_context)
        
        assert result["approved"] is False
        assert result["denied"] is True
