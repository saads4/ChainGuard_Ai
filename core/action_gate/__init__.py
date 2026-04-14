"""
Layer 4: Runtime Action Gate (dual-check)

This layer provides runtime protection and validation:
- Dual-check system for scope and safety validation
- Role-based policy enforcement
- Parameter safety checking
- Escalation handling for denied actions
"""

from .gate_controller import GateController
from .model_a_scope_check import ScopeCheck
from .model_b_safety_check import SafetyCheck
from .escalation_handler import EscalationHandler
from .policy_engine import PolicyEngine

__all__ = [
    "GateController",
    "ScopeCheck",
    "SafetyCheck", 
    "EscalationHandler",
    "PolicyEngine",
]
