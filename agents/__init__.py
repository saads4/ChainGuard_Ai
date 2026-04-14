"""
Example Agent Implementations

This package contains example implementations of agents protected by ChainGuardAI:
- Finance Agent - Handles financial transactions
- Marketing Agent - Manages marketing campaigns
- Base Agent - Abstract base class for all agents
"""

from .base_agent import BaseAgent
from .finance_agent.agent import FinanceAgent
from .marketing_agent.agent import MarketingAgent

__all__ = [
    "BaseAgent",
    "FinanceAgent",
    "MarketingAgent",
]
