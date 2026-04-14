"""
ChainGuardAI Core Framework

This package implements the 5-layer security framework:
1. Identity - Cryptographic agent identity and verification
2. Ingestion - Sandboxed input processing
3. Detection - Multi-stage injection detection
4. Action Gate - Runtime protection and validation
5. Audit - Tamper-evident logging
"""

from .identity import DIDManager, KeyManager, VCIssuer, VCVerifier
from .ingestion import IngestionWorker, IntentParser, IntentValidator
from .detection import DetectionPipeline
from .action_gate import GateController
from .audit import AuditLogger
from .chain_guard_ai import ChainGuardAI

__version__ = "1.0.0"
__all__ = [
    "DIDManager",
    "KeyManager", 
    "VCIssuer",
    "VCVerifier",
    "IngestionWorker",
    "IntentParser",
    "IntentValidator",
    "DetectionPipeline",
    "GateController",
    "AuditLogger",
    "ChainGuardAI",
]
