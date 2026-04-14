"""
Layer 1: Cryptographic Agent Identity

This layer provides decentralized identity management for AI agents using:
- Decentralized Identifiers (DIDs)
- Ed25519 cryptographic keypairs
- Verifiable Credentials for capability management
- Digital signatures for message authentication
"""

from .did_manager import DIDManager
from .key_manager import KeyManager
from .vc_issuer import VCIssuer
from .vc_verifier import VCVerifier
from .signature_utils import SignatureUtils
from .registry.registry_manager import RegistryManager

__all__ = [
    "DIDManager",
    "KeyManager",
    "VCIssuer", 
    "VCVerifier",
    "SignatureUtils",
    "RegistryManager",
]
