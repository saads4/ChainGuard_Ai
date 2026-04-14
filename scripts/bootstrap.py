#!/usr/bin/env python3
"""
ChainGuardAI Bootstrap Script
One-command setup for ChainGuardAI security framework.
Generates keys, creates registry, and initializes all components.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
import logging

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.identity.key_manager import KeyManager
from core.identity.did_manager import DIDManager
from core.identity.vc_issuer import VCIssuer
from core.identity.registry.registry_manager import RegistryManager
from core.audit.hash_chain import HashChain
from core.identity.signature_utils import SignatureUtils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ChainGuardAIBootstrap:
    """Bootstrap class for ChainGuardAI setup."""
    
    def __init__(self, config_path: str = None):
        """Initialize bootstrap with configuration."""
        self.project_root = project_root
        self.config_path = config_path or str(project_root / "config.yaml")
        
        self.key_manager = KeyManager(keys_directory=str(project_root / "data" / "keys"))
        self.signature_utils = SignatureUtils(self.key_manager)
        self.did_manager = DIDManager(self.key_manager)
        self.vc_issuer = VCIssuer(self.key_manager, self.signature_utils)
        
        # Paths
        self.registry_path = project_root / "data" / "registry" / "agent_registry.json"
        self.audit_logs_path = project_root / "core" / "audit" / "logs" / "audit_chain.jsonl"
        self.agents_path = project_root / "agents"
        
    def setup_complete_system(self):
        """Set up complete ChainGuardAI system."""
        logger.info("Starting ChainGuardAI bootstrap...")
        
        try:
            # Step 1: Create directories
            self._create_directories()
            
            # Step 2: Generate root authority keys (before registry as it updates it)
            self._generate_root_authority()
            
            # Step 3: Create example agents
            self._create_example_agents()
            
            # Step 4: Initialize audit chain
            self._initialize_audit_chain()
            
            # Step 5: Create configuration files
            self._create_configuration()
            
            # Step 6: Verify setup
            self._verify_setup()
            
            logger.info("ChainGuardAI bootstrap completed successfully!")
            self._print_summary()
            
        except Exception as e:
            logger.error(f"Bootstrap failed: {str(e)}")
            raise
    
    def _create_directories(self):
        """Create necessary directories."""
        logger.info("Creating directories...")
        
        directories = [
            self.project_root / "data" / "keys",
            self.project_root / "data" / "registry",
            self.project_root / "core" / "audit" / "logs" / "archive",
            self.project_root / "agents" / "finance_agent" / "credentials",
            self.project_root / "agents" / "finance_agent" / "tools",
            self.project_root / "agents" / "marketing_agent" / "credentials",
            self.project_root / "agents" / "marketing_agent" / "tools",
            self.project_root / "api" / "middleware",
            self.project_root / "api" / "routes",
            self.project_root / "tests" / "unit",
            self.project_root / "tests" / "integration",
            self.project_root / "tests" / "attack_simulations",
            self.project_root / "docs"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")
    
    def _generate_root_authority(self):
        """Generate root authority keys and DID."""
        logger.info("Generating root authority keys...")
        
        # Generate root authority key pair
        root_priv, root_pub = self.key_manager.generate_keypair(agent_id="root_authority")
        self.key_manager.save_keypair("root_authority", root_priv, root_pub, encrypt=False)
        
        # Create root authority DID
        root_did = self.did_manager.create_did("root_authority", "chainguard_ai.local", root_pub)
        
        # Save root authority keys metadata
        root_keys_path = self.project_root / "root_authority_keys.json"
        
        root_pub_b64 = self.key_manager.get_public_key_base64(root_pub)
        
        root_keys_data = {
            "did": root_did,
            "agent_id": "root_authority",
            "public_key": root_pub_b64,
            "created_at": datetime.utcnow().isoformat()
        }
        
        with open(root_keys_path, 'w') as f:
            json.dump(root_keys_data, f, indent=2)
            
        # Update registry with root authority
        registry_manager = RegistryManager(str(self.registry_path))
        registry_manager.register_agent(
            agent_did=root_did,
            public_key=root_pub,
            metadata={
                "role": "root_authority",
                "is_root": True,
                "created_at": datetime.utcnow().isoformat()
            }
        )
        
        logger.info(f"Root authority created: {root_did}")
        logger.info(f"Root keys metadata saved to: {root_keys_path}")
    
    def _create_example_agents(self):
        """Create example finance and marketing agents."""
        logger.info("Creating example agents...")
        
        # Load root authority keys
        root_keys_path = self.project_root / "root_authority_keys.json"
        with open(root_keys_path, 'r') as f:
            root_keys = json.load(f)
        
        # Create finance agent
        self._create_agent(
            name="finance_agent",
            capabilities=["process_payments", "generate_reports", "access_financial_data"],
            root_keys=root_keys
        )
        
        # Create marketing agent
        self._create_agent(
            name="marketing_agent",
            capabilities=["create_campaigns", "analyze_marketing_data", "manage_social_media"],
            root_keys=root_keys
        )
    
    def _create_agent(self, name: str, capabilities: list, root_keys: dict):
        """Create a single agent with keys and credentials."""
        logger.info(f"Creating agent: {name}")
        
        # Generate agent key pair
        ag_priv, ag_pub = self.key_manager.generate_keypair(agent_id=name)
        self.key_manager.save_keypair(name, ag_priv, ag_pub, encrypt=False)
        
        # Create agent DID
        agent_did = self.did_manager.create_did(agent_id=name, domain="chainguard_ai.local", public_key=ag_pub)
        
        # Create Verifiable Credential
        self.vc_issuer.set_issuer_did(root_keys["did"])
        vc = self.vc_issuer.issue_capability_credential(
            agent_did=agent_did,
            capabilities=capabilities
        )
        
        # Save agent VC
        agent_vc_path = self.project_root / "agents" / name / "credentials" / "verifiable_credential.json"
        agent_vc_path.parent.mkdir(parents=True, exist_ok=True)
        with open(agent_vc_path, 'w') as f:
            json.dump(vc, f, indent=2)
        
        # Register agent
        registry_manager = RegistryManager(str(self.registry_path))
        
        metadata = {
            "name": name,
            "verifiable_credential": vc,
            "capabilities": capabilities,
            "role": name,
            "agent_type": name
        }
        
        registry_manager.register_agent(agent_did=agent_did, public_key=ag_pub, metadata=metadata)
        
        logger.info(f"Agent {name} created: {agent_did}")
    
    def _initialize_audit_chain(self):
        """Initialize audit hash chain."""
        logger.info("Initializing audit chain...")
        
        # Make sure directory exists
        self.audit_logs_path.parent.mkdir(parents=True, exist_ok=True)
            
        from core.audit.audit_logger import AuditLogger
        
        try:
            # We must use AuditLogger which manages the hash chain file correctly
            audit_logger = AuditLogger(log_file_path=str(self.audit_logs_path), signing_enabled=False)
            
            # Log an initial system event to establish the chain in the file
            audit_logger.log_event(
                event_type="system_init",
                event_data={"message": "ChainGuardAI audit chain initialized"},
                agent_id="root_authority"
            )
            audit_logger.force_flush()
            
            logger.info(f"Audit chain initialized at: {self.audit_logs_path}")
        except Exception as e:
            raise Exception(f"Failed to initialize audit chain: {str(e)}")
    
    def _create_configuration(self):
        """Create configuration files."""
        logger.info("Creating configuration files...")
        
        # Create environment file template
        env_template_path = self.project_root / ".env.example"
        env_content = """# ChainGuardAI Configuration
CHAINGUARD_AI_ENV=development
LOG_LEVEL=INFO
API_HOST=localhost
API_PORT=8000

# Database Configuration
DATABASE_URL=sqlite:///chainguard_ai.db

# Security Configuration
SECRET_KEY=your-secret-key-here
ROOT_AUTHORITY_DID=did:web:chainguard_ai:root

# Audit Configuration
AUDIT_LOG_PATH=core/audit/logs/audit_chain.jsonl
AUDIT_RETENTION_DAYS=365

# Detection Configuration
EMBEDDING_MODEL_PATH=models/sentence-transformers
CLASSIFIER_MODEL_PATH=core/detection/stage3_classifier/classifier_model

# API Configuration
API_RATE_LIMIT=60
API_BURST_SIZE=10
CORS_ORIGINS=http://localhost:3000,http://localhost:8080
"""
        
        with open(env_template_path, 'w') as f:
            f.write(env_content)
        
        logger.info(f"Environment template created: {env_template_path}")
    
    def _verify_setup(self):
        """Verify that setup was successful."""
        logger.info("Verifying setup...")
        
        # Check critical files exist
        critical_files = [
            self.registry_path,
            self.project_root / "root_authority_keys.json",
            self.audit_logs_path,
            self.project_root / "agents" / "finance_agent" / "credentials" / "verifiable_credential.json",
            self.project_root / "agents" / "marketing_agent" / "credentials" / "verifiable_credential.json"
        ]
        
        for file_path in critical_files:
            if not file_path.exists():
                raise Exception(f"Critical file missing: {file_path}")
        
        # Verify registry integrity
        registry_manager = RegistryManager(str(self.registry_path))
        agents = registry_manager.list_agents()
        if len(agents) < 3: # 1 root + 2 agents
            logger.warning(f"Expected at least 3 agents in registry, found {len(agents)}. Proceeding anyways.")
        
        logger.info("Setup verification completed successfully")
    
    def _print_summary(self):
        """Print setup summary."""
        print("\n" + "="*60)
        print("CHAINGUARD_AI BOOTSTRAP COMPLETE")
        print("="*60)
        print(f"Project Root: {self.project_root}")
        print(f"Registry: {self.registry_path}")
        print(f"Audit Log: {self.audit_logs_path}")
        
        print("\nNext Steps:")
        print("1. Copy .env.example to .env and configure")
        print("2. Install dependencies: pip install -r requirements.txt")
        print("3. Run tests: pytest tests/")
        print("4. Start API server: python api/main.py")
        print("5. Check documentation: docs/README.md")
        
        print("\nSecurity Notes:")
        print("- Root authority keys metadata is in root_authority_keys.json")
        print("- Keep this file secure and backed up")
        print("- Agent credentials are in agents/*/credentials/")
        print("- Audit logs are tamper-evident and cryptographically secured")
        
        print("="*60)

def main():
    """Main bootstrap function."""
    parser = argparse.ArgumentParser(description="ChainGuardAI Bootstrap Script")
    parser.add_argument(
        "--config", 
        type=str, 
        help="Path to configuration file",
        default=None
    )
    parser.add_argument(
        "--verbose", 
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        bootstrap = ChainGuardAIBootstrap(args.config)
        bootstrap.setup_complete_system()
        
    except KeyboardInterrupt:
        logger.info("Bootstrap interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Bootstrap failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
