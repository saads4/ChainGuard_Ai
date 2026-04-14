#!/usr/bin/env python3
"""
Agent Key Generation Utility
Standalone utility for generating agent keys and credentials.
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
from core.identity.signature_utils import SignatureUtils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AgentKeyGenerator:
    """Utility for generating agent keys and credentials."""
    
    def __init__(self, registry_path: str = None):
        """Initialize key generator."""
        self.project_root = project_root
        self.key_manager = KeyManager()
        self.did_manager = DIDManager()
        self.vc_issuer = VCIssuer()
        self.signature_utils = SignatureUtils()
        
        if registry_path:
            self.registry_path = Path(registry_path)
        else:
            self.registry_path = project_root / "core" / "identity" / "registry" / "agent_registry.json"
    
    def generate_agent(self, name: str, agent_type: str, capabilities: list, 
                      output_dir: str = None) -> dict:
        """Generate keys and credentials for a new agent."""
        logger.info(f"Generating keys for agent: {name}")
        
        # Generate key pair
        key_pair = self.key_manager.generate_key_pair()
        
        # Create DID
        did = self.did_manager.create_did(key_pair["public_key"])
        
        # Determine output directory
        if output_dir:
            agent_dir = Path(output_dir) / name
        else:
            agent_dir = self.project_root / "agents" / name
        
        # Create agent directory
        agent_dir.mkdir(parents=True, exist_ok=True)
        credentials_dir = agent_dir / "credentials"
        credentials_dir.mkdir(exist_ok=True)
        
        # Save private key
        private_key_path = credentials_dir / "private_key.pem"
        with open(private_key_path, 'w') as f:
            f.write(key_pair["private_key"])
        
        # Create Verifiable Credential
        vc = self.vc_issuer.issue_credential(
            did=did,
            capabilities=capabilities,
            role=agent_type,
            issuer_did="did:web:chainguard_ai:root"
        )
        
        # Save VC
        vc_path = credentials_dir / "verifiable_credential.json"
        with open(vc_path, 'w') as f:
            json.dump(vc, f, indent=2)
        
        # Create agent info file
        agent_info = {
            "name": name,
            "type": agent_type,
            "did": did,
            "public_key": key_pair["public_key"],
            "capabilities": capabilities,
            "created_at": datetime.utcnow().isoformat(),
            "files": {
                "private_key": str(private_key_path),
                "verifiable_credential": str(vc_path)
            }
        }
        
        info_path = agent_dir / "agent_info.json"
        with open(info_path, 'w') as f:
            json.dump(agent_info, f, indent=2)
        
        logger.info(f"Agent keys generated for {name}")
        logger.info(f"  DID: {did}")
        logger.info(f"  Private key: {private_key_path}")
        logger.info(f"  Verifiable Credential: {vc_path}")
        
        return agent_info
    
    def generate_batch_agents(self, config_file: str):
        """Generate multiple agents from configuration file."""
        logger.info(f"Generating batch agents from: {config_file}")
        
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        generated_agents = []
        
        for agent_config in config.get("agents", []):
            name = agent_config["name"]
            agent_type = agent_config["type"]
            capabilities = agent_config["capabilities"]
            output_dir = agent_config.get("output_dir")
            
            try:
                agent_info = self.generate_agent(name, agent_type, capabilities, output_dir)
                generated_agents.append(agent_info)
                
                # Register agent if registry exists
                if self.registry_path.exists():
                    self._register_agent(agent_info)
                
            except Exception as e:
                logger.error(f"Failed to generate agent {name}: {str(e)}")
                continue
        
        # Generate summary report
        report_path = self.project_root / "agent_generation_report.json"
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_agents": len(generated_agents),
            "agents": generated_agents
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Batch generation completed. Report saved to: {report_path}")
        return generated_agents
    
    def _register_agent(self, agent_info: dict):
        """Register agent in registry."""
        from core.identity.registry.registry_manager import RegistryManager
        
        registry_manager = RegistryManager(str(self.registry_path))
        
        # Load VC
        vc_path = Path(agent_info["files"]["verifiable_credential"])
        with open(vc_path, 'r') as f:
            vc = json.load(f)
        
        agent_data = {
            "did": agent_info["did"],
            "name": agent_info["name"],
            "public_key": agent_info["public_key"],
            "verifiable_credential": vc,
            "capabilities": agent_info["capabilities"],
            "role": agent_info["type"],
            "status": "active",
            "created_at": agent_info["created_at"]
        }
        
        registry_manager.register_agent(agent_data)
        logger.info(f"Agent {agent_info['name']} registered in registry")
    
    def list_agent_types(self):
        """List available agent types and their default capabilities."""
        agent_types = {
            "finance_agent": {
                "description": "Handles financial transactions and reporting",
                "default_capabilities": [
                    "process_payments",
                    "generate_reports", 
                    "access_financial_data",
                    "approve_transactions_under_1000"
                ]
            },
            "marketing_agent": {
                "description": "Manages marketing campaigns and analytics",
                "default_capabilities": [
                    "create_campaigns",
                    "analyze_marketing_data",
                    "manage_social_media",
                    "generate_reports",
                    "access_analytics"
                ]
            },
            "security_agent": {
                "description": "Monitors security and handles threats",
                "default_capabilities": [
                    "monitor_security",
                    "analyze_threats",
                    "block_suspicious_activity",
                    "generate_security_reports"
                ]
            },
            "data_agent": {
                "description": "Handles data processing and analysis",
                "default_capabilities": [
                    "process_data",
                    "generate_analytics",
                    "access_databases",
                    "create_reports"
                ]
            },
            "admin_agent": {
                "description": "System administration and maintenance",
                "default_capabilities": [
                    "system_maintenance",
                    "user_management",
                    "backup_operations",
                    "system_monitoring"
                ]
            }
        }
        
        print("Available Agent Types:")
        print("=" * 50)
        
        for agent_type, info in agent_types.items():
            print(f"\n{agent_type}:")
            print(f"  Description: {info['description']}")
            print(f"  Default Capabilities:")
            for capability in info["default_capabilities"]:
                print(f"    - {capability}")
        
        return agent_types
    
    def verify_agent_credentials(self, agent_dir: str) -> dict:
        """Verify agent credentials and integrity."""
        agent_dir = Path(agent_dir)
        
        if not agent_dir.exists():
            raise Exception(f"Agent directory does not exist: {agent_dir}")
        
        # Load agent info
        info_path = agent_dir / "agent_info.json"
        if not info_path.exists():
            raise Exception(f"Agent info file not found: {info_path}")
        
        with open(info_path, 'r') as f:
            agent_info = json.load(f)
        
        verification_results = {
            "agent_name": agent_info["name"],
            "did": agent_info["did"],
            "checks": {}
        }
        
        # Check private key exists
        private_key_path = Path(agent_info["files"]["private_key"])
        verification_results["checks"]["private_key_exists"] = private_key_path.exists()
        
        # Check VC exists
        vc_path = Path(agent_info["files"]["verifiable_credential"])
        verification_results["checks"]["vc_exists"] = vc_path.exists()
        
        # Verify DID format
        verification_results["checks"]["did_format_valid"] = agent_info["did"].startswith("did:")
        
        # Verify VC structure
        if vc_path.exists():
            with open(vc_path, 'r') as f:
                vc = json.load(f)
            
            verification_results["checks"]["vc_structure_valid"] = (
                "credentialSubject" in vc and
                "proof" in vc and
                vc["credentialSubject"]["id"] == agent_info["did"]
            )
        else:
            verification_results["checks"]["vc_structure_valid"] = False
        
        # Overall verification status
        verification_results["verified"] = all(verification_results["checks"].values())
        
        return verification_results
    
    def rotate_agent_keys(self, agent_dir: str):
        """Rotate agent keys and update credentials."""
        agent_dir = Path(agent_dir)
        
        # Load current agent info
        info_path = agent_dir / "agent_info.json"
        with open(info_path, 'r') as f:
            agent_info = json.load(f)
        
        logger.info(f"Rotating keys for agent: {agent_info['name']}")
        
        # Generate new key pair
        new_key_pair = self.key_manager.generate_key_pair()
        
        # Create new DID
        new_did = self.did_manager.create_did(new_key_pair["public_key"])
        
        # Backup old keys
        credentials_dir = agent_dir / "credentials"
        backup_dir = credentials_dir / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_dir.mkdir(exist_ok=True)
        
        old_private_key = credentials_dir / "private_key.pem"
        old_vc = credentials_dir / "verifiable_credential.json"
        
        if old_private_key.exists():
            old_private_key.rename(backup_dir / "private_key.pem")
        if old_vc.exists():
            old_vc.rename(backup_dir / "verifiable_credential.json")
        
        # Save new private key
        with open(credentials_dir / "private_key.pem", 'w') as f:
            f.write(new_key_pair["private_key"])
        
        # Create new VC
        new_vc = self.vc_issuer.issue_credential(
            did=new_did,
            capabilities=agent_info["capabilities"],
            role=agent_info["type"],
            issuer_did="did:web:chainguard_ai:root"
        )
        
        # Save new VC
        with open(credentials_dir / "verifiable_credential.json", 'w') as f:
            json.dump(new_vc, f, indent=2)
        
        # Update agent info
        agent_info["did"] = new_did
        agent_info["public_key"] = new_key_pair["public_key"]
        agent_info["files"]["private_key"] = str(credentials_dir / "private_key.pem")
        agent_info["files"]["verifiable_credential"] = str(credentials_dir / "verifiable_credential.json")
        agent_info["key_rotated_at"] = datetime.utcnow().isoformat()
        
        with open(info_path, 'w') as f:
            json.dump(agent_info, f, indent=2)
        
        # Update registry if it exists
        if self.registry_path.exists():
            self._register_agent(agent_info)
        
        logger.info(f"Keys rotated for agent {agent_info['name']}")
        logger.info(f"  New DID: {new_did}")
        logger.info(f"  Backup saved to: {backup_dir}")
        
        return agent_info

def main():
    """Main function for agent key generation utility."""
    parser = argparse.ArgumentParser(description="Agent Key Generation Utility")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Generate single agent
    generate_parser = subparsers.add_parser("generate", help="Generate keys for a single agent")
    generate_parser.add_argument("name", help="Agent name")
    generate_parser.add_argument("type", help="Agent type")
    generate_parser.add_argument("--capabilities", nargs="+", help="Agent capabilities")
    generate_parser.add_argument("--output-dir", help="Output directory")
    
    # Generate batch agents
    batch_parser = subparsers.add_parser("batch", help="Generate multiple agents from config")
    batch_parser.add_argument("config", help="Configuration file path")
    
    # List agent types
    list_parser = subparsers.add_parser("list", help="List available agent types")
    
    # Verify agent credentials
    verify_parser = subparsers.add_parser("verify", help="Verify agent credentials")
    verify_parser.add_argument("agent_dir", help="Agent directory path")
    
    # Rotate agent keys
    rotate_parser = subparsers.add_parser("rotate", help="Rotate agent keys")
    rotate_parser.add_argument("agent_dir", help="Agent directory path")
    
    # Common arguments
    parser.add_argument("--registry", help="Registry file path")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        generator = AgentKeyGenerator(args.registry)
        
        if args.command == "generate":
            # Get default capabilities for agent type if not specified
            if not args.capabilities:
                agent_types = generator.list_agent_types()
                if args.type in agent_types:
                    args.capabilities = agent_types[args.type]["default_capabilities"]
                else:
                    logger.error(f"Unknown agent type: {args.type}")
                    return
            
            agent_info = generator.generate_agent(
                args.name, 
                args.type, 
                args.capabilities, 
                args.output_dir
            )
            
            # Register agent if registry exists
            if generator.registry_path.exists():
                generator._register_agent(agent_info)
            
            print(f"\nAgent '{args.name}' generated successfully!")
            print(f"DID: {agent_info['did']}")
            print(f"Capabilities: {', '.join(agent_info['capabilities'])}")
        
        elif args.command == "batch":
            generated_agents = generator.generate_batch_agents(args.config)
            print(f"\nGenerated {len(generated_agents)} agents")
        
        elif args.command == "list":
            generator.list_agent_types()
        
        elif args.command == "verify":
            verification = generator.verify_agent_credentials(args.agent_dir)
            print(f"\nVerification Results for {verification['agent_name']}:")
            print(f"DID: {verification['did']}")
            print(f"Verified: {'YES' if verification['verified'] else 'NO'}")
            print("\nChecks:")
            for check, result in verification["checks"].items():
                status = "PASS" if result else "FAIL"
                print(f"  {check}: {status}")
        
        elif args.command == "rotate":
            agent_info = generator.rotate_agent_keys(args.agent_dir)
            print(f"\nKeys rotated for agent '{agent_info['name']}'")
            print(f"New DID: {agent_info['did']}")
        
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Operation failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
