#!/usr/bin/env python3
"""
ChainGuardAI Setup Script

Automated setup and installation script for ChainGuardAI:
- Environment validation
- Dependency installation
- Configuration setup
- Database initialization
- Key generation
"""

import os
import sys
import subprocess
import json
import yaml
from pathlib import Path
import logging

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ChainGuardAISetup:
    """ChainGuardAI setup and installation manager."""
    
    def __init__(self, project_root: str = None):
        """Initialize setup manager."""
        self.project_root = Path(project_root) if project_root else Path(__file__).parent.parent
        self.config_file = self.project_root / "config.yaml"
        self.env_file = self.project_root / ".env"
        self.requirements_file = self.project_root / "requirements.txt"
        
    def run_setup(self):
        """Run complete setup process."""
        logger.info("Starting ChainGuardAI setup...")
        
        try:
            # Setup steps
            self.validate_environment()
            self.install_dependencies()
            self.setup_configuration()
            self.initialize_directories()
            self.generate_keys()
            self.setup_database()
            self.validate_installation()
            
            logger.info("ChainGuardAI setup completed successfully!")
            self.print_next_steps()
            
        except Exception as e:
            logger.error(f"Setup failed: {str(e)}")
            sys.exit(1)
    
    def validate_environment(self):
        """Validate system environment."""
        logger.info("Validating environment...")
        
        # Check Python version
        python_version = sys.version_info
        if python_version < (3, 8):
            raise RuntimeError(f"Python 3.8+ required, found {python_version.major}.{python_version.minor}")
        
        logger.info(f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        # Check required system commands
        required_commands = ["pip", "python"]
        for cmd in required_commands:
            try:
                subprocess.run([cmd, "--version"], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                raise RuntimeError(f"Required command not found: {cmd}")
        
        logger.info("Environment validation passed")
    
    def install_dependencies(self):
        """Install Python dependencies."""
        logger.info("Installing dependencies...")
        
        if not self.requirements_file.exists():
            raise RuntimeError(f"Requirements file not found: {self.requirements_file}")
        
        # Install dependencies
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", str(self.requirements_file)
        ], check=True)
        
        logger.info("Dependencies installed successfully")
    
    def setup_configuration(self):
        """Setup configuration files."""
        logger.info("Setting up configuration...")
        
        # Create .env file from example
        env_example = self.project_root / ".env.example"
        if env_example.exists() and not self.env_file.exists():
            with open(env_example, 'r') as src, open(self.env_file, 'w') as dst:
                dst.write(src.read())
            logger.info("Created .env file from example")
        
        # Validate configuration
        if not self.config_file.exists():
            raise RuntimeError(f"Configuration file not found: {self.config_file}")
        
        with open(self.config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate required configuration sections
        required_sections = ["identity", "ingestion", "detection", "action_gate", "audit"]
        for section in required_sections:
            if section not in config:
                raise RuntimeError(f"Missing configuration section: {section}")
        
        logger.info("Configuration validated")
    
    def initialize_directories(self):
        """Initialize required directories."""
        logger.info("Initializing directories...")
        
        directories = [
            "data/keys",
            "data/registry",
            "data/models",
            "core/audit/logs",
            "core/audit/logs/archive",
            "core/detection/stage1_regex",
            "core/detection/stage2_embedding",
            "core/detection/stage3_classifier",
            "core/action_gate/policies",
            "logs"
        ]
        
        for directory in directories:
            dir_path = self.project_root / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")
    
    def generate_keys(self):
        """Generate initial cryptographic keys."""
        logger.info("Generating cryptographic keys...")
        
        try:
            from core.identity.key_manager import KeyManager
            
            # Initialize key manager
            key_dir = self.project_root / "data" / "keys"
            key_manager = KeyManager(keys_directory=str(key_dir))
            
            # Generate master key
            private_key, public_key = key_manager.generate_keypair(agent_id="master")
            key_manager.save_keypair(agent_id="master", private_key=private_key, public_key=public_key, encrypt=False)
            
            logger.info(f"Generated master key for agent 'master'")
            
        except ImportError as e:
            logger.warning(f"Could not import key manager: {e}")
            logger.info("Keys will be generated on first run")
    
    def setup_database(self):
        """Setup database and registry."""
        logger.info("Setting up database...")
        
        try:
            from core.identity.registry.registry_manager import RegistryManager
            
            # Initialize registry
            registry_file = self.project_root / "data" / "registry" / "agent_registry.json"
            registry_manager = RegistryManager(registry_path=str(registry_file))
            
            logger.info("Database initialized")
            
        except ImportError as e:
            logger.warning(f"Could not import registry manager: {e}")
            logger.info("Database will be initialized on first run")
    
    def validate_installation(self):
        """Validate installation."""
        logger.info("Validating installation...")
        
        # Check critical files
        critical_files = [
            "config.yaml",
            ".env",
            "requirements.txt",
            "core/__init__.py",
            "agents/__init__.py",
            "api/__init__.py"
        ]
        
        for file_path in critical_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                raise RuntimeError(f"Critical file missing: {file_path}")
        
        # Test imports
        try:
            import core
            import agents
            logger.info("Core modules import successfully")
        except ImportError as e:
            raise RuntimeError(f"Import error: {e}")
        
        logger.info("Installation validation passed")
    
    def print_next_steps(self):
        """Print next steps for user."""
        print("\n" + "="*60)
        print("ChainGuardAI Setup Complete!")
        print("="*60)
        print("\nNext steps:")
        print("1. Review configuration in config.yaml")
        print("2. Set environment variables in .env")
        print("3. Run tests: pytest tests/")
        print("4. Start API server: python -m api.app")
        print("5. Access documentation: http://localhost:8000/docs")
        print("\nFor more information, see README.md")
        print("="*60)


def main():
    """Main setup function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="ChainGuardAI Setup Script")
    parser.add_argument("--project-root", help="Project root directory")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    parser.add_argument("--dev", action="store_true", help="Development setup")
    
    args = parser.parse_args()
    
    setup = ChainGuardAISetup(args.project_root)
    
    if args.skip_deps:
        # Override install_dependencies method
        setup.install_dependencies = lambda: logger.info("Skipping dependency installation")
    
    if args.dev:
        logger.info("Running development setup...")
        # Additional dev setup could be added here
    
    setup.run_setup()


if __name__ == "__main__":
    main()
