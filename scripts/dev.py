#!/usr/bin/env python3
"""
ChainGuardAI Development Script

Development utilities for ChainGuardAI:
- Test runner
- Code linting
- Documentation generation
- Development server
- Database management
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ChainGuardAIDev:
    """ChainGuardAI development utilities."""
    
    def __init__(self, project_root: str = None):
        """Initialize development manager."""
        self.project_root = Path(project_root) if project_root else Path(__file__).parent.parent
        
    def run_tests(self, test_type: str = "all", verbose: bool = False, coverage: bool = False):
        """Run test suite."""
        logger.info(f"Running {test_type} tests...")
        
        cmd = ["python", "-m", "pytest"]
        
        # Add test type filter
        if test_type == "unit":
            cmd.extend(["-m", "unit"])
        elif test_type == "integration":
            cmd.extend(["-m", "integration"])
        elif test_type == "attack":
            cmd.extend(["-m", "attack_simulation"])
        elif test_type == "performance":
            cmd.extend(["-m", "performance"])
        
        # Add verbosity
        if verbose:
            cmd.append("-v")
        
        # Add coverage
        if coverage:
            cmd.extend([
                "--cov=core",
                "--cov=agents", 
                "--cov=api",
                "--cov-report=html",
                "--cov-report=term-missing"
            ])
        
        # Run tests
        result = subprocess.run(cmd, cwd=self.project_root)
        
        if result.returncode == 0:
            logger.info("Tests passed!")
        else:
            logger.error("Tests failed!")
            sys.exit(result.returncode)
    
    def lint_code(self, fix: bool = False):
        """Run code linting."""
        logger.info("Running code linting...")
        
        # Run flake8
        logger.info("Running flake8...")
        subprocess.run([
            "python", "-m", "flake8",
            "core", "agents", "api", "tests",
            "--max-line-length=100",
            "--ignore=E203,W503"
        ], cwd=self.project_root)
        
        # Run black (formatting)
        if fix:
            logger.info("Running black (formatting)...")
            subprocess.run([
                "python", "-m", "black",
                "core", "agents", "api", "tests", "scripts"
            ], cwd=self.project_root)
        else:
            logger.info("Checking formatting with black...")
            subprocess.run([
                "python", "-m", "black",
                "--check",
                "core", "agents", "api", "tests", "scripts"
            ], cwd=self.project_root)
        
        # Run isort (import sorting)
        if fix:
            logger.info("Running isort (import sorting)...")
            subprocess.run([
                "python", "-m", "isort",
                "core", "agents", "api", "tests", "scripts"
            ], cwd=self.project_root)
        else:
            logger.info("Checking imports with isort...")
            subprocess.run([
                "python", "-m", "isort",
                "--check-only",
                "core", "agents", "api", "tests", "scripts"
            ], cwd=self.project_root)
        
        logger.info("Linting completed")
    
    def generate_docs(self):
        """Generate documentation."""
        logger.info("Generating documentation...")
        
        # Create docs directory
        docs_dir = self.project_root / "docs"
        docs_dir.mkdir(exist_ok=True)
        
        # Generate API docs
        logger.info("Generating API documentation...")
        subprocess.run([
            "python", "-m", "sphinx",
            "-b", "html",
            "docs/source",
            "docs/build"
        ], cwd=self.project_root)
        
        logger.info("Documentation generated in docs/build/html")
    
    def start_dev_server(self, host: str = "localhost", port: int = 8000, reload: bool = True):
        """Start development API server."""
        logger.info(f"Starting development server on {host}:{port}")
        
        cmd = [
            "python", "-m", "uvicorn",
            "api.app:app",
            "--host", host,
            "--port", str(port)
        ]
        
        if reload:
            cmd.append("--reload")
        
        subprocess.run(cmd, cwd=self.project_root)
    
    def run_attack_simulation(self, test_file: str = None):
        """Run attack simulation tests."""
        logger.info("Running attack simulation...")
        
        if test_file:
            cmd = ["python", "-m", "pytest", test_file, "-v"]
        else:
            cmd = ["python", "-m", "pytest", "tests/attack_simulation/", "-v"]
        
        subprocess.run(cmd, cwd=self.project_root)
    
    def clean_project(self):
        """Clean project artifacts."""
        logger.info("Cleaning project...")
        
        # Remove Python cache files
        logger.info("Removing Python cache files...")
        for pattern in ["**/__pycache__", "**/*.pyc", "**/*.pyo"]:
            for path in self.project_root.glob(pattern):
                if path.is_dir():
                    import shutil
                    shutil.rmtree(path)
                else:
                    path.unlink()
        
        # Remove coverage files
        logger.info("Removing coverage files...")
        for pattern in [".coverage", "htmlcov", "coverage.xml"]:
            for path in self.project_root.glob(pattern):
                if path.is_dir():
                    import shutil
                    shutil.rmtree(path)
                else:
                    path.unlink()
        
        # Remove build artifacts
        logger.info("Removing build artifacts...")
        for pattern in ["build", "dist", "*.egg-info"]:
            for path in self.project_root.glob(pattern):
                if path.is_dir():
                    import shutil
                    shutil.rmtree(path)
                else:
                    path.unlink()
        
        logger.info("Project cleaned")
    
    def setup_dev_environment(self):
        """Setup development environment."""
        logger.info("Setting up development environment...")
        
        # Install development dependencies
        dev_requirements = [
            "pytest",
            "pytest-cov",
            "pytest-asyncio",
            "pytest-timeout",
            "flake8",
            "black",
            "isort",
            "sphinx",
            "sphinx-rtd-theme"
        ]
        
        for requirement in dev_requirements:
            subprocess.run([
                sys.executable, "-m", "pip", "install", requirement
            ], check=True)
        
        # Setup pre-commit hooks
        logger.info("Setting up pre-commit hooks...")
        
        pre_commit_config = {
            "repos": [
                {
                    "repo": "https://github.com/psf/black",
                    "rev": "22.3.0",
                    "hooks": [
                        {"id": "black"}
                    ]
                },
                {
                    "repo": "https://github.com/pycqa/isort",
                    "rev": "5.10.1",
                    "hooks": [
                        {"id": "isort"}
                    ]
                },
                {
                    "repo": "https://github.com/pycqa/flake8",
                    "rev": "4.0.1",
                    "hooks": [
                        {"id": "flake8"}
                    ]
                }
            ]
        }
        
        import json
        with open(self.project_root / ".pre-commit-config.yaml", "w") as f:
            import yaml
            yaml.dump(pre_commit_config, f)
        
        subprocess.run(["pre-commit", "install"], cwd=self.project_root)
        
        logger.info("Development environment setup complete")
    
    def monitor_logs(self, follow: bool = True):
        """Monitor application logs."""
        log_file = self.project_root / "logs" / "chainguard_ai.log"
        
        if not log_file.exists():
            logger.error(f"Log file not found: {log_file}")
            return
        
        cmd = ["tail"]
        if follow:
            cmd.append("-f")
        cmd.append(str(log_file))
        
        subprocess.run(cmd)
    
    def database_status(self):
        """Show database status."""
        logger.info("Checking database status...")
        
        try:
            from core.identity.registry.registry_manager import RegistryManager
            
            registry_file = self.project_root / "data" / "registry" / "agent_registry.json"
            registry_manager = RegistryManager(registry_file=str(registry_file))
            
            registry = registry_manager.load_registry()
            
            print(f"Registry file: {registry_file}")
            print(f"Registry exists: {registry_file.exists()}")
            print(f"Registered agents: {len(registry.get('agents', {}))}")
            
            if registry.get('agents'):
                print("Agent IDs:")
                for agent_id in registry['agents'].keys():
                    print(f"  - {agent_id}")
            
        except Exception as e:
            logger.error(f"Error checking database: {e}")
    
    def performance_test(self, duration: int = 60, concurrency: int = 10):
        """Run performance tests."""
        logger.info(f"Running performance test: {duration}s, {concurrency} concurrent")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/performance/test_performance.py",
            "-v",
            f"--timeout={duration}"
        ]
        
        subprocess.run(cmd, cwd=self.project_root)


def main():
    """Main development function."""
    parser = argparse.ArgumentParser(description="ChainGuardAI Development Script")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Run tests")
    test_parser.add_argument("--type", choices=["all", "unit", "integration", "attack", "performance"], 
                           default="all", help="Test type")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    test_parser.add_argument("--coverage", action="store_true", help="Generate coverage report")
    
    # Lint command
    lint_parser = subparsers.add_parser("lint", help="Run code linting")
    lint_parser.add_argument("--fix", action="store_true", help="Fix issues automatically")
    
    # Docs command
    subparsers.add_parser("docs", help="Generate documentation")
    
    # Server command
    server_parser = subparsers.add_parser("server", help="Start development server")
    server_parser.add_argument("--host", default="localhost", help="Host address")
    server_parser.add_argument("--port", type=int, default=8000, help="Port number")
    server_parser.add_argument("--no-reload", action="store_true", help="Disable auto-reload")
    
    # Attack simulation command
    attack_parser = subparsers.add_parser("attack", help="Run attack simulation")
    attack_parser.add_argument("--file", help="Specific test file to run")
    
    # Clean command
    subparsers.add_parser("clean", help="Clean project artifacts")
    
    # Setup command
    subparsers.add_parser("setup", help="Setup development environment")
    
    # Logs command
    logs_parser = subparsers.add_parser("logs", help="Monitor logs")
    logs_parser.add_argument("--no-follow", action="store_true", help="Don't follow log file")
    
    # Database command
    subparsers.add_parser("db", help="Show database status")
    
    # Performance command
    perf_parser = subparsers.add_parser("perf", help="Run performance tests")
    perf_parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    perf_parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    dev = ChainGuardAIDev()
    
    if args.command == "test":
        dev.run_tests(args.type, args.verbose, args.coverage)
    elif args.command == "lint":
        dev.lint_code(args.fix)
    elif args.command == "docs":
        dev.generate_docs()
    elif args.command == "server":
        dev.start_dev_server(args.host, args.port, not args.no_reload)
    elif args.command == "attack":
        dev.run_attack_simulation(args.file)
    elif args.command == "clean":
        dev.clean_project()
    elif args.command == "setup":
        dev.setup_dev_environment()
    elif args.command == "logs":
        dev.monitor_logs(not args.no_follow)
    elif args.command == "db":
        dev.database_status()
    elif args.command == "perf":
        dev.performance_test(args.duration, args.concurrency)


if __name__ == "__main__":
    main()
