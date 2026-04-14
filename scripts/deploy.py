#!/usr/bin/env python3
"""
ChainGuardAI Deployment Script

Deployment utilities for ChainGuardAI:
- Production deployment
- Docker setup
- Environment configuration
- Service management
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
import logging
import yaml
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ChainGuardAIDeploy:
    """ChainGuardAI deployment manager."""
    
    def __init__(self, project_root: str = None):
        """Initialize deployment manager."""
        self.project_root = Path(project_root) if project_root else Path(__file__).parent.parent
        self.config_file = self.project_root / "config.yaml"
        self.env_file = self.project_root / ".env"
        
    def deploy_production(self, environment: str = "production"):
        """Deploy to production environment."""
        logger.info(f"Deploying to {environment}...")
        
        # Validate environment
        self.validate_production_config(environment)
        
        # Build application
        self.build_application()
        
        # Setup production directories
        self.setup_production_directories()
        
        # Configure services
        self.configure_services(environment)
        
        # Start services
        self.start_services()
        
        logger.info(f"Deployment to {environment} completed successfully!")
    
    def validate_production_config(self, environment: str):
        """Validate production configuration."""
        logger.info("Validating production configuration...")
        
        # Check environment file
        if not self.env_file.exists():
            raise RuntimeError(f"Environment file not found: {self.env_file}")
        
        # Load configuration
        with open(self.config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate production settings
        if environment == "production":
            required_env_vars = [
                "CHAINGUARD_AI_ENV",
                "SECRET_KEY",
                "DATABASE_URL",
                "REDIS_URL"
            ]
            
            for var in required_env_vars:
                if not os.environ.get(var):
                    raise RuntimeError(f"Required environment variable not set: {var}")
        
        logger.info("Production configuration validated")
    
    def build_application(self):
        """Build application for deployment."""
        logger.info("Building application...")
        
        # Install production dependencies
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], check=True)
        
        # Download ML models
        self.download_models()
        
        logger.info("Application built successfully")
    
    def download_models(self):
        """Download required ML models."""
        logger.info("Downloading ML models...")
        
        try:
            from sentence_transformers import SentenceTransformer
            
            # Download embedding model
            model_name = "all-MiniLM-L6-v2"
            model = SentenceTransformer(model_name)
            logger.info(f"Downloaded embedding model: {model_name}")
            
        except Exception as e:
            logger.warning(f"Could not download models: {e}")
            logger.info("Models will be downloaded on first run")
    
    def setup_production_directories(self):
        """Setup production directory structure."""
        logger.info("Setting up production directories...")
        
        production_dirs = [
            "/var/log/chainguard_ai",
            "/var/lib/chainguard_ai/data",
            "/var/lib/chainguard_ai/keys",
            "/var/lib/chainguard_ai/registry",
            "/var/lib/chainguard_ai/models",
            "/etc/chainguard_ai"
        ]
        
        for directory in production_dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")
    
    def configure_services(self, environment: str):
        """Configure system services."""
        logger.info("Configuring services...")
        
        # Create systemd service file
        service_content = f"""[Unit]
Description=ChainGuardAI API Server
After=network.target

[Service]
Type=simple
User=chainguard_ai
Group=chainguard_ai
WorkingDirectory={self.project_root}
Environment=PATH={self.project_root}/venv/bin
EnvironmentFile={self.env_file}
ExecStart={self.project_root}/venv/bin/python -m uvicorn api.app:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        
        service_file = Path("/etc/systemd/system/chainguard_ai.service")
        with open(service_file, 'w') as f:
            f.write(service_content)
        
        logger.info(f"Created service file: {service_file}")
        
        # Create nginx configuration
        nginx_config = f"""server {{
    listen 80;
    server_name your-domain.com;
    
    location / {{
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
    
    location /docs {{
        proxy_pass http://localhost:8000/docs;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
        
        nginx_file = Path("/etc/nginx/sites-available/chainguard_ai")
        with open(nginx_file, 'w') as f:
            f.write(nginx_config)
        
        logger.info(f"Created nginx configuration: {nginx_file}")
    
    def start_services(self):
        """Start system services."""
        logger.info("Starting services...")
        
        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        
        # Enable and start ChainGuardAI service
        subprocess.run(["systemctl", "enable", "chainguard_ai"], check=True)
        subprocess.run(["systemctl", "start", "chainguard_ai"], check=True)
        
        # Restart nginx
        subprocess.run(["systemctl", "restart", "nginx"], check=True)
        
        logger.info("Services started successfully")
    
    def create_docker_setup(self):
        """Create Docker deployment setup."""
        logger.info("Creating Docker setup...")
        
        # Create Dockerfile
        dockerfile_content = """FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 chainguard_ai && chown -R chainguard_ai:chainguard_ai /app
USER chainguard_ai

# Expose port
EXPOSE 8000

# Start application
CMD ["python", "-m", "uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
"""
        
        with open(self.project_root / "Dockerfile", 'w') as f:
            f.write(dockerfile_content)
        
        # Create docker-compose.yml
        compose_content = """version: '3.8'

services:
  chainguard_ai:
    build: .
    ports:
      - "8000:8000"
    environment:
      - CHAINGUARD_AI_ENV=production
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - chainguard_ai
    restart: unless-stopped

volumes:
  redis_data:
"""
        
        with open(self.project_root / "docker-compose.yml", 'w') as f:
            f.write(compose_content)
        
        # Create .dockerignore
        dockerignore_content = """__pycache__
*.pyc
*.pyo
*.pyd
.Python
env
venv
.venv
pip-log.txt
pip-delete-this-directory.txt
.tox
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.log
.git
.mypy_cache
.pytest_cache
.hypothesis
.DS_Store
.vscode
.idea
"""
        
        with open(self.project_root / ".dockerignore", 'w') as f:
            f.write(dockerignore_content)
        
        logger.info("Docker setup created")
    
    def deploy_docker(self):
        """Deploy using Docker."""
        logger.info("Deploying with Docker...")
        
        # Create Docker setup
        self.create_docker_setup()
        
        # Build and start containers
        subprocess.run(["docker-compose", "build"], check=True)
        subprocess.run(["docker-compose", "up", "-d"], check=True)
        
        logger.info("Docker deployment completed")
    
    def backup_data(self, backup_path: str = None):
        """Backup ChainGuardAI data."""
        logger.info("Creating data backup...")
        
        if not backup_path:
            backup_path = f"/tmp/chainguard_ai_backup_{int(time.time())}.tar.gz"
        
        data_dirs = [
            "data",
            "logs",
            "core/audit/logs"
        ]
        
        # Create backup
        subprocess.run([
            "tar", "-czf", backup_path,
            *[str(self.project_root / dir) for dir in data_dirs]
        ], check=True)
        
        logger.info(f"Backup created: {backup_path}")
    
    def restore_data(self, backup_path: str):
        """Restore ChainGuardAI data."""
        logger.info(f"Restoring data from {backup_path}...")
        
        # Stop services
        subprocess.run(["systemctl", "stop", "chainguard_ai"], check=True)
        
        # Restore data
        subprocess.run(["tar", "-xzf", backup_path, "-C", str(self.project_root)], check=True)
        
        # Start services
        subprocess.run(["systemctl", "start", "chainguard_ai"], check=True)
        
        logger.info("Data restored successfully")
    
    def update_deployment(self):
        """Update existing deployment."""
        logger.info("Updating deployment...")
        
        # Backup current data
        self.backup_data()
        
        # Pull latest code
        subprocess.run(["git", "pull"], check=True)
        
        # Rebuild application
        self.build_application()
        
        # Restart services
        subprocess.run(["systemctl", "restart", "chainguard_ai"], check=True)
        
        logger.info("Deployment updated successfully")
    
    def health_check(self):
        """Check deployment health."""
        logger.info("Checking deployment health...")
        
        # Check service status
        result = subprocess.run(
            ["systemctl", "is-active", "chainguard_ai"],
            capture_output=True, text=True
        )
        
        if result.stdout.strip() == "active":
            logger.info("ChainGuardAI service is running")
        else:
            logger.error("ChainGuardAI service is not running")
            return False
        
        # Check API endpoint
        try:
            import requests
            response = requests.get("http://localhost:8000/health", timeout=10)
            if response.status_code == 200:
                logger.info("API health check passed")
            else:
                logger.error(f"API health check failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"API health check failed: {e}")
            return False
        
        logger.info("Deployment health check passed")
        return True


def main():
    """Main deployment function."""
    parser = argparse.ArgumentParser(description="ChainGuardAI Deployment Script")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Production deployment
    prod_parser = subparsers.add_parser("deploy", help="Deploy to production")
    prod_parser.add_argument("--env", default="production", help="Environment name")
    
    # Docker deployment
    subparsers.add_parser("docker", help="Deploy with Docker")
    
    # Docker setup
    subparsers.add_parser("docker-setup", help="Create Docker setup")
    
    # Backup
    backup_parser = subparsers.add_parser("backup", help="Backup data")
    backup_parser.add_argument("--path", help="Backup path")
    
    # Restore
    restore_parser = subparsers.add_parser("restore", help="Restore data")
    restore_parser.add_argument("path", help="Backup file path")
    
    # Update
    subparsers.add_parser("update", help="Update deployment")
    
    # Health check
    subparsers.add_parser("health", help="Check deployment health")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    deploy = ChainGuardAIDeploy()
    
    if args.command == "deploy":
        deploy.deploy_production(args.env)
    elif args.command == "docker":
        deploy.deploy_docker()
    elif args.command == "docker-setup":
        deploy.create_docker_setup()
    elif args.command == "backup":
        deploy.backup_data(args.path)
    elif args.command == "restore":
        deploy.restore_data(args.path)
    elif args.command == "update":
        deploy.update_deployment()
    elif args.command == "health":
        deploy.health_check()


if __name__ == "__main__":
    import time
    main()
