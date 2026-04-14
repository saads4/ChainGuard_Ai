# ChainGuardAI Installation Guide

This guide covers the installation and setup of ChainGuardAI, a comprehensive security framework for AI agents.

## Prerequisites

### System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: Minimum 10GB free space
- **Network**: Internet connection for model downloads

### Required Software

- Python 3.8+ with pip
- Git (for cloning the repository)
- Virtual environment (recommended)

### Core Dependencies

The setup script automatically installs these key dependencies:
- **cryptography>=41.0.0** - Cryptographic operations and identity management
- **sentence-transformers>=2.2.0** - Embedding models for semantic analysis
- **torch>=2.0.0** - ML framework for model inference
- **scikit-learn>=1.4.0** - Classical ML for intent classification
- **fastapi>=0.104.0** - API framework for REST endpoints
- **uvicorn>=0.24.0** - ASGI server for API hosting
- **pydantic>=2.0.0** - Data validation and settings management
- **loguru>=0.7.0** - Structured logging across all modules

See [requirements.txt](../requirements.txt) for complete dependency list.

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/chainguard_ai.git
cd chainguard_ai
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Run Setup Script

```bash
python scripts/setup.py
```

The setup script will:
- **Environment Validation**: Check Python version and required commands
- **Dependency Installation**: Install all required Python packages from requirements.txt
- **Configuration Setup**: Create .env file from .env.example template
- **Directory Initialization**: Create necessary directories (data/, keys/, logs/, etc.)
- **Key Generation**: Generate cryptographic keys for identity management
- **Database Setup**: Initialize agent registry and audit storage
- **Installation Validation**: Verify all components are working correctly

### 4. Verify Installation

```bash
python scripts/dev.py test
```

This runs comprehensive tests including:
- Unit tests for all 5 security layers
- Integration tests for end-to-end workflows
- Attack simulation tests for security validation
- Performance tests for system benchmarks

### 5. Start Development Server

```bash
python scripts/dev.py server
```

The development server starts on http://localhost:8000 with:
- **Interactive API Documentation**: Visit http://localhost:8000/docs
- **Health Check Endpoint**: Visit http://localhost:8000/health
- **Real-time Logging**: Logs displayed in console
- **Auto-reload**: Server restarts on code changes

## Manual Installation

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Environment
CHAINGUARD_AI_ENV=development

# Security
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=sqlite:///chainguard_ai.db

# Redis (optional)
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/chainguard_ai.log
```

### Step 3: Initialize Directories

```bash
mkdir -p data/keys data/registry data/models
mkdir -p core/audit/logs core/audit/logs/archive
mkdir -p logs
```

### Step 4: Generate Keys

```python
from core.identity.key_manager import KeyManager

key_manager = KeyManager(keys_directory="./data/keys")
private_key, public_key = key_manager.generate_keypair(agent_id="root")
key_manager.save_keypair("root", private_key, public_key, encrypt=False)
print(f"Generated root key pair")
```

### Step 5: Initialize Registry

```python
from core.identity.registry.registry_manager import RegistryManager

registry_manager = RegistryManager(registry_path="./data/registry/agent_registry.json")
registry_manager.save_registry()
print("Agent registry initialized")
```

## Docker Installation

### Using Docker Compose

1. Create Docker setup:

```bash
python scripts/deploy.py docker-setup
```

2. Deploy with Docker:

```bash
python scripts/deploy.py docker
```

### Manual Docker Installation

Build the image:

```bash
docker build -t chainguard_ai .
```

Run with docker-compose:

```bash
docker-compose up -d
```

The Docker setup includes:
- **ChainGuardAI API**: Main application service
- **PostgreSQL Database**: Production database
- **Redis**: Caching and session storage
- **Nginx**: Reverse proxy and load balancer

## Production Deployment

### System Requirements

- **CPU**: 4+ cores
- **Memory**: 8GB+ RAM
- **Storage**: 50GB+ SSD
- **Network**: Stable internet connection
- **OS**: Ubuntu 20.04+ or CentOS 8+

### Deployment Steps

1. **Prepare System**

```bash
# Create user
sudo useradd -m -s /bin/bash chainguard_ai
sudo usermod -aG sudo chainguard_ai

# Install dependencies
sudo apt update
sudo apt install -y python3 python3-pip nginx redis-server
```

2. **Deploy Application**

```bash
# Clone repository
sudo -u chainguard_ai git clone https://github.com/your-org/chainguard_ai.git /opt/chainguard_ai
cd /opt/chainguard_ai

# Run deployment script
sudo python scripts/deploy.py deploy --env production
```

3. **Configure Environment**

```bash
# Edit production environment
sudo nano /etc/chainguard_ai/.env
```

4. **Start Services**

```bash
sudo systemctl enable chainguard_ai
sudo systemctl start chainguard_ai
sudo systemctl restart nginx
```

5. **Verify Deployment**

```bash
sudo python scripts/deploy.py health
```

## Configuration

### Main Configuration (config.yaml)

```yaml
# Identity Layer
identity:
  key_dir: "data/keys"
  registry_file: "data/registry/agent_registry.json"

# Ingestion Layer
ingestion:
  max_input_length: 10000
  sanitize_html: true
  validate_json: true

# Detection Layer
detection:
  regex:
    patterns_file: "core/detection/stage1_regex/patterns.json"
    case_sensitive: false
  embedding:
    model_name: "all-MiniLM-L6-v2"
    similarity_threshold: 0.7
  classifier:
    model_path: "data/models/intent_classifier.pkl"
    confidence_threshold: 0.8

# Action Gate Layer
action_gate:
  require_both_checks: true
  escalation_enabled: true
  policy_dir: "core/action_gate/policies"

# Audit Layer
audit:
  log_file_path: "core/audit/logs/audit_chain.jsonl"
  signing_enabled: true
  rotation_interval: 86400  # 24 hours
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CHAINGUARD_AI_ENV` | Environment (development/production) | `development` |
| `SECRET_KEY` | Secret key for encryption | Required |
| `DATABASE_URL` | Database connection string | `sqlite:///chainguard_ai.db` |
| `REDIS_URL` | Redis connection string | Optional |
| `LOG_LEVEL` | Logging level | `INFO` |
| `LOG_FILE` | Log file path | `logs/chainguard_ai.log` |

## Troubleshooting

### Common Issues

#### 1. Import Errors

**Problem**: `ModuleNotFoundError: No module named 'core'`

**Solution**: Ensure you're in the project directory and the virtual environment is activated.

```bash
cd /path/to/chainguard_ai
source venv/bin/activate  # Windows: venv\Scripts\activate
```

#### 2. Permission Errors

**Problem**: Permission denied when accessing files

**Solution**: Check file permissions and ownership:

```bash
sudo chown -R chainguard_ai:chainguard_ai /opt/chainguard_ai
chmod 755 /opt/chainguard_ai
```

#### 3. Model Download Failures

**Problem**: ML models fail to download

**Solution**: Check internet connection and try manual download:

```python
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')
```

#### 4. Service Won't Start

**Problem**: Systemd service fails to start

**Solution**: Check service logs:

```bash
sudo journalctl -u chainguard_ai -f
```

### Debug Mode

Enable debug mode for troubleshooting:

```env
CHAINGUARD_AI_ENV=development
LOG_LEVEL=DEBUG
```

### Health Checks

Run health checks to verify installation:

```bash
# Development
python scripts/dev.py db

# Production
sudo python scripts/deploy.py health
```

## Verification

### Test Suite

Run the complete test suite:

```bash
# All tests
python scripts/dev.py test

# Specific test types
python scripts/dev.py test --type unit
python scripts/dev.py test --type integration
python scripts/dev.py test --type attack
python scripts/dev.py test --type performance
```

### Attack Simulation

Test security with attack simulations:

```bash
python scripts/dev.py attack
```

### Performance Testing

Run performance tests:

```bash
python scripts/dev.py perf --duration 60 --concurrency 10
```

## Next Steps

After successful installation:

1. **Review Configuration**: Customize config.yaml for your use case
2. **Register Agents**: Register your AI agents with ChainGuardAI
3. **Integrate API**: Use the REST API to protect your agents
4. **Monitor Security**: Set up monitoring and alerting
5. **Read Documentation**: Explore the full documentation

## Support

- **Documentation**: [docs/](./README.md)
- **API Reference**: http://localhost:8000/docs
- **Issues**: GitHub Issues
- **Community**: Discord/Slack

## Security Considerations

- Keep your `.env` file secure and never commit to version control
- Use strong secrets and rotate them regularly
- Enable audit logging in production
- Monitor security events and alerts
- Keep dependencies updated
- Use HTTPS in production
- Implement proper access controls

## Performance Optimization

- Use SSD storage for better I/O performance
- Configure appropriate memory limits
- Enable Redis for caching
- Use load balancers for high availability
- Monitor resource usage regularly
- Optimize ML model inference with GPU if available
