# ChainGuardAI Documentation

Welcome to the comprehensive documentation for ChainGuardAI, a multi-layered security framework designed to protect AI agents from prompt injection, data exfiltration, and other security threats.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Security Features](#security-features)
- [Development Guide](#development-guide)
- [Deployment Guide](#deployment-guide)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

ChainGuardAI provides comprehensive security for AI agents through a five-layer architecture:

1. **Identity Layer**: Cryptographic identity management with DIDs and VCs
2. **Ingestion Layer**: Input sanitization and validation
3. **Detection Layer**: Multi-stage threat detection (regex, embedding, ML)
4. **Action Gate Layer**: Dual-check system for action validation
5. **Audit Layer**: Tamper-evident logging with hash chains

### Key Features

- **Prompt Injection Protection**: Detects and blocks various injection attacks
- **Data Exfiltration Prevention**: Prevents unauthorized data access
- **Cryptographic Security**: Uses modern cryptography for identity and audit
- **Real-time Monitoring**: Continuous threat detection and response
- **Comprehensive Auditing**: Tamper-evident audit trails
- **Easy Integration**: Simple API for existing agents
- **Scalable Architecture**: Designed for production workloads

## Architecture

### Layered Security Model

```
User Request
    |
    v
[Identity Layer] - Agent authentication and authorization
    |
    v
[Ingestion Layer] - Input sanitization and parsing
    |
    v
[Detection Layer] - Multi-stage threat detection
    |
    v
[Action Gate Layer] - Action validation and escalation
    |
    v
[Audit Layer] - Logging and monitoring
    |
    v
Agent Response
```

### Components

#### Core Framework

- **core/**: Main security framework
  - **identity/**: DID management, VCs, signatures
  - **ingestion/**: Input processing and validation
  - **detection/**: Threat detection algorithms
  - **action_gate/**: Action validation and policies
  - **audit/**: Logging and chain verification

#### Agent Integration

- **agents/**: Example agent implementations
  - **finance_agent/**: Financial transaction agent
  - **marketing_agent/**: Marketing campaign agent
  - **base_agent.py**: Abstract base class

#### API Layer

- **api/**: REST API for ChainGuardAI
  - **routes/**: API endpoints
  - **middleware/**: Security and audit middleware

#### Testing Suite

- **tests/**: Comprehensive test suite
  - **unit/**: Component unit tests
  - **integration/**: End-to-end tests
  - **attack_simulation/**: Security attack simulations
  - **performance/**: Performance and load tests

## Quick Start

### 1. Installation

```bash
git clone https://github.com/your-org/chainguard_ai.git
cd chainguard_ai
python scripts/setup.py
```

### 2. Basic Usage

```python
from core import ChainGuardAI
from agents.finance_agent.agent import FinanceAgent

# Create ChainGuardAI instance
shield = ChainGuardAI()

# Create and register agent
agent = FinanceAgent("my_finance_agent")
shield.register_agent(agent.agent_id, agent.agent_type, agent.get_capabilities())

# Process request with protection
result = shield.process_request(
    "Pay $50 to John Doe",
    agent.agent_id
)

if result["success"]:
    print(f"Response: {result['response']}")
else:
    print(f"Blocked: {result.get('error', 'Security violation')}")
```

### 3. API Server

```bash
python scripts/dev.py server
```

Visit http://localhost:8000/docs for interactive API documentation.

## Installation

See [Installation Guide](./installation.md) for detailed installation instructions.

### System Requirements

- Python 3.8+
- 4GB+ RAM (8GB recommended)
- 10GB+ storage
- Internet connection for model downloads

### Dependencies

The project uses the following key dependencies:
- **cryptography>=41.0.0** - Cryptographic operations
- **sentence-transformers>=2.2.0** - Embedding models
- **torch>=2.0.0** - ML framework
- **scikit-learn>=1.4.0** - Classical ML
- **fastapi>=0.104.0** - API framework
- **uvicorn>=0.24.0** - ASGI server
- **pydantic>=2.0.0** - Data validation
- **loguru>=0.7.0** - Structured logging

See [requirements.txt](../requirements.txt) for complete list.

### Quick Install

```bash
# Clone and setup
git clone https://github.com/your-org/chainguard_ai.git
cd chainguard_ai
python scripts/setup.py

# Verify installation
python scripts/dev.py test

# Start server
python scripts/dev.py server
```

## Configuration

### Configuration Files

- **config.yaml**: Main configuration
- **.env**: Environment variables
- **core/action_gate/policies/**: Agent policies
- **core/detection/stage1_regex/patterns.json**: Detection patterns

### Key Settings

```yaml
# Detection sensitivity
detection:
  regex:
    case_sensitive: false
  embedding:
    similarity_threshold: 0.7
  classifier:
    confidence_threshold: 0.8

# Action gate settings
action_gate:
  require_both_checks: true
  escalation_enabled: true

# Audit settings
audit:
  signing_enabled: true
  rotation_interval: 86400
```

## API Reference

### Core Endpoints

#### Agent Management

- `POST /api/v1/agents/register` - Register new agent
- `POST /api/v1/agents/{agent_id}/session/start` - Start agent session
- `POST /api/v1/agents/process` - Process request through agent
- `GET /api/v1/agents/{agent_id}/status` - Get agent status

#### Security Monitoring

- `GET /api/v1/security/status` - Get security status
- `GET /api/v1/security/threats` - Get threat alerts
- `POST /api/v1/security/scan` - Run security scan
- `GET /api/v1/security/metrics` - Get security metrics

#### Audit Logs

- `GET /api/v1/audit/logs` - Get audit logs
- `POST /api/v1/audit/verify-chain` - Verify audit chain
- `GET /api/v1/audit/statistics` - Get audit statistics

### Example API Usage

```python
import requests

# Register agent
response = requests.post("http://localhost:8000/api/v1/agents/register", json={
    "agent_type": "finance_agent",
    "capabilities": ["payment", "transfer", "balance_check"]
})

# Process request
response = requests.post("http://localhost:8000/api/v1/agents/process", json={
    "request": "Pay $50 to John Doe",
    "agent_id": "finance_agent_001"
})

result = response.json()
print(f"Success: {result['success']}")
print(f"Response: {result['response']}")
```

## Security Features

### Threat Detection

#### 1. Pattern Matching (Regex)

Fast detection of known attack patterns:
- Instruction override attempts
- Code injection attempts
- System command execution
- Data exfiltration patterns

#### 2. Semantic Analysis (Embeddings)

Detects semantic anomalies using sentence transformers:
- Unusual request patterns
- Out-of-context instructions
- Semantic drift detection
- Contextual threat analysis

#### 3. Machine Learning Classification

Intent classification using trained models:
- Malicious intent detection
- Command injection identification
- Privilege escalation attempts
- Policy violation detection

### Action Validation

#### Scope Check

Validates actions against agent's defined scope:
- Role-based permissions
- Capability validation
- Resource access control
- Operation constraints

#### Safety Check

Evaluates action parameters for risks:
- Parameter validation
- Resource limits
- Financial constraints
- Data access patterns

### Audit and Monitoring

#### Hash-Chain Logging

Tamper-evident audit trails:
- SHA-256 hash chaining
- Cryptographic signing
- Integrity verification
- Log rotation and archiving

#### Real-time Monitoring

Continuous security monitoring:
- Threat detection alerts
- Performance metrics
- Resource usage tracking
- Security event correlation

## Development Guide

### Project Structure

```
chainguard_ai/
|-- core/                 # Security framework (5 layers)
|   |-- identity/         # DID management, VCs, signatures
|   |-- ingestion/        # Input processing and validation
|   |-- detection/        # Multi-stage threat detection
|   |-- action_gate/      # Action validation and policies
|   `-- audit/           # Logging and monitoring
|-- agents/               # Example agent implementations
|   |-- finance_agent/    # Financial transaction agent
|   |-- marketing_agent/  # Marketing campaign agent
|   `-- base_agent.py     # Abstract base class
|-- api/                  # REST API endpoints
|-- tests/                # Comprehensive test suite
|   |-- unit/             # Component unit tests
|   |-- integration/      # End-to-end tests
|   |-- attack_simulation/ # Security attack simulations
|   `-- performance/      # Performance and load tests
|-- scripts/              # Development and deployment scripts
|   |-- setup.py          # Environment setup
|   |-- dev.py            # Development commands
|   |-- deploy.py         # Production deployment
|   |-- bootstrap.py      # System initialization
|   `-- generate_agent_keys.py # Key generation
|-- ml/                   # ML models and training data
|-- dataset/              # Training datasets
|-- config.yaml           # Main configuration
|-- requirements.txt       # Python dependencies
`-- .env.example          # Environment variables template
```

### Adding New Agents

1. **Inherit from BaseAgent**:

```python
from agents.base_agent import BaseAgent

class MyAgent(BaseAgent):
    def __init__(self, agent_id: str):
        super().__init__(agent_id, "my_agent_type")
    
    def get_capabilities(self) -> List[str]:
        return ["capability1", "capability2"]
    
    def process_request_internal(self, request: str) -> str:
        # Your agent logic here
        return f"Processed: {request}"
```

2. **Register with ChainGuardAI**:

```python
shield = ChainGuardAI()
agent = MyAgent("my_agent_001")
shield.register_agent(agent.agent_id, agent.agent_type, agent.get_capabilities())
```

### Custom Detection Patterns

Add new regex patterns to `core/detection/stage1_regex/patterns.json`:

```json
{
  "patterns": [
    {
      "name": "custom_attack",
      "pattern": "custom_regex_pattern",
      "severity": "high",
      "description": "Custom attack pattern"
    }
  ]
}
```

### Custom Policies

Create agent-specific policies in `core/action_gate/policies/`:

```json
{
  "agent_type": "my_agent",
  "allowed_actions": ["action1", "action2"],
  "denied_actions": ["dangerous_action"],
  "constraints": {
    "max_amount": 1000,
    "allowed_resources": ["resource1"]
  }
}
```

## Deployment Guide

### Development Deployment

```bash
# Start development server
python scripts/dev.py server

# Run tests
python scripts/dev.py test

# Run specific test types
python scripts/dev.py test --type unit
python scripts/dev.py test --type integration
python scripts/dev.py test --type attack
python scripts/dev.py test --type performance

# Monitor logs
python scripts/dev.py logs

# Run security attack simulations
python scripts/dev.py attack

# Performance testing
python scripts/dev.py perf --duration 60 --concurrency 10

# Database operations
python scripts/dev.py db

# Generate agent keys
python scripts/generate_agent_keys.py
```

### Production Deployment

```bash
# Deploy to production
python scripts/deploy.py deploy --env production

# Deploy with Docker
python scripts/deploy.py docker

# Health check
python scripts/deploy.py health
```

### Environment Configuration

#### Development (.env)

```env
CHAINGUARD_AI_ENV=development
LOG_LEVEL=DEBUG
SECRET_KEY=dev-secret-key
```

#### Production (.env)

```env
CHAINGUARD_AI_ENV=production
LOG_LEVEL=INFO
SECRET_KEY=production-secret-key
DATABASE_URL=postgresql://user:pass@localhost/chainguard_ai
REDIS_URL=redis://localhost:6379
```

## Testing

### Running Tests

```bash
# All tests
python scripts/dev.py test

# Specific test types
python scripts/dev.py test --type unit
python scripts/dev.py test --type integration
python scripts/dev.py test --type attack
python scripts/dev.py test --type performance

# With coverage
python scripts/dev.py test --coverage
```

### Attack Simulations

```bash
# Run all attack simulations
python scripts/dev.py attack

# Specific attack test
python scripts/dev.py attack --file tests/attack_simulation/test_prompt_injection.py
```

### Performance Testing

```bash
# Performance test
python scripts/dev.py perf --duration 60 --concurrency 10
```

### Test Coverage

- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Attack Simulations**: Security validation
- **Performance Tests**: Load and stress testing

## Troubleshooting

### Common Issues

#### Installation Problems

1. **Python Version**: Ensure Python 3.8+
2. **Dependencies**: Run `pip install -r requirements.txt`
3. **Permissions**: Check file permissions for data directories

#### Runtime Issues

1. **Model Downloads**: Check internet connection
2. **Memory Usage**: Monitor resource consumption
3. **Configuration**: Validate config.yaml syntax

#### Performance Issues

1. **Model Loading**: Pre-load models for better performance
2. **Caching**: Enable Redis for caching
3. **Hardware**: Consider GPU acceleration for ML models

### Debug Mode

Enable debug mode for troubleshooting:

```env
CHAINGUARD_AI_ENV=development
LOG_LEVEL=DEBUG
```

### Health Checks

```bash
# Development
python scripts/dev.py db

# Production
python scripts/deploy.py health
```

### Log Analysis

```bash
# Monitor logs
python scripts/dev.py logs

# Search audit logs
curl "http://localhost:8000/api/v1/audit/logs?limit=100"
```

## Best Practices

### Security

1. **Environment Variables**: Never commit secrets to version control
2. **Access Control**: Implement proper authentication and authorization
3. **Audit Logging**: Enable audit logging in production
4. **Regular Updates**: Keep dependencies updated
5. **Monitoring**: Set up security monitoring and alerting

### Performance

1. **Caching**: Use Redis for caching and session management
2. **Load Balancing**: Use load balancers for high availability
3. **Resource Limits**: Configure appropriate memory and CPU limits
4. **Monitoring**: Monitor resource usage and performance metrics

### Development

1. **Testing**: Write comprehensive tests for new features
2. **Documentation**: Keep documentation updated
3. **Code Quality**: Use linting and formatting tools
4. **Version Control**: Use semantic versioning and proper branching

## Support and Community

- **Documentation**: [Full Documentation](./README.md)
- **API Reference**: http://localhost:8000/docs
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Community**: Discord/Slack

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

### Code Standards

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write comprehensive docstrings
- Add tests for new features
- Update documentation

## License

ChainGuardAI is licensed under the MIT License. See [LICENSE](../LICENSE) for details.

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for version history and changes.
