# ChainGuardAI

A comprehensive multi-layered security framework for AI agents that provides cryptographic identity, injection detection, runtime gating, and tamper-evident audit logging.

## Architecture Overview

ChainGuardAI implements 5 distinct security layers:

1. **Cryptographic Agent Identity** - DID-based identity with verifiable credentials
2. **Ingestion vs Execution Separation** - Sandboxed input processing
3. **Multi-Stage Injection Detection** - Regex, embedding, and ML-based detection
4. **Runtime Action Gate** - Dual-check system for scope and safety validation
5. **Tamper-Evident Audit Log** - Hash-chained, signed audit trail

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd chainguard_ai

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env

# Edit .env with your configuration
nano .env

# Bootstrap the system
python scripts/bootstrap.py
```

### Basic Usage

```python
from chainguard_ai.core import ChainGuardAI
from chainguard_ai.agents.finance_agent import FinanceAgent

# Initialize ChainGuardAI
shield = ChainGuardAI(config_path="config.yaml")

# Create and wrap an agent
agent = FinanceAgent()
protected_agent = shield.wrap_agent(agent)

# Use the agent with full protection
response = protected_agent.process_request("Transfer $100 to account 12345")
```

## Project Structure

```
chainguard_ai/
|
# Core Framework (5 security layers)
core/
  identity/          # Layer 1: Cryptographic Identity
  ingestion/         # Layer 2: Input Processing
  detection/         # Layer 3: Injection Detection
  action_gate/       # Layer 4: Runtime Protection
  audit/             # Layer 5: Audit Logging
|
# Example Implementations
agents/
  finance_agent/     # Finance agent example
  marketing_agent/   # Marketing agent example
|
# REST API
api/
  routes/            # API endpoints
  middleware/        # Authentication and rate limiting
|
# Testing
tests/
  unit/              # Unit tests
  integration/       # Integration tests
  attack_simulations/ # Security testing
|
# Utilities
scripts/             # Setup and maintenance scripts
docs/               # Documentation
```

## Security Features

### Identity & Authentication
- Decentralized Identifiers (DIDs) for agent identity
- Ed25519 cryptographic signatures
- Verifiable Credentials for capability management
- Agent registry with public key management

### Injection Detection
- **Stage 1**: Regex pattern matching for known attacks
- **Stage 2**: Semantic embedding analysis for anomaly detection
- **Stage 3**: ML classifier for intent validation
- Risk aggregation with configurable thresholds

### Runtime Protection
- Scope validation against agent role
- Parameter safety checking
- Resource usage limits
- Escalation to human-in-loop when needed

### Audit & Compliance
- SHA-256 hash-chained log entries
- Cryptographic signing of audit records
- Tamper detection and alerts
- Log rotation and archiving

## Configuration

### Environment Variables

Key environment variables (see `.env.example`):

```bash
# Core settings
CHAINGUARD_AI_ENV=development
LOG_LEVEL=INFO

# Security
REGISTRY_ENCRYPTION_KEY=your_key_here
API_SECRET_KEY=your_api_secret_here

# Detection thresholds
ANOMALY_THRESHOLD=0.7
RISK_THRESHOLD_HIGH=0.8
RISK_THRESHOLD_MEDIUM=0.5
```

### YAML Configuration

The `config.yaml` file provides comprehensive configuration for all layers:

```yaml
# Detection layer weights
detection:
  risk:
    weights:
      regex: 0.3
      embedding: 0.4
      classifier: 0.3

# Action gate settings
action_gate:
  scope_check:
    enabled: true
    strict_mode: false
  safety_check:
    resource_limits:
      max_file_size: 10485760  # 10MB
```

## API Usage

### Start the API Server

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Key Endpoints

- `POST /api/v1/agents/register` - Register a new agent
- `POST /api/v1/messages` - Send message to agent
- `GET /api/v1/audit/logs` - Query audit logs
- `POST /api/v1/audit/verify` - Verify audit chain integrity

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run specific test suites
pytest tests/unit/
pytest tests/integration/
pytest tests/attack_simulations/

# Run with coverage
pytest --cov=chainguard_ai tests/
```

### Security Testing

```bash
# Run attack simulations
python tests/attack_simulations/simulate_prompt_injection.py
python tests/attack_simulations/simulate_impersonation.py
python tests/attack_simulations/simulate_privilege_escalation.py
```

## Security Considerations

### Threat Model

ChainGuardAI protects against:
- **Prompt Injection**: Multi-stage detection prevents malicious instructions
- **Impersonation**: Cryptographic identity verification
- **Privilege Escalation**: Scope validation and capability checking
- **Data Tampering**: Hash-chained audit logs with signing

### Limitations

- Requires proper key management
- Detection accuracy depends on training data quality
- Human-in-loop escalation needs monitoring
- Performance overhead from security layers

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all security tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For security issues, please email security@chainguard_ai.dev
For general questions, please open an issue on GitHub.
