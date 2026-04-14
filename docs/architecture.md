# ChainGuardAI Architecture

## Overview

ChainGuardAI is a comprehensive security framework designed to protect AI agents from injection attacks, unauthorized access, and privilege escalation. The architecture follows a layered defense approach with five distinct security layers, each providing specific protection mechanisms.

## Core Architecture

### Layer 1: Cryptographic Agent Identity

**Purpose**: Establish and verify agent identities using decentralized identifiers and verifiable credentials.

**Components**:
- **KeyManager**: Handles Ed25519 keypair generation and secure storage
- **RegistryManager**: Creates and manages Decentralized Identifiers (DIDs) for agents
- **Agent Registry**: Maintains a registry of known agents and their public keys
- **Signature Utils**: Signs and verifies message signatures

**Security Features**:
- Cryptographic identity verification
- Capability-based access control
- Tamper-evident credentials
- Agent-to-agent authentication

**Implementation**:
- Located in `core/identity/`
- Uses Ed25519 cryptographic algorithm
- File-based registry storage with encryption support
- Automatic key generation on agent registration

### Layer 2: Ingestion vs Execution Separation

**Purpose**: Separate input processing from execution to prevent direct code injection.

**Components**:
- **IngestionWorker**: Sandboxed process that reads raw input without execution capabilities
- **Input Sanitizer**: Strips instructions, tags, and hidden content from raw input
- **Intent Parser**: Converts raw text to structured JSON intent objects
- **Schema Validator**: Validates intent JSON against schema before handoff
- **Process Isolation**: Separate process for safe input processing

**Security Features**:
- Process isolation
- Input sanitization
- Schema validation
- Safe execution environment

**Implementation**:
- Located in `core/ingestion/`
- Uses process sandboxing for isolation
- JSON schema validation for intent objects
- Configurable input sanitization rules

### Layer 3: Multi-Stage Injection Detection

**Purpose**: Detect injection attempts using multiple detection techniques.

**Components**:
- **DetectionPipeline**: Orchestrates all detectors and returns final risk score
- **Stage 1 - Regex Detector**: Fast pattern matching for known injection phrases
- **Stage 2 - Embedding Detector**: Semantic anomaly detection via sentence-transformer embeddings
- **Stage 3 - Intent Classifier**: ML classifier to validate intent against agent's role
- **Risk Aggregator**: Combines stage scores into final risk level (LOW/MED/HIGH)

**Security Features**:
- Multi-layered detection
- Pattern-based filtering
- Semantic analysis
- Role-based validation

**Implementation**:
- Located in `core/detection/`
- Uses sentence-transformers for semantic analysis
- Configurable detection thresholds
- Real-time risk scoring
- Supports model training and updates

### Layer 4: Runtime Action Gate

**Purpose**: Enforce runtime policies and prevent unauthorized actions.

**Components**:
- **GateController**: Main entry point that intercepts planned actions
- **Scope Check**: Verifies action is within agent's declared role/scope
- **Safety Check**: Evaluates action parameters for risk (amounts, paths, etc.)
- **Escalation Handler**: Handles denied actions with human-in-loop or hard block
- **Policy Engine**: Loads and applies role-based policies per agent type
- **Policy Files**: JSON policy files for different agent types

**Security Features**:
- Dual-check validation
- Policy enforcement
- Risk assessment
- Human escalation

**Implementation**:
- Located in `core/action_gate/`
- Configurable dual-check validation
- Role-based policy enforcement
- Automatic escalation handling
- Supports custom policy definitions

### Layer 5: Tamper-Evident Audit Log

**Purpose**: Maintain an immutable audit trail of all agent actions.

**Components**:
- **AuditLogger**: Appends events to the hash-chain log
- **Hash Chain**: SHA-256 chaining logic where each entry hashes the previous
- **Log Verifier**: Verifies chain integrity to detect tampering
- **Log Signer**: Signs each log entry with ChainGuardAI's private key
- **Log Storage**: Append-only log file in JSON Lines format with archive rotation

**Security Features**:
- Immutable logging
- Cryptographic chaining
- Signature verification
- Tamper detection

**Implementation**:
- Located in `core/audit/`
- SHA-256 hash chaining for integrity
- Configurable log rotation and compression
- Automatic integrity verification
- Supports log archiving and backup

## Data Flow

```
User Input
    |
    v
Layer 2: Ingestion (Sanitize & Parse)
    |
    v
Layer 3: Detection (Multi-Stage Analysis)
    |
    v
Layer 4: Action Gate (Policy Enforcement)
    |
    v
Layer 5: Audit (Immutable Logging)
    |
    v
Agent Execution
```

## Security Model

### Threat Mitigation

1. **Prompt Injection**:
   - Input sanitization removes malicious patterns
   - Multi-stage detection identifies injection attempts
   - Scope validation prevents unauthorized actions

2. **Agent Impersonation**:
   - Cryptographic identities prevent spoofing
   - Verifiable credentials prove capabilities
   - Signature verification ensures authenticity

3. **Privilege Escalation**:
   - Role-based policies limit actions
   - Dual-check validation prevents bypass
   - Audit logging tracks all attempts

4. **Data Exfiltration**:
   - Intent validation blocks unauthorized data access
   - Safety checks prevent suspicious transfers
   - Comprehensive audit trail enables detection

### Defense in Depth

The architecture implements defense-in-depth with multiple independent security layers:

- **Prevention**: Input sanitization, identity verification, policy enforcement
- **Detection**: Multi-stage analysis, anomaly detection, pattern matching
- **Response**: Action blocking, human escalation, audit logging
- **Recovery**: Audit verification, tamper detection, incident analysis

## Agent Types

### Finance Agent
- **Capabilities**: Process payments, generate reports, access financial data
- **Policies**: Transaction limits, recipient validation, amount restrictions
- **Risk Profile**: High - handles sensitive financial operations

### Marketing Agent
- **Capabilities**: Create campaigns, analyze data, manage social media
- **Policies**: Budget limits, content restrictions, access controls
- **Risk Profile**: Medium - handles marketing operations

### Custom Agents
- **Capabilities**: Defined per agent requirements
- **Policies**: Custom policies based on role and risk
- **Risk Profile**: Variable based on capabilities

## Integration Points

### API Layer
- **REST API**: Exposes ChainGuardAI as a service
- **Authentication**: JWT-based auth with role-based access
- **Rate Limiting**: Token bucket algorithm for API protection
- **Middleware**: Security and audit middleware for all requests

### Agent Integration
- **SDK**: Python SDK for easy agent integration
- **Decorators**: Function decorators for automatic protection
- **Configuration**: YAML-based configuration for agents
- **Monitoring**: Built-in metrics and health checks

## Performance Considerations

### Optimization Strategies
- **Caching**: Embedding cache for semantic analysis
- **Parallel Processing**: Concurrent detection stages
- **Lazy Loading**: On-demand policy loading
- **Batch Processing**: Efficient audit log operations

### Scalability
- **Horizontal Scaling**: Multiple detection pipeline instances
- **Load Balancing**: Distribute requests across pipeline instances
- **Caching Layer**: Redis for shared state and caching
- **Database**: PostgreSQL for registry and audit storage

## Security Best Practices

### Key Management
- **Root Authority**: Secure offline storage of root keys
- **Agent Keys**: Individual key pairs per agent
- **Key Rotation**: Automated key rotation capabilities
- **Backup**: Encrypted backup of critical keys

### Audit Security
- **Immutable Logs**: Hash-chained, signed audit entries
- **Access Control**: Restricted access to audit logs
- **Verification**: Regular integrity verification
- **Archival**: Secure long-term storage with encryption

### Operational Security
- **Monitoring**: Real-time security monitoring
- **Alerting**: Automated threat detection alerts
- **Incident Response**: Defined incident response procedures
- **Compliance**: Audit trail for regulatory compliance

## Deployment Architecture

### Development Environment
```
Local Development
    |
    v
Docker Compose (All Services)
    |
    v
ChainGuardAI Core + API + Agents
```

### Production Environment
```
Load Balancer
    |
    v
API Gateway (Rate Limiting, Auth)
    |
    v
ChainGuardAI API (Multiple Instances)
    |
    v
Detection Pipeline (Scaled Horizontally)
    |
    v
Audit Service (Distributed Logging)
    |
    v
Database Cluster (PostgreSQL)
```

### Monitoring Stack
```
Prometheus (Metrics)
    |
    v
Grafana (Visualization)
    |
    v
AlertManager (Alerts)
    |
    v
ELK Stack (Logging)
```

## Configuration Management

### Environment Configuration
- **Development**: Local configuration with debug settings
- **Testing**: Isolated test environment with mock data
- **Staging**: Production-like environment for testing
- **Production**: Hardened configuration with security settings

### Policy Management
- **Default Policies**: Base policies for common agent types
- **Custom Policies**: Organization-specific policies
- **Policy Updates**: Automated policy distribution
- **Version Control**: Git-based policy versioning

## Future Enhancements

### Planned Features
- **Machine Learning**: Advanced ML models for threat detection
- **Blockchain**: Distributed audit ledger for enhanced security
- **Zero Trust**: Zero Trust architecture implementation
- **Compliance**: Automated compliance reporting

### Research Areas
- **Quantum Resistance**: Post-quantum cryptographic algorithms
- **Federated Learning**: Distributed threat intelligence
- **Behavioral Analysis**: Agent behavior profiling
- **Auto-Remediation**: Automated threat response

## Conclusion

ChainGuardAI provides a comprehensive, layered security framework for AI agents. By combining cryptographic identity verification, multi-stage injection detection, policy enforcement, and immutable audit logging, it creates a robust defense against a wide range of security threats while maintaining performance and usability.

The architecture is designed to be extensible, allowing for new detection methods, policy types, and agent capabilities to be added as the security landscape evolves.
