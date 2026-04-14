# ChainGuardAI API Reference

## Overview

The ChainGuardAI API provides a RESTful interface for interacting with the ChainGuardAI security framework. This API enables agent registration, message processing, audit log access, and security management.

## Base URL

```
Development: http://localhost:8000
Production: https://api.chainguard_ai.example.com
```

## API Version

Current API version: **v1.0.0**

## Authentication

All API endpoints currently use basic authentication. JWT and API key authentication will be available in future versions.

### Basic Authentication
```http
Authorization: Basic <base64_encoded_credentials>
```

## API Endpoints

### 1. Agent Management

#### Register Agent
```http
POST /api/v1/agents/register
```

**Request Body**:
```json
{
  "agent_id": "finance_agent_001",
  "agent_type": "finance_agent",
  "capabilities": ["process_payments", "generate_reports"],
  "config": {
    "max_transaction_amount": 10000,
    "requires_approval": true
  }
}
```

**Response**:
```json
{
  "success": true,
  "agent_id": "finance_agent_001",
  "message": "Agent registered successfully",
  "session_id": "session_12345"
}
```

#### Get Agent Info
```http
GET /api/v1/agents/{agent_id}
```

**Response**:
```json
{
  "agent_id": "finance_agent_001",
  "agent_type": "finance_agent",
  "is_active": true,
  "session_active": true,
  "protected": true,
  "trust_score": 0.95,
  "statistics": {
    "requests_processed": 1250,
    "threats_blocked": 15,
    "avg_response_time": 0.25
  },
  "health_status": {
    "status": "healthy",
    "last_check": 1704067200
  }
}
```

#### Process Request
```http
POST /api/v1/agents/process
```

**Request Body**:
```json
{
  "request": "Transfer $100 to John Doe",
  "agent_id": "finance_agent_001",
  "session_id": "session_12345"
}
```

**Response**:
```json
{
  "success": true,
  "response": "Transfer of $100 to John Doe processed successfully",
  "agent_id": "finance_agent_001",
  "session_id": "session_12345",
  "processing_time": 0.25,
  "risk_level": "LOW",
  "shield_protection": true
}
```

#### Get Agent Status
```http
GET /api/v1/agents/{agent_id}/status
```

**Response**:
```json
{
  "agent_id": "finance_agent_001",
  "agent_type": "finance_agent",
  "is_active": true,
  "session_active": true,
  "protected": true,
  "trust_score": 0.95,
  "statistics": {
    "requests_processed": 1250,
    "threats_blocked": 15,
    "avg_response_time": 0.25
  },
  "health_status": {
    "status": "healthy",
    "last_check": 1704067200
  }
}
```

### 2. Security Management

#### Get Security Status
```http
GET /api/v1/security/status
```

**Response**:
```json
{
  "status": "operational",
  "protection_active": true,
  "threats_detected": 5,
  "risk_level": "low",
  "last_scan": 1704067200,
  "components": {
    "identity_layer": {"status": "active", "issues": []},
    "ingestion_layer": {"status": "active", "issues": []},
    "detection_layer": {"status": "active", "issues": []},
    "action_gate_layer": {"status": "active", "issues": []},
    "audit_layer": {"status": "active", "issues": []}
  }
}
```

#### Get Threat Alerts
```http
GET /api/v1/security/threats
```

**Response**:
```json
{
  "threats": [
    {
      "alert_id": "threat_12345",
      "severity": "medium",
      "threat_type": "prompt_injection",
      "description": "Suspicious instruction override attempt detected",
      "timestamp": 1704067200,
      "agent_id": "finance_agent_001",
      "resolved": false
    }
  ]
}
```

#### Update Security Configuration
```http
PUT /api/v1/security/config
```

**Request Body**:
```json
{
  "threat_detection_enabled": true,
  "auto_block_enabled": false,
  "alert_threshold": "medium",
  "scan_interval": 300
}
```

### 3. Audit and Logging

#### Query Audit Logs
```http
GET /api/v1/audit/logs
```

**Query Parameters**:
- `limit` (optional): Maximum number of results (default: 100, max: 1000)
- `event_type` (optional): Filter by event type
- `agent_id` (optional): Filter by agent ID
- `start_time` (optional): Filter by start timestamp
- `end_time` (optional): Filter by end timestamp

**Response**:
```json
[
  {
    "entry_id": "log_12345",
    "timestamp": 1704067200,
    "event_type": "agent_request",
    "agent_id": "finance_agent_001",
    "session_id": "session_12345",
    "event_data": {
      "request": "Transfer $100 to John Doe",
      "risk_level": "LOW",
      "processing_time": 0.25
    },
    "entry_hash": "abc123...",
    "previous_hash": "def456...",
    "signature": "sig789...",
    "metadata": {
      "source": "api",
      "version": "1.0.0"
    }
  }
]
```

#### Verify Audit Integrity
```http
POST /api/v1/audit/verify
```

**Request Body**:
```json
{
  "start_date": "2024-01-01T00:00:00Z",
  "end_date": "2024-01-01T23:59:59Z"
}
```

**Response**:
```json
{
  "verified": true,
  "issues": [],
  "warnings": ["No entries found in specified range"],
  "entries_checked": 0,
  "broken_links": [],
  "verification_time": 0.05
}
```

#### Get Audit Statistics
```http
GET /api/v1/audit/stats
```

**Response**:
```json
{
  "total_entries": 1250,
  "signed_entries": 1250,
  "date_range": {
    "start": 1704067200,
    "end": 1704153600
  },
  "event_types": {
    "agent_request": 1000,
    "agent_registered": 50,
    "threat_detected": 200
  },
  "agents": {
    "finance_agent_001": 600,
    "marketing_agent_001": 650
  },
  "avg_entries_per_day": 125.0
}
```

### 4. Security Management

#### Verify Credentials
```http
POST /api/v1/security/verify-credentials
```

**Request Body**:
```json
{
  "verifiable_credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential"],
    "credentialSubject": {
      "id": "did:web:chainguard_ai:finance_agent_001",
      "capabilities": ["process_payments"]
    },
    "proof": {
      "type": "Ed25519Signature2018",
      "jws": "eyJhbGciOiJFZERTQSJ9..."
    }
  }
}
```

**Response**:
```json
{
  "valid": true,
  "subject": "did:web:chainguard_ai:finance_agent_001",
  "capabilities": ["process_payments"],
  "role": "finance_agent",
  "issuer": "did:web:chainguard_ai:root",
  "issued_at": "2024-01-01T00:00:00Z",
  "verified_at": "2024-01-01T12:00:00Z"
}
```

#### Check Message Signature
```http
POST /api/v1/security/verify-signature
```

**Request Body**:
```json
{
  "message": {
    "content": "Transfer $100 to John",
    "timestamp": "2024-01-01T12:00:00Z",
    "sender": "did:web:chainguard_ai:finance_agent_001"
  },
  "signature": "eyJhbGciOiJFZERTQSJ9...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

**Response**:
```json
{
  "valid": true,
  "verified_at": "2024-01-01T12:00:00Z"
}
```

#### Get Security Status
```http
GET /api/v1/security/status
```

**Response**:
```json
{
  "status": "operational",
  "components": {
    "identity_layer": "operational",
    "ingestion_layer": "operational",
    "detection_layer": "operational",
    "action_gate_layer": "operational",
    "audit_layer": "operational"
  },
  "active_agents": 25,
  "messages_processed_last_hour": 1250,
  "threats_blocked_last_hour": 15,
  "system_health": "healthy"
}
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": {
      "field": "agent_type",
      "issue": "Invalid agent type specified"
    },
    "timestamp": "2024-01-01T12:00:00Z",
    "request_id": "req_12345"
  }
}
```

### Common Error Codes

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| VALIDATION_ERROR | 400 | Request validation failed |
| UNAUTHORIZED | 401 | Authentication required |
| FORBIDDEN | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| CONFLICT | 409 | Resource conflict |
| RATE_LIMITED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Internal server error |
| SERVICE_UNAVAILABLE | 503 | Service temporarily unavailable |

## Rate Limiting

### Rate Limits by Endpoint

| Endpoint | Requests/Minute | Burst Size |
|----------|----------------|------------|
| Agent Registration | 10 | 5 |
| Message Send | 30 | 10 |
| Audit Query | 20 | 5 |
| Security Verify | 15 | 3 |

### Rate Limit Headers
```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1640995200
```

## SDK Integration

### Python SDK Example

```python
from chainguard_ai import ChainGuardAIClient

# Initialize client
client = ChainGuardAIClient(
    base_url="http://localhost:8000",
    api_key="your_api_key_here"
)

# Register agent
agent = client.agents.register(
    name="finance_agent_001",
    type="finance_agent",
    capabilities=["process_payments", "generate_reports"]
)

# Send message
response = client.messages.send(
    sender=agent.did,
    recipient="did:web:chainguard_ai:marketing_agent_001",
    message="Transfer $1000 to marketing budget",
    message_type="payment_request"
)

# Check audit logs
logs = client.audit.query(
    agent_id=agent.agent_id,
    start_date="2024-01-01T00:00:00Z",
    end_date="2024-01-01T23:59:59Z"
)
```

### JavaScript SDK Example

```javascript
import { ChainGuardAIClient } from 'chainguard_ai-js';

// Initialize client
const client = new ChainGuardAIClient({
  baseURL: 'http://localhost:8000',
  apiKey: 'your_api_key_here'
});

// Register agent
const agent = await client.agents.register({
  name: 'finance_agent_001',
  type: 'finance_agent',
  capabilities: ['process_payments', 'generate_reports']
});

// Send message
const response = await client.messages.send({
  sender: agent.did,
  recipient: 'did:web:chainguard_ai:marketing_agent_001',
  message: 'Transfer $1000 to marketing budget',
  messageType: 'payment_request'
});

// Check audit logs
const logs = await client.audit.query({
  agentId: agent.agentId,
  startDate: '2024-01-01T00:00:00Z',
  endDate: '2024-01-01T23:59:59Z'
});
```

## Webhooks

### Configure Webhook
```http
POST /api/v1/webhooks
```

**Request Body**:
```json
{
  "url": "https://your-service.com/webhook",
  "events": ["message.blocked", "agent.registered", "security.threat"],
  "secret": "webhook_secret_key",
  "active": true
}
```

### Webhook Event Format
```json
{
  "event": "message.blocked",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "message_id": "msg_12345",
    "reason": "High risk content detected",
    "risk_level": "HIGH",
    "agent_id": "agent_12345"
  },
  "signature": "sha256=webhook_signature"
}
```

## Monitoring and Metrics

### Health Check
```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "1.0.0",
  "uptime": 86400,
  "checks": {
    "database": "healthy",
    "detection_pipeline": "healthy",
    "audit_system": "healthy"
  }
}
```

### Metrics Endpoint
```http
GET /metrics
```

**Response** (Prometheus format):
```
# HELP chainguard_ai_requests_total Total number of API requests
# TYPE chainguard_ai_requests_total counter
chainguard_ai_requests_total{endpoint="/api/v1/messages/send",status="200"} 1250

# HELP chainguard_ai_threats_blocked_total Total number of blocked threats
# TYPE chainguard_ai_threats_blocked_total counter
chainguard_ai_threats_blocked_total{threat_type="prompt_injection"} 45

# HELP chainguard_ai_processing_duration_seconds Request processing duration
# TYPE chainguard_ai_processing_duration_seconds histogram
chainguard_ai_processing_duration_seconds_bucket{le="0.1"} 1000
chainguard_ai_processing_duration_seconds_bucket{le="0.5"} 1200
chainguard_ai_processing_duration_seconds_bucket{le="1.0"} 1250
```

## Configuration

### Environment Variables
```bash
# API Configuration
CHAINGUARD_AI_ENV=production
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=postgresql://user:pass@localhost/chainguard_ai

# Security
ROOT_AUTHORITY_DID=did:web:chainguard_ai:root
JWT_SECRET=jwt-secret-key
CORS_ORIGINS=https://app.example.com

# Rate Limiting
API_RATE_LIMIT=60
API_BURST_SIZE=10

# Detection Models
EMBEDDING_MODEL_PATH=/models/sentence-transformers
CLASSIFIER_MODEL_PATH=/models/intent-classifier

# Audit Configuration
AUDIT_LOG_PATH=/var/log/chainguard_ai/audit.jsonl
AUDIT_RETENTION_DAYS=365
```

## Deployment

### Docker Deployment
```yaml
version: '3.8'
services:
  chainguard_ai-api:
    image: chainguard_ai/api:latest
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/chainguard_ai
      - SECRET_KEY=${SECRET_KEY}
    depends_on:
      - db
      - redis

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=chainguard_ai
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chainguard_ai-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: chainguard_ai-api
  template:
    metadata:
      labels:
        app: chainguard_ai-api
    spec:
      containers:
      - name: chainguard_ai-api
        image: chainguard_ai/api:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: chainguard_ai-secrets
              key: database-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## Support

### API Support Channels
- **Documentation**: https://docs.chainguard_ai.example.com
- **Support Email**: support@chainguard_ai.example.com
- **Status Page**: https://status.chainguard_ai.example.com
- **Community Forum**: https://community.chainguard_ai.example.com

### API Versioning
- **Current Version**: v1.0.0
- **Version Policy**: Semantic versioning
- **Backward Compatibility**: Maintained within major versions
- **Deprecation Notice**: 6 months advance notice for breaking changes

### Rate Limit Appeals
For rate limit increases or special requirements, contact:
- **Email**: api-requests@chainguard_ai.example.com
- **Include**: Use case, expected request volume, timeframe

This API reference provides comprehensive documentation for integrating with the ChainGuardAI security framework. For additional examples and use cases, refer to the developer documentation and SDK guides.
