# Architecture Quick Reference Guide

## System Overview

**Platform**: AI-Powered Trading & Chat Platform  
**Architecture**: Microservices, Event-Driven, Multi-Region  
**Scale**: Enterprise-grade, millions of users

---

## Service Catalog

| Service | Port | Technology | Primary DB | Key Features |
|---------|------|------------|------------|--------------|
| Auth/User | 3001 | Node.js + Fastify | PostgreSQL + Redis | JWT, OAuth, RBAC, MFA |
| Chat | 3003 | Node.js + WebSocket | MongoDB + Redis | Real-time messaging, multi-user rooms |
| Discussion Hub | 3004 | Node.js | MongoDB + Elasticsearch | Threaded discussions, reputation |
| Chart & Analysis | 3005 | Node.js + Python | TimescaleDB + S3 | Technical indicators, chart generation |
| Alerts | 3006 | Node.js | PostgreSQL + Redis | Custom alerts, multi-channel notifications |
| AI/ML | 3007 | Python + Node.js | Vector DB + PostgreSQL | LLM inference, RAG, multiple modes |
| Memory/Vector | 3008 | Python | Vector DB + PostgreSQL | Embeddings, semantic search |
| Worker | 3009 | Node.js/Python | Various | Background jobs, embeddings, backtesting |
| Audit | 3010 | Node.js | Elasticsearch + PostgreSQL | Audit logs, security events |

---

## Database Strategy

| Database | Use Case | Scaling | Backup |
|----------|----------|---------|--------|
| PostgreSQL | Users, auth, metadata | Read replicas, partitioning | Daily full, hourly incremental |
| MongoDB | Chat messages, discussions | Sharding, replica sets | Oplog replication |
| Redis | Cache, sessions, pub/sub | Redis Cluster | RDB + AOF |
| TimescaleDB | Market data, time-series | Hypertables, compression | Continuous WAL |
| Vector DB | Embeddings, RAG | Distributed cluster | Snapshot backups |
| Elasticsearch | Search, logs | Sharding, replicas | Index rotation |
| S3/MinIO | Files, charts, backups | Automatic | Versioning, cross-region |

---

## Technology Stack

### Backend
- **Runtime**: Node.js (Fastify), Python (FastAPI)
- **Communication**: gRPC, WebSocket, REST
- **Message Queue**: Apache Kafka, Redis Pub/Sub

### Frontend
- **Web**: React/Vue.js
- **Mobile**: React Native/Flutter
- **Desktop**: Electron (optional)

### Infrastructure
- **Containers**: Docker
- **Orchestration**: Kubernetes
- **CI/CD**: GitHub Actions/Jenkins
- **IaC**: Terraform, Helm

### Monitoring
- **Metrics**: Prometheus
- **Visualization**: Grafana
- **Tracing**: Jaeger
- **Logging**: ELK Stack (Elasticsearch, Logstash, Kibana)

### Security
- **WAF**: CloudFlare/AWS WAF
- **CDN**: CloudFlare/AWS CloudFront
- **Secrets**: Vault/AWS Secrets Manager
- **Encryption**: TLS 1.3, AES-256

---

## AI Modes & Characteristics

| Mode | Latency | Model Size | Use Case | Cost |
|------|---------|------------|----------|------|
| Fast | < 200ms | 7B params | Quick questions | Low |
| Deep Thinking | < 5s | 70B+ params | Complex reasoning | High |
| Trade Buddy | < 1s | Fine-tuned | Emotional support | Medium |
| Stock Analysis | < 3s | Multi-model | Technical/fundamental | High |
| Web Search | < 10s | LLM + Crawler | Real-time research | Medium |
| Learn | < 2s | Fine-tuned | Tutoring | Medium |
| Normal Search | < 500ms | Lightweight | Quick lookup | Low |

---

## Scaling Strategies

### Horizontal Scaling
- **Stateless Services**: Auto-scale based on CPU/memory
- **Stateful Services**: Read replicas, sharding
- **Kubernetes HPA**: Automatic pod scaling
- **Cluster Autoscaler**: Node-level scaling

### Performance Optimization
- **Caching**: Redis (L2), In-memory (L1), CDN (L3)
- **Database**: Connection pooling, read replicas, indexing
- **API**: Compression, pagination, field selection
- **CDN**: Static assets, chart images

---

## Security Layers

1. **Edge**: DDoS protection, WAF, rate limiting
2. **Network**: VPC isolation, firewall, VPN
3. **Application**: TLS, JWT, input validation
4. **Data**: Encryption at rest/transit, RBAC
5. **Monitoring**: SIEM, audit logs, vulnerability scanning

---

## Deployment Architecture

### Regions
- **US**: Primary region
- **EU**: Secondary region
- **Asia**: Tertiary region

### Availability Zones
- **Multi-AZ**: All critical services
- **Auto-failover**: Database replication
- **Health Checks**: Liveness and readiness probes

### CI/CD Pipeline
1. Code commit → CI (tests, build)
2. Container registry → CD (deploy)
3. Staging → Production (blue-green/rolling)

---

## Monitoring Metrics

### Application Metrics
- Request rate (RPS)
- Error rate (%)
- Response time (p50, p95, p99)
- Active users
- Chat messages/sec

### Infrastructure Metrics
- CPU usage (%)
- Memory usage (%)
- Disk I/O
- Network throughput
- Database connections

### Business Metrics
- Daily active users (DAU)
- AI queries per user
- Trading alerts triggered
- Chat room participation
- Premium conversions

---

## Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Error Rate | > 0.5% | > 1% |
| Response Time (p95) | > 500ms | > 1s |
| CPU Usage | > 70% | > 90% |
| Memory Usage | > 80% | > 90% |
| DB Connections | > 70% | > 80% |
| Cache Hit Rate | < 85% | < 70% |

---

## Disaster Recovery

- **RTO**: < 4 hours (Recovery Time Objective)
- **RPO**: < 1 hour (Recovery Point Objective)
- **Backups**: Daily full, hourly incremental
- **Testing**: Quarterly DR drills
- **Multi-Region**: Cross-region replication

---

## Cost Optimization

### Infrastructure
- Spot instances for non-critical workloads
- Auto-scaling to match demand
- Reserved instances for predictable load
- Tiered storage (hot/warm/cold)

### AI/ML
- Route simple queries to lightweight models
- Cache common responses
- Batch processing for embeddings
- Use local LLMs when possible

---

## Key Performance Indicators (KPIs)

### Availability
- **Target**: 99.9% uptime (8.76 hours downtime/year)
- **Monitoring**: External uptime checks
- **SLA**: Defined per service tier

### Performance
- **Chat Latency**: < 100ms (p95)
- **AI Response**: < 500ms (Fast Mode), < 5s (Deep Thinking)
- **API Response**: < 200ms (p95)

### Scalability
- **Concurrent Users**: 10,000+ per region
- **Messages/sec**: 50,000+
- **AI Queries/sec**: 5,000+

---

## API Endpoints (Key)

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/refresh` - Refresh token
- `POST /api/auth/logout` - Logout

### Chat
- `WS /api/chat/connect` - WebSocket connection
- `POST /api/chat/message` - Send message
- `GET /api/chat/history` - Get chat history
- `POST /api/chat/room` - Create room

### AI
- `POST /api/ai/chat` - AI chat request
- `POST /api/ai/analyze` - Stock analysis
- `POST /api/ai/search` - Web search
- `POST /api/ai/mode` - Switch AI mode

### Charts
- `GET /api/charts/{symbol}` - Get chart data
- `POST /api/charts/generate` - Generate chart
- `GET /api/charts/indicators` - Get indicators

---

## Network Ports

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| API Gateway | 443 | HTTPS | External API |
| Auth Service | 3001 | gRPC/REST | Authentication |
| Chat Service | 3003 | WebSocket/gRPC | Real-time chat |
| AI Service | 3007 | gRPC/REST | AI inference |
| PostgreSQL | 5432 | TCP | Database |
| MongoDB | 27017 | TCP | Document store |
| Redis | 6379 | TCP | Cache |
| Kafka | 9092 | TCP | Message queue |
| Prometheus | 9090 | HTTP | Metrics |
| Grafana | 3000 | HTTP | Dashboards |

---

## Data Retention Policies

| Data Type | Retention | Archive |
|-----------|-----------|---------|
| Chat Messages | 1 year | S3 (7 years) |
| Market Data | 10 years | S3 (permanent) |
| User Data | Account lifetime | S3 (7 years after deletion) |
| Audit Logs | 2 years | S3 (7 years) |
| Application Logs | 30 days | S3 (1 year) |
| Metrics | 15 days | S3 (1 year) |

---

## Compliance & Regulations

- **SOC 2**: Security and availability controls
- **GDPR**: Data privacy and user rights
- **Financial Regulations**: Trading platform compliance
- **PCI DSS**: If handling payments (future)

---

## Quick Troubleshooting

### High Error Rate
1. Check application logs
2. Review database connections
3. Verify service health
4. Check external dependencies

### Slow Response Times
1. Check cache hit rates
2. Review database query performance
3. Verify network latency
4. Check service resource usage

### Database Issues
1. Check connection pool usage
2. Review slow query logs
3. Verify replication lag
4. Check disk space

### AI Service Issues
1. Check LLM API status
2. Review queue depth
3. Verify GPU availability
4. Check model serving health

---

## Contact & Resources

- **Architecture Diagrams**: `ARCHITECTURE_DIAGRAMS.md`
- **Deep Analysis**: `ARCHITECTURE_ANALYSIS.md`
- **Requirements**: `AI.txt`

---
