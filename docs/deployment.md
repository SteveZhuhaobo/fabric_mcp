# Deployment Guide

This guide covers deploying the Fabric Lakehouse MCP Server in various environments.

## Deployment Options

### 1. Local Development

For local development and testing:

```bash
# Install in development mode
pip install -e .

# Run with development configuration
fabric-lakehouse-mcp-server --config-file config/development.env
```

### 2. Docker Deployment

#### Build Docker Image

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY pyproject.toml .
RUN pip install .

# Copy application code
COPY fabric_lakehouse_mcp/ ./fabric_lakehouse_mcp/

# Create non-root user
RUN useradd --create-home --shell /bin/bash mcp
USER mcp

# Expose port (if needed for health checks)
EXPOSE 8080

# Run the server
CMD ["fabric-lakehouse-mcp-server"]
```

#### Docker Compose

```yaml
version: '3.8'

services:
  fabric-lakehouse-mcp:
    build: .
    environment:
      - FABRIC_WORKSPACE_ID=${FABRIC_WORKSPACE_ID}
      - FABRIC_LAKEHOUSE_ID=${FABRIC_LAKEHOUSE_ID}
      - FABRIC_TENANT_ID=${FABRIC_TENANT_ID}
      - FABRIC_AUTH_METHOD=managed_identity
      - LOG_LEVEL=INFO
      - STRUCTURED_LOGGING=true
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "fabric-lakehouse-mcp-server", "--health-check"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### 3. Azure Container Instances

Deploy using Azure CLI:

```bash
# Create resource group
az group create --name fabric-mcp-rg --location eastus

# Create container instance with managed identity
az container create \
  --resource-group fabric-mcp-rg \
  --name fabric-lakehouse-mcp \
  --image your-registry/fabric-lakehouse-mcp:latest \
  --assign-identity \
  --environment-variables \
    FABRIC_WORKSPACE_ID=your-workspace-id \
    FABRIC_LAKEHOUSE_ID=your-lakehouse-id \
    FABRIC_TENANT_ID=your-tenant-id \
    FABRIC_AUTH_METHOD=managed_identity \
    LOG_LEVEL=INFO \
    STRUCTURED_LOGGING=true \
  --cpu 1 \
  --memory 2 \
  --restart-policy Always
```

### 4. Azure App Service

Deploy as a web app:

```bash
# Create App Service plan
az appservice plan create \
  --name fabric-mcp-plan \
  --resource-group fabric-mcp-rg \
  --sku B1 \
  --is-linux

# Create web app
az webapp create \
  --resource-group fabric-mcp-rg \
  --plan fabric-mcp-plan \
  --name fabric-lakehouse-mcp \
  --deployment-container-image-name your-registry/fabric-lakehouse-mcp:latest

# Configure app settings
az webapp config appsettings set \
  --resource-group fabric-mcp-rg \
  --name fabric-lakehouse-mcp \
  --settings \
    FABRIC_WORKSPACE_ID=your-workspace-id \
    FABRIC_LAKEHOUSE_ID=your-lakehouse-id \
    FABRIC_TENANT_ID=your-tenant-id \
    FABRIC_AUTH_METHOD=managed_identity \
    LOG_LEVEL=INFO \
    STRUCTURED_LOGGING=true

# Enable managed identity
az webapp identity assign \
  --resource-group fabric-mcp-rg \
  --name fabric-lakehouse-mcp
```

### 5. Kubernetes Deployment

#### Deployment YAML

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fabric-lakehouse-mcp
  labels:
    app: fabric-lakehouse-mcp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: fabric-lakehouse-mcp
  template:
    metadata:
      labels:
        app: fabric-lakehouse-mcp
    spec:
      containers:
      - name: fabric-lakehouse-mcp
        image: your-registry/fabric-lakehouse-mcp:latest
        ports:
        - containerPort: 8080
        env:
        - name: FABRIC_WORKSPACE_ID
          valueFrom:
            secretKeyRef:
              name: fabric-secrets
              key: workspace-id
        - name: FABRIC_LAKEHOUSE_ID
          valueFrom:
            secretKeyRef:
              name: fabric-secrets
              key: lakehouse-id
        - name: FABRIC_TENANT_ID
          valueFrom:
            secretKeyRef:
              name: fabric-secrets
              key: tenant-id
        - name: FABRIC_AUTH_METHOD
          value: "service_principal"
        - name: FABRIC_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: fabric-secrets
              key: client-id
        - name: FABRIC_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: fabric-secrets
              key: client-secret
        - name: LOG_LEVEL
          value: "INFO"
        - name: STRUCTURED_LOGGING
          value: "true"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          exec:
            command:
            - fabric-lakehouse-mcp-server
            - --health-check
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - fabric-lakehouse-mcp-server
            - --health-check
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Secret
metadata:
  name: fabric-secrets
type: Opaque
data:
  workspace-id: <base64-encoded-workspace-id>
  lakehouse-id: <base64-encoded-lakehouse-id>
  tenant-id: <base64-encoded-tenant-id>
  client-id: <base64-encoded-client-id>
  client-secret: <base64-encoded-client-secret>
```

## Environment-Specific Configurations

### Development Environment

```bash
# Use interactive authentication for development
export FABRIC_AUTH_METHOD=interactive
export LOG_LEVEL=DEBUG
export STRUCTURED_LOGGING=true
export MAX_RESULT_ROWS=1000
export MAX_QUERY_TIMEOUT=60

fabric-lakehouse-mcp-server
```

### Staging Environment

```bash
# Use service principal with staging credentials
export FABRIC_AUTH_METHOD=service_principal
export FABRIC_CLIENT_ID=staging-client-id
export FABRIC_CLIENT_SECRET=staging-client-secret
export LOG_LEVEL=INFO
export STRUCTURED_LOGGING=true
export MAX_RESULT_ROWS=10000
export MAX_QUERY_TIMEOUT=300

fabric-lakehouse-mcp-server
```

### Production Environment

```bash
# Use managed identity in production
export FABRIC_AUTH_METHOD=managed_identity
export LOG_LEVEL=INFO
export LOG_FILE=/var/log/fabric-lakehouse-mcp/server.log
export STRUCTURED_LOGGING=true
export MAX_RESULT_ROWS=50000
export MAX_QUERY_TIMEOUT=600
export RETRY_ATTEMPTS=5

fabric-lakehouse-mcp-server
```

## Monitoring and Observability

### Health Checks

The server provides built-in health check endpoints:

```bash
# Basic health check
fabric-lakehouse-mcp-server --health-check

# Detailed status
fabric-lakehouse-mcp-server --status
```

### Logging

#### Structured Logging

Enable structured logging for better log analysis:

```bash
export STRUCTURED_LOGGING=true
export LOG_LEVEL=INFO
```

Example structured log output:

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "level": "INFO",
  "logger": "fabric_lakehouse_mcp.server",
  "operation": "server_startup_initiated",
  "workspace_id": "12345678...",
  "auth_method": "managed_identity",
  "log_level": "INFO"
}
```

#### Log Aggregation

For production deployments, consider using log aggregation:

- **Azure Monitor**: For Azure deployments
- **ELK Stack**: Elasticsearch, Logstash, Kibana
- **Fluentd**: For Kubernetes deployments
- **Splunk**: Enterprise log management

### Metrics and Monitoring

#### Custom Metrics

The server exposes metrics through health checks:

- Server uptime
- Component health status
- Query execution times
- Error rates
- Authentication status

#### Integration with Monitoring Systems

##### Prometheus

Create a metrics endpoint wrapper:

```python
from prometheus_client import Counter, Histogram, Gauge
import time

# Define metrics
REQUEST_COUNT = Counter('mcp_requests_total', 'Total requests', ['tool', 'status'])
REQUEST_DURATION = Histogram('mcp_request_duration_seconds', 'Request duration', ['tool'])
HEALTH_STATUS = Gauge('mcp_health_status', 'Health status', ['component'])
```

##### Azure Monitor

Use Azure Monitor for Azure deployments:

```bash
# Install Azure Monitor extension
pip install azure-monitor-opentelemetry-exporter

# Configure in your application
export APPLICATIONINSIGHTS_CONNECTION_STRING="your-connection-string"
```

## Security Considerations

### Network Security

1. **Use HTTPS only**
   - All communication with Fabric uses HTTPS
   - Consider using reverse proxy with SSL termination

2. **Network isolation**
   - Deploy in private subnets
   - Use network security groups/firewalls
   - Consider private endpoints for Fabric

### Authentication Security

1. **Credential management**
   - Use Azure Key Vault for secrets
   - Rotate credentials regularly
   - Use managed identities when possible

2. **Access control**
   - Follow principle of least privilege
   - Use role-based access control (RBAC)
   - Monitor access patterns

### Container Security

1. **Base image security**
   - Use minimal base images
   - Regularly update base images
   - Scan for vulnerabilities

2. **Runtime security**
   - Run as non-root user
   - Use read-only file systems
   - Limit resource usage

## Scaling Considerations

### Horizontal Scaling

The server is stateless and can be horizontally scaled:

```yaml
# Kubernetes HPA example
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: fabric-lakehouse-mcp-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: fabric-lakehouse-mcp
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### Load Balancing

Use load balancers for multiple instances:

- **Azure Load Balancer**: For Azure deployments
- **Kubernetes Service**: For Kubernetes deployments
- **NGINX**: For custom deployments

### Performance Tuning

1. **Connection pooling**
   - Configure appropriate connection limits
   - Monitor connection usage

2. **Query optimization**
   - Set appropriate timeouts
   - Limit result set sizes
   - Monitor query performance

3. **Resource allocation**
   - Allocate sufficient CPU and memory
   - Monitor resource usage
   - Adjust limits based on workload

## Backup and Disaster Recovery

### Configuration Backup

1. **Version control**
   - Store configuration in version control
   - Use infrastructure as code

2. **Secret backup**
   - Backup secrets securely
   - Document recovery procedures

### Disaster Recovery

1. **Multi-region deployment**
   - Deploy in multiple regions
   - Use traffic routing for failover

2. **Recovery procedures**
   - Document recovery steps
   - Test recovery procedures regularly
   - Monitor recovery time objectives (RTO)

## Troubleshooting Deployment Issues

### Common Issues

1. **Authentication failures**
   - Verify credentials are correct
   - Check service principal permissions
   - Ensure managed identity is configured

2. **Network connectivity**
   - Test connectivity to Fabric endpoints
   - Check firewall rules
   - Verify DNS resolution

3. **Resource constraints**
   - Monitor CPU and memory usage
   - Check disk space
   - Verify network bandwidth

### Debugging Tools

1. **Health checks**
   ```bash
   fabric-lakehouse-mcp-server --health-check
   ```

2. **Configuration validation**
   ```bash
   fabric-lakehouse-mcp-server --validate-config
   ```

3. **Debug logging**
   ```bash
   fabric-lakehouse-mcp-server --log-level DEBUG
   ```

4. **Status information**
   ```bash
   fabric-lakehouse-mcp-server --status
   ```