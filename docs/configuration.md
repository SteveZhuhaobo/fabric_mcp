# Configuration Reference

This document provides a comprehensive reference for all configuration options available in the Fabric Lakehouse MCP Server.

## Configuration Methods

The server supports multiple configuration methods, in order of precedence:

1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration files (.env format)
4. Default values (lowest priority)

## Required Configuration

### Microsoft Fabric Settings

| Setting | Environment Variable | CLI Argument | Required | Description |
|---------|---------------------|--------------|----------|-------------|
| Workspace ID | `FABRIC_WORKSPACE_ID` | `--workspace-id` | Yes | Microsoft Fabric workspace ID |
| Lakehouse ID | `FABRIC_LAKEHOUSE_ID` | `--lakehouse-id` | Yes | Microsoft Fabric lakehouse ID |
| Tenant ID | `FABRIC_TENANT_ID` | `--tenant-id` | Yes | Azure Active Directory tenant ID |

### Authentication Settings

| Setting | Environment Variable | CLI Argument | Required | Description |
|---------|---------------------|--------------|----------|-------------|
| Auth Method | `FABRIC_AUTH_METHOD` | `--auth-method` | Yes | Authentication method: `service_principal`, `managed_identity`, or `interactive` |
| Client ID | `FABRIC_CLIENT_ID` | `--client-id` | Conditional* | Azure application client ID |
| Client Secret | `FABRIC_CLIENT_SECRET` | `--client-secret` | Conditional* | Azure application client secret |

*Required when using `service_principal` authentication method.

## Optional Configuration

### Logging Settings

| Setting | Environment Variable | CLI Argument | Default | Description |
|---------|---------------------|--------------|---------|-------------|
| Log Level | `LOG_LEVEL` | `--log-level` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| Log File | `LOG_FILE` | `--log-file` | None | Path to log file (logs to stdout if not specified) |
| Structured Logging | `STRUCTURED_LOGGING` | `--structured-logging` | `false` | Enable JSON structured logging |

### Operation Limits

| Setting | Environment Variable | CLI Argument | Default | Description |
|---------|---------------------|--------------|---------|-------------|
| Max Query Timeout | `MAX_QUERY_TIMEOUT` | `--max-query-timeout` | `300` | Maximum query execution time in seconds |
| Max Result Rows | `MAX_RESULT_ROWS` | `--max-result-rows` | `10000` | Maximum number of rows to return in query results |
| Enable Write Operations | `ENABLE_WRITE_OPERATIONS` | `--enable-write-operations` | `true` | Allow CREATE, INSERT, UPDATE, DELETE operations |

### Retry Configuration

| Setting | Environment Variable | CLI Argument | Default | Description |
|---------|---------------------|--------------|---------|-------------|
| Retry Attempts | `RETRY_ATTEMPTS` | `--retry-attempts` | `3` | Number of retry attempts for failed operations |
| Retry Backoff Factor | `RETRY_BACKOFF_FACTOR` | `--retry-backoff-factor` | `2.0` | Exponential backoff factor for retry delays |

## Configuration File Format

Configuration files use the `.env` format:

```bash
# Microsoft Fabric Configuration
FABRIC_WORKSPACE_ID=your-workspace-id
FABRIC_LAKEHOUSE_ID=your-lakehouse-id
FABRIC_TENANT_ID=your-tenant-id

# Authentication
FABRIC_AUTH_METHOD=service_principal
FABRIC_CLIENT_ID=your-client-id
FABRIC_CLIENT_SECRET=your-client-secret

# Logging
LOG_LEVEL=INFO
STRUCTURED_LOGGING=false

# Limits
MAX_QUERY_TIMEOUT=300
MAX_RESULT_ROWS=10000
ENABLE_WRITE_OPERATIONS=true

# Retry Configuration
RETRY_ATTEMPTS=3
RETRY_BACKOFF_FACTOR=2.0
```

## Environment-Specific Configurations

### Development Configuration

Recommended settings for development environments:

```bash
# Development settings
LOG_LEVEL=DEBUG
STRUCTURED_LOGGING=true
MAX_QUERY_TIMEOUT=60
MAX_RESULT_ROWS=1000
ENABLE_WRITE_OPERATIONS=true
RETRY_ATTEMPTS=2
RETRY_BACKOFF_FACTOR=1.5

# Use interactive auth for development
FABRIC_AUTH_METHOD=interactive
```

### Production Configuration

Recommended settings for production environments:

```bash
# Production settings
LOG_LEVEL=INFO
LOG_FILE=/var/log/fabric-lakehouse-mcp/server.log
STRUCTURED_LOGGING=true
MAX_QUERY_TIMEOUT=600
MAX_RESULT_ROWS=50000
ENABLE_WRITE_OPERATIONS=true
RETRY_ATTEMPTS=5
RETRY_BACKOFF_FACTOR=2.0

# Use managed identity in Azure environments
FABRIC_AUTH_METHOD=managed_identity
```

### Testing Configuration

Recommended settings for testing environments:

```bash
# Testing settings
LOG_LEVEL=DEBUG
STRUCTURED_LOGGING=true
MAX_QUERY_TIMEOUT=30
MAX_RESULT_ROWS=100
ENABLE_WRITE_OPERATIONS=false
RETRY_ATTEMPTS=1
RETRY_BACKOFF_FACTOR=1.0

# Use service principal with test credentials
FABRIC_AUTH_METHOD=service_principal
```

## Authentication Methods

### Service Principal

Best for production environments and automated deployments.

**Required Settings:**
- `FABRIC_AUTH_METHOD=service_principal`
- `FABRIC_CLIENT_ID=your-client-id`
- `FABRIC_CLIENT_SECRET=your-client-secret`
- `FABRIC_TENANT_ID=your-tenant-id`

**Setup:**
1. Create an Azure AD application
2. Generate a client secret
3. Grant appropriate permissions in Fabric workspace

### Managed Identity

Best for Azure-hosted environments (Azure VMs, Container Instances, etc.).

**Required Settings:**
- `FABRIC_AUTH_METHOD=managed_identity`
- `FABRIC_TENANT_ID=your-tenant-id`

**Setup:**
1. Enable managed identity on your Azure resource
2. Grant appropriate permissions in Fabric workspace

### Interactive Authentication

Best for development and testing.

**Required Settings:**
- `FABRIC_AUTH_METHOD=interactive`
- `FABRIC_TENANT_ID=your-tenant-id`

**Setup:**
1. Ensure you have appropriate permissions in Fabric workspace
2. Browser-based authentication will be prompted

## Validation

### Configuration Validation

Use the validation command to check your configuration:

```bash
fabric-lakehouse-mcp-server --validate-config
```

This will:
- Check all required settings are present
- Validate setting formats and values
- Display configuration summary (without sensitive data)

### Common Validation Errors

1. **Missing Required Settings**
   ```
   Configuration validation failed: workspace_id is required
   ```
   Solution: Set the `FABRIC_WORKSPACE_ID` environment variable or use `--workspace-id`

2. **Invalid Authentication Method**
   ```
   Configuration validation failed: auth_method must be one of: service_principal, managed_identity, interactive
   ```
   Solution: Use a valid authentication method

3. **Missing Authentication Credentials**
   ```
   Configuration validation failed: client_id and client_secret are required for service_principal authentication
   ```
   Solution: Set `FABRIC_CLIENT_ID` and `FABRIC_CLIENT_SECRET` for service principal auth

## Security Best Practices

### Credential Management

1. **Never commit secrets to version control**
   - Use `.env` files (add to `.gitignore`)
   - Use environment variables
   - Use secure configuration management systems

2. **Rotate credentials regularly**
   - Set up automated credential rotation
   - Monitor credential expiration dates

3. **Use least privilege principle**
   - Grant only necessary permissions
   - Use role-based access control

### Network Security

1. **Use secure connections**
   - All communication with Fabric uses HTTPS
   - Verify SSL certificates

2. **Network restrictions**
   - Consider firewall rules for production
   - Use private endpoints where available

### Monitoring

1. **Enable structured logging**
   - Set `STRUCTURED_LOGGING=true`
   - Use log aggregation systems

2. **Monitor authentication events**
   - Track authentication failures
   - Set up alerts for suspicious activity

3. **Audit data access**
   - Log all data operations
   - Monitor query patterns

## Troubleshooting Configuration

### Debug Configuration Loading

Enable debug logging to see configuration loading:

```bash
fabric-lakehouse-mcp-server --log-level DEBUG --validate-config
```

### Check Environment Variables

Verify environment variables are set correctly:

```bash
env | grep FABRIC_
```

### Test Configuration File Loading

Test loading a specific configuration file:

```bash
fabric-lakehouse-mcp-server --config-file /path/to/config.env --validate-config
```

### Common Issues

1. **Configuration file not found**
   - Verify file path is correct
   - Check file permissions

2. **Environment variables not loaded**
   - Verify variable names are correct
   - Check shell environment

3. **CLI arguments not working**
   - Verify argument syntax
   - Check for typos in argument names