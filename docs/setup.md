# Fabric Lakehouse MCP Server Setup Guide

This guide will help you set up and configure the Microsoft Fabric Lakehouse MCP Server.

## Prerequisites

- Python 3.8 or higher
- Microsoft Fabric workspace with a Lakehouse
- Azure Active Directory application (for service principal authentication) or appropriate permissions for managed identity/interactive authentication

## Installation

### From PyPI (Recommended)

```bash
pip install fabric-lakehouse-mcp-server
```

### From Source

```bash
git clone https://github.com/your-org/fabric-lakehouse-mcp-server.git
cd fabric-lakehouse-mcp-server
pip install -e .
```

## Configuration

### 1. Environment Variables

The server can be configured using environment variables. Copy the `.env.template` file to `.env` and fill in your values:

```bash
cp .env.template .env
```

### 2. Required Configuration

The following configuration values are required:

- `FABRIC_WORKSPACE_ID`: Your Microsoft Fabric workspace ID
- `FABRIC_LAKEHOUSE_ID`: Your Fabric Lakehouse ID  
- `FABRIC_TENANT_ID`: Your Azure tenant ID

### 3. Authentication Configuration

Choose one of the following authentication methods:

#### Service Principal (Recommended for Production)

```bash
FABRIC_AUTH_METHOD=service_principal
FABRIC_CLIENT_ID=your-client-id
FABRIC_CLIENT_SECRET=your-client-secret
```

#### Managed Identity (For Azure-hosted environments)

```bash
FABRIC_AUTH_METHOD=managed_identity
```

#### Interactive Authentication (For Development)

```bash
FABRIC_AUTH_METHOD=interactive
```

### 4. Optional Configuration

```bash
# Logging
LOG_LEVEL=INFO
LOG_FILE=/path/to/logfile.log
STRUCTURED_LOGGING=false

# Operation Limits
MAX_QUERY_TIMEOUT=300
MAX_RESULT_ROWS=10000
ENABLE_WRITE_OPERATIONS=true

# Retry Configuration
RETRY_ATTEMPTS=3
RETRY_BACKOFF_FACTOR=2.0
```

## Getting Required IDs

### Workspace ID

1. Go to your Microsoft Fabric workspace
2. The workspace ID is in the URL: `https://app.fabric.microsoft.com/groups/{workspace-id}/`

### Lakehouse ID

1. Navigate to your Lakehouse in the Fabric workspace
2. The lakehouse ID is in the URL: `https://app.fabric.microsoft.com/groups/{workspace-id}/lakehouses/{lakehouse-id}`

### Setting up Service Principal

1. Go to Azure Portal > Azure Active Directory > App registrations
2. Click "New registration"
3. Provide a name and register the application
4. Note the "Application (client) ID" and "Directory (tenant) ID"
5. Go to "Certificates & secrets" and create a new client secret
6. Grant the service principal appropriate permissions in your Fabric workspace

## Running the Server

### Basic Usage

```bash
fabric-lakehouse-mcp-server
```

### With Configuration File

```bash
fabric-lakehouse-mcp-server --config-file /path/to/config.env
```

### With CLI Arguments

```bash
fabric-lakehouse-mcp-server \
  --workspace-id "your-workspace-id" \
  --lakehouse-id "your-lakehouse-id" \
  --tenant-id "your-tenant-id" \
  --auth-method service_principal \
  --log-level DEBUG
```

## Validation and Testing

### Validate Configuration

```bash
fabric-lakehouse-mcp-server --validate-config
```

### Health Check

```bash
fabric-lakehouse-mcp-server --health-check
```

### Show Status

```bash
fabric-lakehouse-mcp-server --status
```

## Environment-Specific Configurations

### Development Environment

Use the provided development configuration:

```bash
fabric-lakehouse-mcp-server --config-file config/development.env
```

### Production Environment

Use the provided production configuration:

```bash
fabric-lakehouse-mcp-server --config-file config/production.env
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify your tenant ID, client ID, and client secret
   - Ensure the service principal has appropriate permissions
   - Check that the authentication method matches your setup

2. **Connection Errors**
   - Verify workspace ID and lakehouse ID are correct
   - Check network connectivity to Microsoft Fabric
   - Ensure your authentication credentials have access to the workspace

3. **Permission Errors**
   - Grant the service principal appropriate roles in the Fabric workspace
   - Ensure the user/service principal has access to the specific lakehouse

### Logging

Enable debug logging for troubleshooting:

```bash
fabric-lakehouse-mcp-server --log-level DEBUG
```

Or set structured logging for better log analysis:

```bash
fabric-lakehouse-mcp-server --structured-logging
```

### Health Checks

Use the health check command to verify all components are working:

```bash
fabric-lakehouse-mcp-server --health-check
```

This will test:
- Configuration validity
- Authentication status
- Fabric connectivity
- Component initialization

## Security Considerations

1. **Credential Management**
   - Never commit secrets to version control
   - Use environment variables or secure configuration management
   - Rotate credentials regularly

2. **Network Security**
   - Use HTTPS endpoints only
   - Consider network restrictions for production deployments

3. **Access Control**
   - Follow principle of least privilege
   - Grant only necessary permissions to service principals
   - Monitor access logs regularly

## Next Steps

Once the server is running, you can:

1. Connect MCP clients to interact with your Fabric Lakehouse
2. Use the available tools: `list_tables`, `describe_table`, `create_table`, `execute_query`
3. Monitor server logs for operations and errors
4. Set up monitoring and alerting for production deployments

For more information on using the MCP tools, see the [Usage Guide](usage.md).