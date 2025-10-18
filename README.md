# Fabric Lakehouse MCP Server

A Model Context Protocol (MCP) server that provides seamless integration with Microsoft Fabric Lakehouse, enabling AI assistants and other MCP clients to interact with Fabric Lakehouse data programmatically.

## Features

- **Data Structure Inspection**: List tables and retrieve detailed schema information
- **Table Creation**: Create new tables in the Lakehouse with proper validation
- **SQL Query Execution**: Execute SELECT, INSERT, UPDATE, and DELETE operations
- **Multiple Authentication Methods**: Support for service principal, managed identity, and interactive authentication
- **Comprehensive Error Handling**: Detailed error messages and retry logic
- **Configurable Limits**: Query timeouts, result size limits, and security controls

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd fabric-lakehouse-mcp-server
```

2. Create a Python virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the package and dependencies:
```bash
pip install -e .
```

For development, install with dev dependencies:
```bash
pip install -e ".[dev]"
```

## Configuration

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit `.env` with your Microsoft Fabric credentials and settings:
```bash
# Required settings
FABRIC_WORKSPACE_ID=your-workspace-id
FABRIC_LAKEHOUSE_ID=your-lakehouse-id
FABRIC_TENANT_ID=your-tenant-id

# For service principal authentication
FABRIC_CLIENT_ID=your-client-id
FABRIC_CLIENT_SECRET=your-client-secret
```

## Usage

Start the MCP server:
```bash
fabric-lakehouse-mcp
```

Or with custom configuration:
```bash
fabric-lakehouse-mcp --workspace-id <id> --lakehouse-id <id> --log-level DEBUG
```

## Authentication Methods

### Service Principal (Recommended for Production)
```bash
FABRIC_AUTH_METHOD=service_principal
FABRIC_CLIENT_ID=your-app-id
FABRIC_CLIENT_SECRET=your-app-secret
FABRIC_TENANT_ID=your-tenant-id
```

### Managed Identity (For Azure-hosted environments)
```bash
FABRIC_AUTH_METHOD=managed_identity
FABRIC_TENANT_ID=your-tenant-id
```

### Interactive Authentication (For Development)
```bash
FABRIC_AUTH_METHOD=interactive
FABRIC_TENANT_ID=your-tenant-id
```

## MCP Tools

The server exposes the following MCP tools:

- `list_tables`: Get all available tables in the Lakehouse
- `describe_table`: Get detailed schema information for a specific table
- `create_table`: Create new tables with specified schema
- `execute_query`: Execute SQL queries against the Lakehouse

## Development

Run tests:
```bash
pytest
```

Format code:
```bash
black fabric_lakehouse_mcp/
isort fabric_lakehouse_mcp/
```

Type checking:
```bash
mypy fabric_lakehouse_mcp/
```

## License

MIT License - see LICENSE file for details.