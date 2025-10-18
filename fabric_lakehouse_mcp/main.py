"""Main entry point for Fabric Lakehouse MCP server."""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import click

from fabric_lakehouse_mcp.config.settings import ServerConfig
from fabric_lakehouse_mcp.server import FabricLakehouseMCPServer
from fabric_lakehouse_mcp.errors import (
    setup_logging,
    get_logger,
    log_error,
    log_operation,
    ErrorHandler,
    ErrorContext
)


@click.command()
@click.option(
    "--workspace-id",
    envvar="FABRIC_WORKSPACE_ID",
    help="Microsoft Fabric workspace ID",
)
@click.option(
    "--lakehouse-id",
    envvar="FABRIC_LAKEHOUSE_ID",
    help="Microsoft Fabric lakehouse ID",
)
@click.option(
    "--tenant-id",
    envvar="FABRIC_TENANT_ID",
    help="Azure tenant ID",
)
@click.option(
    "--client-id",
    envvar="FABRIC_CLIENT_ID",
    help="Azure client ID (for service principal auth)",
)
@click.option(
    "--client-secret",
    envvar="FABRIC_CLIENT_SECRET",
    help="Azure client secret (for service principal auth)",
)
@click.option(
    "--auth-method",
    envvar="FABRIC_AUTH_METHOD",
    default="service_principal",
    type=click.Choice(["service_principal", "managed_identity", "interactive"]),
    help="Authentication method to use",
)
@click.option(
    "--log-level",
    envvar="LOG_LEVEL",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Logging level",
)
@click.option(
    "--log-file",
    envvar="LOG_FILE",
    type=click.Path(),
    help="Path to log file (optional)",
)
@click.option(
    "--config-file",
    type=click.Path(exists=True),
    help="Path to configuration file (.env format)",
)
@click.option(
    "--health-check",
    is_flag=True,
    help="Perform a health check and exit",
)
@click.option(
    "--validate-config",
    is_flag=True,
    help="Validate configuration and exit",
)
@click.option(
    "--max-query-timeout",
    envvar="MAX_QUERY_TIMEOUT",
    type=int,
    help="Maximum query timeout in seconds",
)
@click.option(
    "--max-result-rows",
    envvar="MAX_RESULT_ROWS",
    type=int,
    help="Maximum number of rows to return in query results",
)
@click.option(
    "--enable-write-operations/--disable-write-operations",
    envvar="ENABLE_WRITE_OPERATIONS",
    default=True,
    help="Enable or disable write operations (CREATE, INSERT, UPDATE, DELETE)",
)
@click.option(
    "--structured-logging/--no-structured-logging",
    envvar="STRUCTURED_LOGGING",
    default=False,
    help="Enable structured JSON logging",
)
@click.option(
    "--retry-attempts",
    envvar="RETRY_ATTEMPTS",
    type=int,
    help="Number of retry attempts for failed operations",
)
@click.option(
    "--retry-backoff-factor",
    envvar="RETRY_BACKOFF_FACTOR",
    type=float,
    help="Backoff factor for retry delays",
)
@click.option(
    "--status",
    is_flag=True,
    help="Show server status and configuration",
)
@click.option(
    "--version",
    is_flag=True,
    help="Show version information and exit",
)
def main(
    workspace_id: Optional[str],
    lakehouse_id: Optional[str],
    tenant_id: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    auth_method: str,
    log_level: str,
    log_file: Optional[str],
    config_file: Optional[str],
    health_check: bool,
    validate_config: bool,
    max_query_timeout: Optional[int],
    max_result_rows: Optional[int],
    enable_write_operations: bool,
    structured_logging: bool,
    retry_attempts: Optional[int],
    retry_backoff_factor: Optional[float],
    status: bool,
    version: bool,
) -> None:
    """Start the Fabric Lakehouse MCP server."""
    
    try:
        # Handle version request
        if version:
            _show_version()
            return
        
        # Load configuration from file if specified
        if config_file:
            _load_config_file(config_file)
        
        # Load configuration from environment
        config = _load_configuration(
            workspace_id, lakehouse_id, tenant_id, client_id, client_secret,
            auth_method, log_level, log_file, max_query_timeout, max_result_rows,
            enable_write_operations, structured_logging, retry_attempts, retry_backoff_factor
        )
        
        # Handle special modes
        if validate_config:
            _validate_configuration_mode(config)
            return
        
        if status:
            _show_status_mode(config)
            return
        
        if health_check:
            asyncio.run(_health_check_mode(config))
            return
        
        # Set up logging
        setup_logging(
            level=config.log_level,
            log_file=config.log_file,
            structured=config.structured_logging
        )
        
        logger = get_logger(__name__)
        
        log_operation(
            logger,
            "server_startup_initiated",
            workspace_id=config.workspace_id[:8] + "..." if config.workspace_id else None,
            lakehouse_id=config.lakehouse_id[:8] + "..." if config.lakehouse_id else None,
            auth_method=config.auth_method,
            log_level=config.log_level,
        )
        
        # Create and start server
        server = FabricLakehouseMCPServer()
        asyncio.run(_run_server(server, logger))
        
    except Exception as e:
        # Set up basic logging if it hasn't been set up yet
        try:
            logger = get_logger(__name__)
        except:
            setup_logging(level="ERROR")
            logger = get_logger(__name__)
        
        context = ErrorContext(operation="main_startup")
        fabric_error = ErrorHandler.handle_fabric_error(e, operation="main_startup", context=context)
        log_error(logger, fabric_error, operation="main_startup")
        
        click.echo(f"Error starting server: {fabric_error.get_user_message()}", err=True)
        click.echo(f"Technical details: {fabric_error.get_technical_details()}", err=True)
        sys.exit(1)


def _load_config_file(config_file: str) -> None:
    """Load configuration from a file."""
    try:
        from dotenv import load_dotenv
        config_path = Path(config_file)
        if not config_path.exists():
            raise click.ClickException(f"Configuration file not found: {config_file}")
        
        load_dotenv(config_path)
        click.echo(f"Loaded configuration from: {config_file}")
        
    except ImportError:
        raise click.ClickException(
            "python-dotenv is required to load configuration files. "
            "Install it with: pip install python-dotenv"
        )


def _load_configuration(
    workspace_id: Optional[str],
    lakehouse_id: Optional[str],
    tenant_id: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    auth_method: str,
    log_level: str,
    log_file: Optional[str],
    max_query_timeout: Optional[int],
    max_result_rows: Optional[int],
    enable_write_operations: bool,
    structured_logging: bool,
    retry_attempts: Optional[int],
    retry_backoff_factor: Optional[float],
) -> ServerConfig:
    """Load and validate configuration."""
    # Load base configuration from environment
    config = ServerConfig.from_env()
    
    # Override with CLI arguments if provided
    if workspace_id:
        config.workspace_id = workspace_id
    if lakehouse_id:
        config.lakehouse_id = lakehouse_id
    if tenant_id:
        config.tenant_id = tenant_id
    if client_id:
        config.client_id = client_id
    if client_secret:
        config.client_secret = client_secret
    if auth_method:
        config.auth_method = auth_method
    if log_level:
        config.log_level = log_level
    if log_file:
        config.log_file = log_file
    if max_query_timeout is not None:
        config.max_query_timeout = max_query_timeout
    if max_result_rows is not None:
        config.max_result_rows = max_result_rows
    config.enable_write_operations = enable_write_operations
    config.structured_logging = structured_logging
    if retry_attempts is not None:
        config.retry_attempts = retry_attempts
    if retry_backoff_factor is not None:
        config.retry_backoff_factor = retry_backoff_factor
    
    # Validate configuration
    config.validate()
    
    return config


def _validate_configuration_mode(config: ServerConfig) -> None:
    """Validate configuration and exit."""
    try:
        config.validate()
        click.echo("✓ Configuration is valid")
        
        # Show configuration summary (without sensitive data)
        click.echo("\nConfiguration Summary:")
        click.echo(f"  Workspace ID: {config.workspace_id[:8]}...")
        click.echo(f"  Lakehouse ID: {config.lakehouse_id[:8]}...")
        click.echo(f"  Tenant ID: {config.tenant_id[:8]}...")
        click.echo(f"  Auth Method: {config.auth_method}")
        click.echo(f"  Log Level: {config.log_level}")
        if config.log_file:
            click.echo(f"  Log File: {config.log_file}")
        click.echo(f"  Max Query Timeout: {config.max_query_timeout}s")
        click.echo(f"  Max Result Rows: {config.max_result_rows}")
        click.echo(f"  Write Operations: {'Enabled' if config.enable_write_operations else 'Disabled'}")
        
    except Exception as e:
        click.echo(f"✗ Configuration validation failed: {e}", err=True)
        sys.exit(1)


async def _run_server(server: FabricLakehouseMCPServer, logger) -> None:
    """Run the server with proper lifecycle management."""
    try:
        await server.start()
    except KeyboardInterrupt:
        log_operation(logger, "keyboard_interrupt_received")
        click.echo("\nShutting down server...")
    except Exception:
        raise
    finally:
        await server.stop()
        log_operation(logger, "server_stopped")


async def _health_check_mode(config: ServerConfig) -> None:
    """Perform health check and exit."""
    try:
        click.echo("Performing health check...")
        
        # Create server instance
        server = FabricLakehouseMCPServer()
        
        try:
            # Initialize server components
            await server.initialize()
            
            # Perform health check
            health_status = await server.health_check()
            
            # Display results
            overall_status = health_status.get("overall_status", "unknown")
            if overall_status == "healthy":
                click.echo("✓ Server health check passed")
                click.echo(f"  Overall Status: {overall_status}")
                
                for component, status in health_status.get("components", {}).items():
                    component_status = status.get("status", "unknown")
                    if component_status == "healthy":
                        click.echo(f"  {component.title()}: ✓ {component_status}")
                    else:
                        click.echo(f"  {component.title()}: ✗ {component_status}")
                        if "error" in status:
                            click.echo(f"    Error: {status['error']}")
                
            else:
                click.echo(f"✗ Server health check failed: {overall_status}", err=True)
                
                for component, status in health_status.get("components", {}).items():
                    component_status = status.get("status", "unknown")
                    click.echo(f"  {component.title()}: {component_status}")
                    if "error" in status:
                        click.echo(f"    Error: {status['error']}")
                
                sys.exit(1)
                
        finally:
            await server.stop()
            
    except Exception as e:
        click.echo(f"✗ Health check failed: {e}", err=True)
        sys.exit(1)


def _show_version() -> None:
    """Show version information and exit."""
    try:
        import importlib.metadata
        version = importlib.metadata.version("fabric-lakehouse-mcp-server")
    except importlib.metadata.PackageNotFoundError:
        version = "development"
    
    click.echo(f"Fabric Lakehouse MCP Server v{version}")
    click.echo("Microsoft Fabric Lakehouse integration for Model Context Protocol")
    click.echo("https://github.com/your-org/fabric-lakehouse-mcp-server")


def _show_status_mode(config: ServerConfig) -> None:
    """Show server status and configuration."""
    click.echo("Fabric Lakehouse MCP Server Status")
    click.echo("=" * 40)
    
    # Configuration status
    click.echo("\nConfiguration:")
    click.echo(f"  Workspace ID: {config.workspace_id[:8]}..." if config.workspace_id else "  Workspace ID: Not set")
    click.echo(f"  Lakehouse ID: {config.lakehouse_id[:8]}..." if config.lakehouse_id else "  Lakehouse ID: Not set")
    click.echo(f"  Tenant ID: {config.tenant_id[:8]}..." if config.tenant_id else "  Tenant ID: Not set")
    click.echo(f"  Auth Method: {config.auth_method}")
    click.echo(f"  Log Level: {config.log_level}")
    if config.log_file:
        click.echo(f"  Log File: {config.log_file}")
    click.echo(f"  Structured Logging: {'Enabled' if config.structured_logging else 'Disabled'}")
    
    # Operation limits
    click.echo("\nOperation Limits:")
    click.echo(f"  Max Query Timeout: {config.max_query_timeout}s")
    click.echo(f"  Max Result Rows: {config.max_result_rows}")
    click.echo(f"  Write Operations: {'Enabled' if config.enable_write_operations else 'Disabled'}")
    
    # Retry configuration
    click.echo("\nRetry Configuration:")
    click.echo(f"  Retry Attempts: {config.retry_attempts}")
    click.echo(f"  Backoff Factor: {config.retry_backoff_factor}")
    
    # Environment information
    click.echo("\nEnvironment:")
    click.echo(f"  Python Version: {sys.version.split()[0]}")
    click.echo(f"  Platform: {sys.platform}")
    
    # Configuration validation
    click.echo("\nValidation:")
    try:
        config.validate()
        click.echo("  ✓ Configuration is valid")
    except Exception as e:
        click.echo(f"  ✗ Configuration error: {e}")


if __name__ == "__main__":
    main()