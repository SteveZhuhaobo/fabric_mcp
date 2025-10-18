"""Main MCP server implementation."""

import asyncio
import signal
import sys
import time
from typing import Any, Dict, Optional

from mcp.server.stdio import stdio_server

from .auth.manager import AuthenticationManager
from .client.fabric_client import FabricLakehouseClient
from .models.data_models import QueryExecutionConfig
from .config.settings import ServerConfig
from .tools.mcp_tools import app, initialize_client
from .errors import (
    setup_logging,
    get_logger,
    log_error,
    log_operation,
    OperationLogger,
    ErrorHandler,
    ErrorContext
)


logger = get_logger(__name__)


class FabricLakehouseMCPServer:
    """Main MCP server for Fabric Lakehouse integration."""
    
    def __init__(self):
        """Initialize the MCP server."""
        self.config: Optional[ServerConfig] = None
        self.auth_manager: Optional[AuthenticationManager] = None
        self.fabric_client: Optional[FabricLakehouseClient] = None
        self._shutdown_event = asyncio.Event()
        self._running = False
        self._start_time = time.time()
        log_operation(logger, "server_initialization_started")
    
    async def initialize(self) -> None:
        """Initialize server components."""
        with OperationLogger(logger, "server_initialization"):
            try:
                # Load configuration
                log_operation(logger, "loading_configuration")
                self.config = ServerConfig.from_env()
                self.config.validate()
                
                # Setup logging with configuration
                setup_logging(
                    level=self.config.log_level,
                    log_file=self.config.log_file,
                    structured=self.config.structured_logging
                )
                
                log_operation(logger, "configuration_loaded", log_level=self.config.log_level)
                
                # Initialize authentication
                log_operation(logger, "initializing_authentication", auth_method=self.config.auth_method)
                self.auth_manager = AuthenticationManager()
                
                # Prepare credentials dictionary
                credentials_dict = {}
                if self.config.tenant_id:
                    credentials_dict["tenant_id"] = self.config.tenant_id
                if self.config.client_id:
                    credentials_dict["client_id"] = self.config.client_id
                if self.config.client_secret:
                    credentials_dict["client_secret"] = self.config.client_secret
                
                credentials = self.auth_manager.authenticate(
                    method=self.config.auth_method,
                    credentials=credentials_dict
                )
                
                # Create query execution configuration
                query_config = QueryExecutionConfig(
                    timeout_seconds=self.config.max_query_timeout,
                    max_result_rows=self.config.max_result_rows,
                    page_size=self.config.default_page_size,
                    enable_pagination=self.config.enable_pagination,
                    format_results=True,
                    include_metadata=self.config.include_result_metadata
                )
                
                # Initialize Fabric client
                log_operation(logger, "initializing_fabric_client")
                self.fabric_client = FabricLakehouseClient(
                    workspace_id=self.config.workspace_id,
                    lakehouse_id=self.config.lakehouse_id,
                    credentials=credentials,
                    max_retries=self.config.retry_attempts,
                    retry_delay=self.config.retry_backoff_factor,
                    query_config=query_config
                )
                
                # Test connection
                log_operation(logger, "testing_fabric_connection")
                await asyncio.get_event_loop().run_in_executor(
                    None, self.fabric_client.test_connection
                )
                
                # Initialize MCP tools with the client and config
                log_operation(logger, "initializing_mcp_tools")
                initialize_client(self.fabric_client, self.config)
                
                # Configure FastMCP server capabilities
                self._configure_server_capabilities()
                
                log_operation(logger, "server_initialization_completed")
                
            except Exception as e:
                context = ErrorContext(operation="server_initialization")
                fabric_error = ErrorHandler.handle_fabric_error(e, operation="server_initialization", context=context)
                log_error(logger, fabric_error, operation="server_initialization")
                raise fabric_error
    
    def _configure_server_capabilities(self) -> None:
        """Configure MCP server capabilities and metadata."""
        log_operation(logger, "configuring_server_capabilities")
        
        # Server is already configured through FastMCP decorators in mcp_tools.py
        # The app instance contains all registered tools and their schemas
        
        # Log registered tools for debugging
        tool_names = []
        if hasattr(app, '_tools'):
            tool_names = list(app._tools.keys())
        
        log_operation(
            logger, 
            "server_capabilities_configured",
            registered_tools=tool_names,
            tool_count=len(tool_names)
        )
    
    async def start(self) -> None:
        """Start the MCP server."""
        with OperationLogger(logger, "server_startup"):
            try:
                # Initialize components
                await self.initialize()
                
                # Set up signal handlers for graceful shutdown
                self._setup_signal_handlers()
                
                # Mark server as running
                self._running = True
                
                # Start the FastMCP server using stdio transport
                log_operation(logger, "starting_mcp_server")
                async with stdio_server() as (read_stream, write_stream):
                    # Create server task
                    server_task = asyncio.create_task(
                        app.run(
                            read_stream,
                            write_stream,
                            app.create_initialization_options()
                        )
                    )
                    
                    # Create shutdown monitoring task
                    shutdown_task = asyncio.create_task(self._shutdown_event.wait())
                    
                    try:
                        # Wait for either server completion or shutdown signal
                        done, pending = await asyncio.wait(
                            [server_task, shutdown_task],
                            return_when=asyncio.FIRST_COMPLETED
                        )
                        
                        # Cancel pending tasks
                        for task in pending:
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass
                        
                        # Check if server task completed with an exception
                        if server_task in done:
                            await server_task  # This will raise any exception
                            
                    except asyncio.CancelledError:
                        log_operation(logger, "server_cancelled")
                        raise
                    finally:
                        self._running = False
                        
            except Exception as e:
                self._running = False
                context = ErrorContext(operation="server_startup")
                fabric_error = ErrorHandler.handle_fabric_error(e, operation="server_startup", context=context)
                log_error(logger, fabric_error, operation="server_startup")
                raise fabric_error
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        if sys.platform != "win32":
            # Unix-like systems
            loop = asyncio.get_event_loop()
            
            def signal_handler(signum, frame):
                log_operation(logger, "shutdown_signal_received", signal=signum)
                if self._running:
                    loop.create_task(self._initiate_shutdown())
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        else:
            # Windows - limited signal support
            def signal_handler(signum, frame):
                log_operation(logger, "shutdown_signal_received", signal=signum)
                if self._running:
                    asyncio.create_task(self._initiate_shutdown())
            
            signal.signal(signal.SIGINT, signal_handler)
    
    async def _initiate_shutdown(self) -> None:
        """Initiate graceful shutdown."""
        log_operation(logger, "initiating_graceful_shutdown")
        self._shutdown_event.set()
    
    async def stop(self) -> None:
        """Stop the MCP server."""
        with OperationLogger(logger, "server_shutdown"):
            try:
                # Signal shutdown if not already initiated
                if not self._shutdown_event.is_set():
                    self._shutdown_event.set()
                
                # Clean up resources
                if self.fabric_client:
                    log_operation(logger, "cleaning_up_fabric_client")
                    # Close any open connections or cleanup resources
                    # The FabricLakehouseClient doesn't have explicit cleanup methods
                    # but we can clear the reference
                    self.fabric_client = None
                
                if self.auth_manager:
                    log_operation(logger, "cleaning_up_auth_manager")
                    self.auth_manager.clear_authentication()
                    self.auth_manager = None
                
                # Clear configuration
                self.config = None
                self._running = False
                
                log_operation(logger, "server_shutdown_completed")
                
            except Exception as e:
                context = ErrorContext(operation="server_shutdown")
                fabric_error = ErrorHandler.handle_fabric_error(e, operation="server_shutdown", context=context)
                log_error(logger, fabric_error, operation="server_shutdown")
                # Don't re-raise during shutdown
    
    @property
    def is_running(self) -> bool:
        """Check if the server is currently running."""
        return self._running
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform a comprehensive health check of the server and its components."""
        import time
        from datetime import datetime
        
        with OperationLogger(logger, "health_check"):
            start_time = time.time()
            health_status = {
                "server_running": self._running,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "check_duration_ms": 0,
                "components": {},
                "metrics": {}
            }
            
            try:
                # Check configuration
                config_start = time.time()
                if self.config:
                    try:
                        self.config.validate()
                        health_status["components"]["configuration"] = {
                            "status": "healthy",
                            "workspace_id": self.config.workspace_id[:8] + "..." if self.config.workspace_id else None,
                            "lakehouse_id": self.config.lakehouse_id[:8] + "..." if self.config.lakehouse_id else None,
                            "auth_method": self.config.auth_method,
                            "write_operations_enabled": self.config.enable_write_operations,
                            "max_query_timeout": self.config.max_query_timeout,
                            "max_result_rows": self.config.max_result_rows
                        }
                    except Exception as e:
                        health_status["components"]["configuration"] = {
                            "status": "unhealthy",
                            "error": str(e)
                        }
                else:
                    health_status["components"]["configuration"] = {"status": "not_initialized"}
                
                config_duration = (time.time() - config_start) * 1000
                
                # Check authentication
                auth_start = time.time()
                if self.auth_manager:
                    try:
                        auth_healthy = self.auth_manager.is_authenticated()
                        health_status["components"]["authentication"] = {
                            "status": "healthy" if auth_healthy else "unhealthy",
                            "authenticated": auth_healthy,
                            "auth_method": self.config.auth_method if self.config else "unknown"
                        }
                        
                        # Try to refresh token to test auth health
                        if auth_healthy:
                            try:
                                refresh_result = self.auth_manager.refresh_token()
                                health_status["components"]["authentication"]["token_refresh_available"] = refresh_result
                            except Exception:
                                health_status["components"]["authentication"]["token_refresh_available"] = False
                                
                    except Exception as e:
                        health_status["components"]["authentication"] = {
                            "status": "unhealthy",
                            "error": str(e)
                        }
                else:
                    health_status["components"]["authentication"] = {"status": "not_initialized"}
                
                auth_duration = (time.time() - auth_start) * 1000
                
                # Check Fabric client
                fabric_start = time.time()
                if self.fabric_client:
                    try:
                        # Test connection in executor to avoid blocking
                        connection_result = await asyncio.get_event_loop().run_in_executor(
                            None, self.fabric_client.test_connection
                        )
                        
                        # Try to get a simple table list to test API access
                        try:
                            tables = await asyncio.get_event_loop().run_in_executor(
                                None, self.fabric_client.get_tables
                            )
                            table_count = len(tables) if tables else 0
                            
                            health_status["components"]["fabric_client"] = {
                                "status": "healthy",
                                "connection_test": connection_result,
                                "api_access": True,
                                "table_count": table_count
                            }
                        except Exception as api_error:
                            health_status["components"]["fabric_client"] = {
                                "status": "degraded",
                                "connection_test": connection_result,
                                "api_access": False,
                                "api_error": str(api_error)
                            }
                            
                    except Exception as e:
                        health_status["components"]["fabric_client"] = {
                            "status": "unhealthy",
                            "error": str(e)
                        }
                else:
                    health_status["components"]["fabric_client"] = {"status": "not_initialized"}
                
                fabric_duration = (time.time() - fabric_start) * 1000
                
                # Check MCP tools registration
                tools_start = time.time()
                try:
                    from .tools.mcp_tools import app
                    if hasattr(app, '_tools'):
                        tool_names = list(app._tools.keys())
                        health_status["components"]["mcp_tools"] = {
                            "status": "healthy",
                            "registered_tools": tool_names,
                            "tool_count": len(tool_names)
                        }
                    else:
                        health_status["components"]["mcp_tools"] = {
                            "status": "unhealthy",
                            "error": "No tools registered"
                        }
                except Exception as e:
                    health_status["components"]["mcp_tools"] = {
                        "status": "unhealthy",
                        "error": str(e)
                    }
                
                tools_duration = (time.time() - tools_start) * 1000
                
                # Calculate overall health
                component_statuses = [comp.get("status") for comp in health_status["components"].values()]
                if all(status == "healthy" for status in component_statuses):
                    health_status["overall_status"] = "healthy"
                elif any(status == "unhealthy" for status in component_statuses):
                    health_status["overall_status"] = "unhealthy"
                elif any(status == "degraded" for status in component_statuses):
                    health_status["overall_status"] = "degraded"
                else:
                    health_status["overall_status"] = "initializing"
                
                # Add performance metrics
                total_duration = (time.time() - start_time) * 1000
                health_status["check_duration_ms"] = round(total_duration, 2)
                health_status["metrics"] = {
                    "config_check_ms": round(config_duration, 2),
                    "auth_check_ms": round(auth_duration, 2),
                    "fabric_check_ms": round(fabric_duration, 2),
                    "tools_check_ms": round(tools_duration, 2)
                }
                
                log_operation(
                    logger, 
                    "health_check_completed", 
                    overall_status=health_status["overall_status"],
                    duration_ms=health_status["check_duration_ms"]
                )
                return health_status
                
            except Exception as e:
                context = ErrorContext(operation="health_check")
                fabric_error = ErrorHandler.handle_fabric_error(e, operation="health_check", context=context)
                log_error(logger, fabric_error, operation="health_check")
                
                total_duration = (time.time() - start_time) * 1000
                health_status["overall_status"] = "error"
                health_status["error"] = str(fabric_error)
                health_status["check_duration_ms"] = round(total_duration, 2)
                return health_status
    
    async def get_server_status(self) -> Dict[str, Any]:
        """Get comprehensive server status information."""
        import time
        import psutil
        import sys
        from datetime import datetime
        
        with OperationLogger(logger, "get_server_status"):
            try:
                status = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "server": {
                        "running": self._running,
                        "uptime_seconds": time.time() - getattr(self, '_start_time', time.time()),
                        "version": self._get_version()
                    },
                    "system": {
                        "python_version": sys.version.split()[0],
                        "platform": sys.platform,
                        "cpu_percent": psutil.cpu_percent(interval=1),
                        "memory_percent": psutil.virtual_memory().percent,
                        "disk_percent": psutil.disk_usage('/').percent if sys.platform != 'win32' else None
                    },
                    "configuration": {},
                    "health": await self.health_check()
                }
                
                # Add configuration summary (without sensitive data)
                if self.config:
                    status["configuration"] = {
                        "workspace_id": self.config.workspace_id[:8] + "..." if self.config.workspace_id else None,
                        "lakehouse_id": self.config.lakehouse_id[:8] + "..." if self.config.lakehouse_id else None,
                        "auth_method": self.config.auth_method,
                        "log_level": self.config.log_level,
                        "max_query_timeout": self.config.max_query_timeout,
                        "max_result_rows": self.config.max_result_rows,
                        "write_operations_enabled": self.config.enable_write_operations,
                        "structured_logging": self.config.structured_logging,
                        "retry_attempts": self.config.retry_attempts,
                        "retry_backoff_factor": self.config.retry_backoff_factor
                    }
                
                return status
                
            except Exception as e:
                context = ErrorContext(operation="get_server_status")
                fabric_error = ErrorHandler.handle_fabric_error(e, operation="get_server_status", context=context)
                log_error(logger, fabric_error, operation="get_server_status")
                
                return {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "error": str(fabric_error),
                    "server": {"running": self._running}
                }
    
    def _get_version(self) -> str:
        """Get the server version."""
        try:
            import importlib.metadata
            return importlib.metadata.version("fabric-lakehouse-mcp-server")
        except importlib.metadata.PackageNotFoundError:
            return "development"