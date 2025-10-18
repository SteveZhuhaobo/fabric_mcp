"""Configuration settings for Fabric Lakehouse MCP server."""

import os
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv

from ..errors import ConfigurationError, ErrorContext, get_logger

# Load environment variables from .env file if it exists
load_dotenv()

logger = get_logger(__name__)


@dataclass
class ServerConfig:
    """Server configuration settings."""
    
    # Fabric connection settings
    workspace_id: str
    lakehouse_id: str
    tenant_id: str
    
    # Authentication settings
    auth_method: str = "service_principal"  # service_principal, managed_identity, interactive
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    
    # Server settings
    max_query_timeout: int = 300  # seconds
    max_result_rows: int = 10000
    enable_write_operations: bool = True
    
    # Query execution settings
    default_page_size: int = 1000
    enable_pagination: bool = True
    enable_query_cancellation: bool = True
    result_format: str = "structured"  # structured, table, csv, json
    include_result_metadata: bool = True
    
    # Security settings
    enable_sql_validation: bool = True
    enable_complexity_analysis: bool = True
    enable_rate_limiting: bool = True
    enable_audit_logging: bool = True
    sql_security_level: str = "moderate"  # strict, moderate, permissive
    max_complexity_score: int = 100
    max_concurrent_queries: int = 5
    requests_per_minute: int = 100
    queries_per_minute: int = 50
    
    # Logging settings
    log_level: str = "INFO"
    log_file: Optional[str] = None
    structured_logging: bool = True
    
    # API settings
    fabric_base_url: str = "https://api.fabric.microsoft.com"
    retry_attempts: int = 3
    retry_backoff_factor: float = 1.0
    
    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables."""
        
        # Required settings
        workspace_id = os.getenv("FABRIC_WORKSPACE_ID")
        lakehouse_id = os.getenv("FABRIC_LAKEHOUSE_ID")
        tenant_id = os.getenv("FABRIC_TENANT_ID")
        
        if not workspace_id:
            context = ErrorContext(operation="load_config", additional_data={"config_key": "FABRIC_WORKSPACE_ID"})
            raise ConfigurationError("FABRIC_WORKSPACE_ID environment variable is required", config_key="FABRIC_WORKSPACE_ID", context=context)
        if not lakehouse_id:
            context = ErrorContext(operation="load_config", additional_data={"config_key": "FABRIC_LAKEHOUSE_ID"})
            raise ConfigurationError("FABRIC_LAKEHOUSE_ID environment variable is required", config_key="FABRIC_LAKEHOUSE_ID", context=context)
        if not tenant_id:
            context = ErrorContext(operation="load_config", additional_data={"config_key": "FABRIC_TENANT_ID"})
            raise ConfigurationError("FABRIC_TENANT_ID environment variable is required", config_key="FABRIC_TENANT_ID", context=context)
        
        # Optional settings with defaults
        auth_method = os.getenv("FABRIC_AUTH_METHOD", "service_principal")
        client_id = os.getenv("FABRIC_CLIENT_ID")
        client_secret = os.getenv("FABRIC_CLIENT_SECRET")
        
        # Validate authentication settings
        if auth_method == "service_principal":
            if not client_id or not client_secret:
                context = ErrorContext(operation="load_config", additional_data={"auth_method": auth_method})
                raise ConfigurationError(
                    "FABRIC_CLIENT_ID and FABRIC_CLIENT_SECRET are required for service_principal authentication",
                    config_key="FABRIC_CLIENT_ID",
                    context=context
                )
        
        return cls(
            workspace_id=workspace_id,
            lakehouse_id=lakehouse_id,
            tenant_id=tenant_id,
            auth_method=auth_method,
            client_id=client_id,
            client_secret=client_secret,
            max_query_timeout=int(os.getenv("FABRIC_MAX_QUERY_TIMEOUT", "300")),
            max_result_rows=int(os.getenv("FABRIC_MAX_RESULT_ROWS", "10000")),
            enable_write_operations=os.getenv("FABRIC_ENABLE_WRITE_OPERATIONS", "true").lower() == "true",
            default_page_size=int(os.getenv("FABRIC_DEFAULT_PAGE_SIZE", "1000")),
            enable_pagination=os.getenv("FABRIC_ENABLE_PAGINATION", "true").lower() == "true",
            enable_query_cancellation=os.getenv("FABRIC_ENABLE_QUERY_CANCELLATION", "true").lower() == "true",
            result_format=os.getenv("FABRIC_RESULT_FORMAT", "structured"),
            include_result_metadata=os.getenv("FABRIC_INCLUDE_RESULT_METADATA", "true").lower() == "true",
            # Security settings
            enable_sql_validation=os.getenv("FABRIC_ENABLE_SQL_VALIDATION", "true").lower() == "true",
            enable_complexity_analysis=os.getenv("FABRIC_ENABLE_COMPLEXITY_ANALYSIS", "true").lower() == "true",
            enable_rate_limiting=os.getenv("FABRIC_ENABLE_RATE_LIMITING", "true").lower() == "true",
            enable_audit_logging=os.getenv("FABRIC_ENABLE_AUDIT_LOGGING", "true").lower() == "true",
            sql_security_level=os.getenv("FABRIC_SQL_SECURITY_LEVEL", "moderate"),
            max_complexity_score=int(os.getenv("FABRIC_MAX_COMPLEXITY_SCORE", "100")),
            max_concurrent_queries=int(os.getenv("FABRIC_MAX_CONCURRENT_QUERIES", "5")),
            requests_per_minute=int(os.getenv("FABRIC_REQUESTS_PER_MINUTE", "100")),
            queries_per_minute=int(os.getenv("FABRIC_QUERIES_PER_MINUTE", "50")),
            # Logging and API settings
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            log_file=os.getenv("LOG_FILE"),
            structured_logging=os.getenv("STRUCTURED_LOGGING", "true").lower() == "true",
            fabric_base_url=os.getenv("FABRIC_BASE_URL", "https://api.fabric.microsoft.com"),
            retry_attempts=int(os.getenv("FABRIC_RETRY_ATTEMPTS", "3")),
            retry_backoff_factor=float(os.getenv("FABRIC_RETRY_BACKOFF_FACTOR", "1.0")),
        )
    
    def validate(self) -> None:
        """Validate configuration settings."""
        if self.max_query_timeout <= 0:
            context = ErrorContext(operation="validate_config", additional_data={"config_key": "max_query_timeout"})
            raise ConfigurationError("max_query_timeout must be positive", config_key="max_query_timeout", context=context)
        
        if self.max_result_rows <= 0:
            context = ErrorContext(operation="validate_config", additional_data={"config_key": "max_result_rows"})
            raise ConfigurationError("max_result_rows must be positive", config_key="max_result_rows", context=context)
        
        if self.auth_method not in ["service_principal", "managed_identity", "interactive"]:
            context = ErrorContext(operation="validate_config", additional_data={"config_key": "auth_method", "value": self.auth_method})
            raise ConfigurationError(
                "auth_method must be one of: service_principal, managed_identity, interactive",
                config_key="auth_method",
                context=context
            )
        
        if self.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            context = ErrorContext(operation="validate_config", additional_data={"config_key": "log_level", "value": self.log_level})
            raise ConfigurationError(
                "log_level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL",
                config_key="log_level",
                context=context
            )
        
        if self.retry_attempts < 0:
            context = ErrorContext(operation="validate_config", additional_data={"config_key": "retry_attempts"})
            raise ConfigurationError("retry_attempts must be non-negative", config_key="retry_attempts", context=context)
        
        if self.retry_backoff_factor < 0:
            context = ErrorContext(operation="validate_config", additional_data={"config_key": "retry_backoff_factor"})
            raise ConfigurationError("retry_backoff_factor must be non-negative", config_key="retry_backoff_factor", context=context)