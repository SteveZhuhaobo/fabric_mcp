"""MCP tools for Fabric Lakehouse operations."""

from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from ..auth.manager import AuthenticationManager
from ..client.fabric_client import FabricLakehouseClient
from ..config.settings import ServerConfig
from ..models.data_models import (
    TableDefinition,
    ColumnDefinition,
    validate_table_definition,
    validate_sql_query,
    QueryExecutionConfig,
)
from ..models.query_formatter import QueryResultFormatter
from ..errors import (
    ValidationError,
    ErrorHandler,
    ErrorContext,
    get_logger,
    log_error,
    log_operation,
    OperationLogger,
    handle_fabric_error
)
from ..security import (
    SQLValidator,
    SQLSecurityError,
    QueryComplexityAnalyzer,
    QueryComplexityError,
    AuditLogger,
    AuditEventStatus,
    RateLimiter,
    RateLimitExceeded,
    ConcurrentQuerySlot,
    SecurityLevel,
    create_sql_validator,
    create_complexity_analyzer,
    get_audit_logger,
    get_rate_limiter
)


logger = get_logger(__name__)

# Global client instance (will be initialized by server)
_fabric_client: Optional[FabricLakehouseClient] = None

# Security components
_sql_validator: Optional[SQLValidator] = None
_complexity_analyzer: Optional[QueryComplexityAnalyzer] = None
_audit_logger: Optional[AuditLogger] = None
_rate_limiter: Optional[RateLimiter] = None


def initialize_client(client: FabricLakehouseClient, config: Optional[ServerConfig] = None) -> None:
    """Initialize the global Fabric client instance and security components."""
    global _fabric_client, _sql_validator, _complexity_analyzer, _audit_logger, _rate_limiter
    
    _fabric_client = client
    
    # Initialize security components based on configuration
    if config and config.enable_sql_validation:
        security_level = SecurityLevel.STRICT if config.sql_security_level == "strict" else \
                        SecurityLevel.PERMISSIVE if config.sql_security_level == "permissive" else \
                        SecurityLevel.MODERATE
        _sql_validator = create_sql_validator(security_level)
    else:
        _sql_validator = create_sql_validator(SecurityLevel.MODERATE)
    
    if config and config.enable_complexity_analysis:
        _complexity_analyzer = create_complexity_analyzer(
            max_complexity_score=config.max_complexity_score,
            max_joins=10,
            max_subqueries=5
        )
    else:
        _complexity_analyzer = create_complexity_analyzer()
    
    if config and config.enable_audit_logging:
        _audit_logger = get_audit_logger(config)
    else:
        _audit_logger = get_audit_logger()
    
    if config and config.enable_rate_limiting:
        from ..security.rate_limiter import RateLimitConfig
        rate_config = RateLimitConfig(
            requests_per_minute=config.requests_per_minute,
            queries_per_minute=config.queries_per_minute,
            max_concurrent_queries=config.max_concurrent_queries
        )
        from ..security.rate_limiter import initialize_rate_limiter
        _rate_limiter = initialize_rate_limiter(rate_config)
    else:
        _rate_limiter = get_rate_limiter()
    
    log_operation(logger, "mcp_tools_initialized")
    
    # Log initialization in audit log
    _audit_logger.log_data_access(
        operation="mcp_tools_initialized",
        status=AuditEventStatus.SUCCESS,
        additional_data={"security_enabled": True}
    )


def get_client() -> FabricLakehouseClient:
    """Get the initialized Fabric client."""
    if _fabric_client is None:
        raise RuntimeError("Fabric client not initialized. Call initialize_client() first.")
    return _fabric_client


def get_security_components() -> tuple:
    """Get initialized security components."""
    if _sql_validator is None or _complexity_analyzer is None or _audit_logger is None or _rate_limiter is None:
        raise RuntimeError("Security components not initialized. Call initialize_client() first.")
    return _sql_validator, _complexity_analyzer, _audit_logger, _rate_limiter


def _get_user_id() -> str:
    """Get user ID for rate limiting and auditing (simplified implementation)."""
    # In a real implementation, this would extract user ID from authentication context
    # For now, return a default user ID
    return "default_user"


# Create FastMCP app
app = FastMCP("Fabric Lakehouse MCP Server")


@app.tool()
def list_tables() -> List[Dict[str, Any]]:
    """
    List all tables available in the Microsoft Fabric Lakehouse.
    
    Returns a list of tables with their basic information including name, 
    schema, type, and description.
    
    Returns:
        List of dictionaries containing table information
    """
    # Get security components
    sql_validator, complexity_analyzer, audit_logger, rate_limiter = get_security_components()
    user_id = _get_user_id()
    
    with OperationLogger(logger, "list_tables_tool"):
        try:
            # Rate limiting
            rate_limiter.check_request_limit(user_id, "list_tables")
            
            client = get_client()
            tables = client.get_tables()
            
            # Convert to dictionary format for MCP response
            result = []
            for table in tables:
                table_dict = {
                    "name": table.name,
                    "schema_name": table.schema_name,
                    "table_type": table.table_type.value,
                    "description": table.description,
                }
                
                # Add optional fields if available
                if table.created_date:
                    table_dict["created_date"] = table.created_date.isoformat()
                if table.row_count is not None:
                    table_dict["row_count"] = table.row_count
                    
                result.append(table_dict)
            
            # Audit successful operation
            audit_logger.log_schema_access(
                operation="list_tables",
                user_id=user_id,
                status=AuditEventStatus.SUCCESS,
                additional_data={"table_count": len(result)}
            )
            
            log_operation(logger, "list_tables_completed", table_count=len(result))
            return result
            
        except RateLimitExceeded as e:
            # Rate limit violation - audit and block
            audit_logger.log_security_violation(
                operation="list_tables",
                violation_type="rate_limit_exceeded",
                user_id=user_id,
                error_message=str(e)
            )
            
            log_error(logger, e, operation="list_tables")
            raise ErrorHandler.to_mcp_error(e)
            
        except Exception as e:
            # Audit error
            audit_logger.log_error(
                operation="list_tables",
                error_message=str(e),
                user_id=user_id,
                additional_data={"error_type": type(e).__name__}
            )
            
            # Convert to appropriate MCP error
            context = ErrorContext(operation="list_tables")
            fabric_error = ErrorHandler.handle_fabric_error(e, operation="list_tables", context=context)
            log_error(logger, fabric_error, operation="list_tables")
            raise ErrorHandler.to_mcp_error(fabric_error)


@app.tool()
def describe_table(table_name: str) -> Dict[str, Any]:
    """
    Get detailed schema information for a specific table in the Lakehouse.
    
    Returns comprehensive information about the table including all columns,
    their data types, constraints, indexes, and relationships.
    
    Args:
        table_name: Name of the table to describe
        
    Returns:
        Dictionary containing detailed table schema information
    """
    # Validate input parameters
    if not table_name or not table_name.strip():
        context = ErrorContext(operation="describe_table")
        validation_error = ValidationError("Table name cannot be empty", context=context)
        log_error(logger, validation_error, operation="describe_table")
        raise ErrorHandler.to_mcp_error(validation_error)
    
    table_name = table_name.strip()
    
    # Get security components
    sql_validator, complexity_analyzer, audit_logger, rate_limiter = get_security_components()
    user_id = _get_user_id()
    
    with OperationLogger(logger, "describe_table_tool", table_name=table_name):
        try:
            # Rate limiting
            rate_limiter.check_request_limit(user_id, "describe_table")
            
            client = get_client()
            schema = client.get_table_schema(table_name)
            
            # Convert to dictionary format for MCP response
            result = {
                "table_name": schema.table_name,
                "schema_name": schema.schema_name,
                "columns": [],
                "primary_keys": schema.primary_keys,
                "indexes": []
            }
            
            # Add column information
            for column in schema.columns:
                column_dict = {
                    "name": column.name,
                    "data_type": column.data_type,
                    "is_nullable": column.is_nullable,
                    "ordinal_position": column.ordinal_position,
                }
                
                # Add optional fields if available
                if column.default_value is not None:
                    column_dict["default_value"] = column.default_value
                if column.description:
                    column_dict["description"] = column.description
                    
                result["columns"].append(column_dict)
            
            # Add index information
            for index in schema.indexes:
                index_dict = {
                    "name": index.name,
                    "columns": index.columns,
                    "is_unique": index.is_unique,
                    "is_primary": index.is_primary,
                }
                result["indexes"].append(index_dict)
            
            # Audit successful operation
            audit_logger.log_schema_access(
                operation="describe_table",
                resource=table_name,
                user_id=user_id,
                status=AuditEventStatus.SUCCESS,
                additional_data={"column_count": len(result['columns'])}
            )
            
            log_operation(
                logger, 
                "describe_table_completed", 
                table_name=table_name, 
                column_count=len(result['columns'])
            )
            return result
            
        except RateLimitExceeded as e:
            # Rate limit violation - audit and block
            audit_logger.log_security_violation(
                operation="describe_table",
                violation_type="rate_limit_exceeded",
                resource=table_name,
                user_id=user_id,
                error_message=str(e)
            )
            
            log_error(logger, e, operation="describe_table")
            raise ErrorHandler.to_mcp_error(e)
            
        except Exception as e:
            # Audit error
            audit_logger.log_error(
                operation="describe_table",
                error_message=str(e),
                resource=table_name,
                user_id=user_id,
                additional_data={"error_type": type(e).__name__}
            )
            
            # Convert to appropriate MCP error
            context = ErrorContext(operation="describe_table", resource=table_name)
            fabric_error = ErrorHandler.handle_fabric_error(e, operation="describe_table", resource=table_name, context=context)
            log_error(logger, fabric_error, operation="describe_table")
            raise ErrorHandler.to_mcp_error(fabric_error)


@app.tool()
def create_table(
    table_name: str,
    columns: List[Dict[str, Any]],
    schema_name: str = "dbo",
    format: str = "DELTA",
    location: Optional[str] = None,
    description: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a new table in the Microsoft Fabric Lakehouse.
    
    Creates a table with the specified schema and configuration. Supports
    various data types and formats including Delta, Parquet, and external tables.
    
    Args:
        table_name: Name of the table to create
        columns: List of column definitions with name, data_type, nullable, and description
        schema_name: Schema name (default: "dbo")
        format: Table format (default: "DELTA")
        location: Optional location for external tables
        description: Optional table description
        
    Returns:
        Dictionary containing creation result and table information
    """
    # Validate input parameters
    if not table_name or not table_name.strip():
        context = ErrorContext(operation="create_table")
        validation_error = ValidationError("Table name cannot be empty", context=context)
        log_error(logger, validation_error, operation="create_table")
        raise ErrorHandler.to_mcp_error(validation_error)
    
    if not columns:
        context = ErrorContext(operation="create_table")
        validation_error = ValidationError("Table must have at least one column", context=context)
        log_error(logger, validation_error, operation="create_table")
        raise ErrorHandler.to_mcp_error(validation_error)
    
    # Validate column format
    for i, col_data in enumerate(columns):
        if not isinstance(col_data, dict):
            context = ErrorContext(operation="create_table", additional_data={"column_index": i+1})
            validation_error = ValidationError(f"Column {i+1} must be a dictionary", context=context)
            log_error(logger, validation_error, operation="create_table")
            raise ErrorHandler.to_mcp_error(validation_error)
        
        if "name" not in col_data or "data_type" not in col_data:
            context = ErrorContext(operation="create_table", additional_data={"column_index": i+1})
            validation_error = ValidationError(f"Column {i+1} must have 'name' and 'data_type' fields", context=context)
            log_error(logger, validation_error, operation="create_table")
            raise ErrorHandler.to_mcp_error(validation_error)
    
    # Get security components
    sql_validator, complexity_analyzer, audit_logger, rate_limiter = get_security_components()
    user_id = _get_user_id()
    
    with OperationLogger(
        logger, 
        "create_table_tool", 
        table_name=table_name, 
        column_count=len(columns),
        format=format
    ):
        try:
            # Rate limiting for schema operations
            rate_limiter.check_request_limit(user_id, "create_table")
            rate_limiter.check_schema_operation_limit(user_id, "create_table")
            # Build column definitions
            column_definitions = []
            for col_data in columns:
                column_def = ColumnDefinition(
                    name=col_data["name"],
                    data_type=col_data["data_type"],
                    nullable=col_data.get("nullable", True),
                    description=col_data.get("description")
                )
                column_definitions.append(column_def)
            
            # Create table definition
            table_def = TableDefinition(
                name=table_name.strip(),
                columns=column_definitions,
                schema_name=schema_name,
                format=format,
                location=location,
                description=description
            )
            
            # Validate table definition
            validate_table_definition(table_def)
            
            # Create the table
            client = get_client()
            success = client.create_table(table_def)
            
            result = {
                "success": success,
                "table_name": table_def.name,
                "schema_name": table_def.schema_name,
                "format": table_def.format,
                "column_count": len(table_def.columns),
                "message": f"Table '{table_def.schema_name}.{table_def.name}' created successfully"
            }
            
            if table_def.location:
                result["location"] = table_def.location
            if table_def.description:
                result["description"] = table_def.description
            
            # Audit successful table creation
            audit_logger.log_schema_modification(
                operation="create_table",
                resource=f"{table_def.schema_name}.{table_def.name}",
                user_id=user_id,
                status=AuditEventStatus.SUCCESS,
                additional_data={
                    "table_name": table_def.name,
                    "schema_name": table_def.schema_name,
                    "column_count": len(table_def.columns),
                    "format": table_def.format
                }
            )
            
            log_operation(
                logger, 
                "create_table_completed", 
                table_name=table_def.name, 
                column_count=len(table_def.columns)
            )
            return result
            
        except RateLimitExceeded as e:
            # Rate limit violation - audit and block
            audit_logger.log_security_violation(
                operation="create_table",
                violation_type="rate_limit_exceeded",
                resource=table_name,
                user_id=user_id,
                error_message=str(e)
            )
            
            log_error(logger, e, operation="create_table")
            raise ErrorHandler.to_mcp_error(e)
            
        except ValidationError as e:
            # Audit validation error
            audit_logger.log_error(
                operation="create_table",
                error_message=str(e),
                user_id=user_id,
                additional_data={"table_name": table_name}
            )
            
            log_error(logger, e, operation="create_table")
            raise ErrorHandler.to_mcp_error(e)
            
        except Exception as e:
            # Audit general error
            audit_logger.log_error(
                operation="create_table",
                error_message=str(e),
                user_id=user_id,
                additional_data={"table_name": table_name, "error_type": type(e).__name__}
            )
            
            # Convert to appropriate MCP error
            context = ErrorContext(operation="create_table", resource=table_name)
            fabric_error = ErrorHandler.handle_fabric_error(e, operation="create_table", resource=table_name, context=context)
            log_error(logger, fabric_error, operation="create_table")
            raise ErrorHandler.to_mcp_error(fabric_error)


@app.tool()
def execute_query(
    query: str,
    limit: Optional[int] = None,
    page: int = 1,
    page_size: Optional[int] = None,
    timeout_seconds: Optional[int] = None,
    format_type: str = "structured",
    enable_pagination: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Execute a SQL query against the Microsoft Fabric Lakehouse with enhanced security features.
    
    Supports SELECT queries for data retrieval and INSERT/UPDATE/DELETE for
    data modification. Includes pagination, timeout handling, multiple output formats,
    SQL injection prevention, query complexity analysis, rate limiting, and audit logging.
    
    Args:
        query: SQL query to execute
        limit: Optional limit on number of rows to return (legacy parameter)
        page: Page number for pagination (1-based, default: 1)
        page_size: Number of rows per page (uses server default if not specified)
        timeout_seconds: Query timeout in seconds (uses server default if not specified)
        format_type: Output format - 'structured', 'table', 'csv', or 'json'
        enable_pagination: Whether to enable pagination for this query
        
    Returns:
        Dictionary containing formatted query results, execution metadata, and pagination info
    """
    # Get security components
    sql_validator, complexity_analyzer, audit_logger, rate_limiter = get_security_components()
    user_id = _get_user_id()
    
    # Validate input parameters
    if not query or not query.strip():
        context = ErrorContext(operation="execute_query")
        validation_error = ValidationError("Query cannot be empty", context=context)
        log_error(logger, validation_error, operation="execute_query")
        
        # Audit the failed attempt
        audit_logger.log_error(
            operation="execute_query",
            error_message="Query cannot be empty",
            user_id=user_id,
            query=query
        )
        
        raise ErrorHandler.to_mcp_error(validation_error)
    
    query = query.strip()
    
    # Validate parameters
    if limit is not None:
        if not isinstance(limit, int) or limit <= 0:
            context = ErrorContext(operation="execute_query", additional_data={"limit": limit})
            validation_error = ValidationError("Limit must be a positive integer", context=context)
            log_error(logger, validation_error, operation="execute_query")
            
            audit_logger.log_error(
                operation="execute_query",
                error_message="Invalid limit parameter",
                user_id=user_id,
                query=query,
                additional_data={"limit": limit}
            )
            
            raise ErrorHandler.to_mcp_error(validation_error)
        
        if limit > 10000:  # Reasonable upper bound
            context = ErrorContext(operation="execute_query", additional_data={"limit": limit})
            validation_error = ValidationError("Limit cannot exceed 10,000 rows", context=context)
            log_error(logger, validation_error, operation="execute_query")
            
            audit_logger.log_error(
                operation="execute_query",
                error_message="Limit exceeds maximum allowed",
                user_id=user_id,
                query=query,
                additional_data={"limit": limit}
            )
            
            raise ErrorHandler.to_mcp_error(validation_error)
    
    if page < 1:
        context = ErrorContext(operation="execute_query", additional_data={"page": page})
        validation_error = ValidationError("Page must be 1 or greater", context=context)
        log_error(logger, validation_error, operation="execute_query")
        
        audit_logger.log_error(
            operation="execute_query",
            error_message="Invalid page parameter",
            user_id=user_id,
            query=query,
            additional_data={"page": page}
        )
        
        raise ErrorHandler.to_mcp_error(validation_error)
    
    if page_size is not None and (page_size <= 0 or page_size > 10000):
        context = ErrorContext(operation="execute_query", additional_data={"page_size": page_size})
        validation_error = ValidationError("Page size must be between 1 and 10,000", context=context)
        log_error(logger, validation_error, operation="execute_query")
        
        audit_logger.log_error(
            operation="execute_query",
            error_message="Invalid page_size parameter",
            user_id=user_id,
            query=query,
            additional_data={"page_size": page_size}
        )
        
        raise ErrorHandler.to_mcp_error(validation_error)
    
    if timeout_seconds is not None and timeout_seconds <= 0:
        context = ErrorContext(operation="execute_query", additional_data={"timeout_seconds": timeout_seconds})
        validation_error = ValidationError("Timeout must be positive", context=context)
        log_error(logger, validation_error, operation="execute_query")
        
        audit_logger.log_error(
            operation="execute_query",
            error_message="Invalid timeout parameter",
            user_id=user_id,
            query=query,
            additional_data={"timeout_seconds": timeout_seconds}
        )
        
        raise ErrorHandler.to_mcp_error(validation_error)
    
    if format_type not in ["structured", "table", "csv", "json"]:
        context = ErrorContext(operation="execute_query", additional_data={"format_type": format_type})
        validation_error = ValidationError("Format type must be one of: structured, table, csv, json", context=context)
        log_error(logger, validation_error, operation="execute_query")
        
        audit_logger.log_error(
            operation="execute_query",
            error_message="Invalid format_type parameter",
            user_id=user_id,
            query=query,
            additional_data={"format_type": format_type}
        )
        
        raise ErrorHandler.to_mcp_error(validation_error)
    
    with OperationLogger(
        logger, 
        "execute_query_tool", 
        query_preview=query[:100] + "..." if len(query) > 100 else query,
        limit=limit,
        page=page,
        page_size=page_size,
        format_type=format_type,
        timeout_seconds=timeout_seconds
    ):
        try:
            # 1. Rate limiting check
            rate_limiter.check_request_limit(user_id, "execute_query")
            rate_limiter.check_query_limit(user_id, "execute_query")
            
            # 2. SQL security validation
            sql_validator.validate_query(query, "execute_query")
            
            # 3. Basic query type validation
            query_type = validate_sql_query(query)
            
            # 4. Query complexity analysis
            complexity_metrics = complexity_analyzer.analyze_query(query, "execute_query")
            
            # 5. Additional rate limiting for data modification operations
            if query_type.value in ["INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER"]:
                if query_type.value in ["INSERT", "UPDATE", "DELETE"]:
                    rate_limiter.check_data_operation_limit(user_id, "execute_query")
                elif query_type.value in ["CREATE", "DROP", "ALTER"]:
                    rate_limiter.check_schema_operation_limit(user_id, "execute_query")
            
            # 6. Acquire concurrent query slot
            with ConcurrentQuerySlot(rate_limiter, user_id, "execute_query") as slot_id:
                
                # Execute the query with enhanced features
                client = get_client()
                
                # For backward compatibility, if limit is provided, disable pagination
                if limit is not None:
                    enable_pagination = False
                    page_size = None
                
                result = client.execute_sql(
                    query=query,
                    limit=limit,
                    page=page,
                    page_size=page_size,
                    timeout_seconds=timeout_seconds,
                    enable_pagination=enable_pagination
                )
                
                # Format the result using the formatter
                if hasattr(client, 'formatter'):
                    formatter = client.formatter
                else:
                    # Create a temporary formatter if client doesn't have one
                    config = QueryExecutionConfig(
                        page_size=page_size or 1000,
                        enable_pagination=enable_pagination if enable_pagination is not None else True,
                        format_results=True,
                        include_metadata=True
                    )
                    formatter = QueryResultFormatter(config)
                
                response = formatter.format_result(result, format_type, page)
                
                # For backward compatibility with legacy limit parameter
                if limit is not None and result.query_type.value == "SELECT":
                    if result.row_count >= limit:
                        response["message"] = f"Query executed successfully, returned {result.row_count} rows (limited to {limit} rows)"
                        response["truncated"] = True
                    else:
                        response["truncated"] = False
                
                # Add security metadata to response
                response["security_info"] = {
                    "complexity_score": complexity_metrics.total_score,
                    "complexity_level": complexity_metrics.complexity_level.value,
                    "security_validated": True,
                    "rate_limited": True
                }
                
                # 7. Audit successful operation
                if query_type.value == "SELECT":
                    audit_logger.log_data_access(
                        operation="execute_query",
                        query=query,
                        user_id=user_id,
                        result_count=result.row_count,
                        execution_time_ms=result.execution_time_ms,
                        status=AuditEventStatus.SUCCESS,
                        additional_data={
                            "query_type": query_type.value,
                            "complexity_score": complexity_metrics.total_score,
                            "format_type": format_type,
                            "page": page,
                            "limit": limit
                        }
                    )
                else:
                    audit_logger.log_data_modification(
                        operation="execute_query",
                        query=query,
                        user_id=user_id,
                        affected_rows=getattr(result, 'affected_rows', None),
                        execution_time_ms=result.execution_time_ms,
                        status=AuditEventStatus.SUCCESS,
                        additional_data={
                            "query_type": query_type.value,
                            "complexity_score": complexity_metrics.total_score
                        }
                    )
                
                log_operation(
                    logger,
                    "execute_query_completed",
                    query_type=result.query_type.value,
                    execution_time_ms=result.execution_time_ms,
                    row_count=getattr(result, 'row_count', None),
                    affected_rows=getattr(result, 'affected_rows', None),
                    format_type=format_type,
                    has_more_rows=getattr(result, 'has_more_rows', False),
                    complexity_score=complexity_metrics.total_score,
                    security_validated=True
                )
                
                return response
            
        except (SQLSecurityError, QueryComplexityError, RateLimitExceeded) as e:
            # Security violations - audit and block
            audit_logger.log_security_violation(
                operation="execute_query",
                violation_type=type(e).__name__,
                query=query,
                user_id=user_id,
                error_message=str(e),
                additional_data={
                    "security_issue": getattr(e, 'security_issue', None) or getattr(e, 'complexity_issue', None) or getattr(e, 'limit_type', None)
                }
            )
            
            log_error(logger, e, operation="execute_query")
            raise ErrorHandler.to_mcp_error(e)
            
        except ValidationError as e:
            # Validation errors - audit and return error
            audit_logger.log_error(
                operation="execute_query",
                error_message=str(e),
                user_id=user_id,
                query=query
            )
            
            log_error(logger, e, operation="execute_query")
            raise ErrorHandler.to_mcp_error(e)
            
        except Exception as e:
            # Other errors - audit and handle
            audit_logger.log_error(
                operation="execute_query",
                error_message=str(e),
                user_id=user_id,
                query=query,
                additional_data={"error_type": type(e).__name__}
            )
            
            # Convert to appropriate MCP error
            context = ErrorContext(operation="execute_query")
            fabric_error = ErrorHandler.handle_fabric_error(e, operation="execute_query", context=context)
            log_error(logger, fabric_error, operation="execute_query")
            raise ErrorHandler.to_mcp_error(fabric_error)


@app.tool()
def cancel_query(query_id: str) -> Dict[str, Any]:
    """
    Cancel a running query by its ID.
    
    Args:
        query_id: ID of the query to cancel
        
    Returns:
        Dictionary containing cancellation result
    """
    if not query_id or not query_id.strip():
        context = ErrorContext(operation="cancel_query")
        validation_error = ValidationError("Query ID cannot be empty", context=context)
        log_error(logger, validation_error, operation="cancel_query")
        raise ErrorHandler.to_mcp_error(validation_error)
    
    query_id = query_id.strip()
    
    with OperationLogger(logger, "cancel_query_tool", query_id=query_id):
        try:
            client = get_client()
            success = client.cancel_query(query_id)
            
            response = {
                "success": success,
                "query_id": query_id,
                "message": f"Query {query_id} {'cancelled successfully' if success else 'not found or already completed'}"
            }
            
            log_operation(
                logger,
                "cancel_query_completed",
                query_id=query_id,
                success=success
            )
            return response
            
        except Exception as e:
            context = ErrorContext(operation="cancel_query", resource=query_id)
            fabric_error = ErrorHandler.handle_fabric_error(e, operation="cancel_query", resource=query_id, context=context)
            log_error(logger, fabric_error, operation="cancel_query")
            raise ErrorHandler.to_mcp_error(fabric_error)


@app.tool()
def get_active_queries() -> Dict[str, Any]:
    """
    Get information about currently active queries.
    
    Returns:
        Dictionary containing active query information
    """
    with OperationLogger(logger, "get_active_queries_tool"):
        try:
            client = get_client()
            active_queries = client.get_active_queries()
            
            response = {
                "success": True,
                "active_queries": active_queries,
                "count": len(active_queries),
                "message": f"Found {len(active_queries)} active queries"
            }
            
            log_operation(
                logger,
                "get_active_queries_completed",
                count=len(active_queries)
            )
            return response
            
        except Exception as e:
            context = ErrorContext(operation="get_active_queries")
            fabric_error = ErrorHandler.handle_fabric_error(e, operation="get_active_queries", context=context)
            log_error(logger, fabric_error, operation="get_active_queries")
            raise ErrorHandler.to_mcp_error(fabric_error)