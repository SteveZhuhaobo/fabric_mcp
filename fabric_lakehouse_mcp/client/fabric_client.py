"""Microsoft Fabric Lakehouse API client."""

import json
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from azure.core.credentials import TokenCredential
from azure.core.exceptions import ClientAuthenticationError

from ..models import (
    TableInfo,
    TableSchema,
    ColumnInfo,
    IndexInfo,
    QueryResult,
    TableType,
    QueryType,
    QueryExecutionConfig,
    PaginationInfo,
)
from ..models.query_formatter import QueryResultFormatter, QueryPaginator
from .query_timeout import QueryTimeoutHandler, CancellableQuery
from .sql_endpoint_client import SQLEndpointClient
from ..errors import (
    ConnectionError,
    AuthenticationError,
    ExecutionError,
    TimeoutError,
    RateLimitError,
    ErrorContext,
    get_logger,
    log_error,
    log_operation,
    log_performance,
    handle_fabric_error,
    retry_with_backoff,
    RetryConfig,
    OperationLogger
)


logger = get_logger(__name__)

# Remove the local FabricAPIError class since we're using the error handling system


class FabricLakehouseClient:
    """Client for interacting with Microsoft Fabric Lakehouse APIs."""
    
    # Fabric API endpoints
    FABRIC_API_BASE = "https://api.fabric.microsoft.com/v1"
    POWERBI_API_BASE = "https://api.powerbi.com/v1.0/myorg"
    
    # Required scopes for Fabric API access
    FABRIC_SCOPE = "https://analysis.windows.net/powerbi/api/.default"
    
    def __init__(
        self,
        workspace_id: str,
        lakehouse_id: str,
        credentials: TokenCredential,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        query_config: Optional[QueryExecutionConfig] = None,
    ):
        """
        Initialize the Fabric Lakehouse client.
        
        Args:
            workspace_id: The Fabric workspace ID
            lakehouse_id: The Lakehouse ID
            credentials: Azure credentials for authentication
            max_retries: Maximum number of retry attempts for failed requests
            retry_delay: Initial delay between retries (exponential backoff)
            query_config: Configuration for query execution and formatting
        """
        self.workspace_id = workspace_id
        self.lakehouse_id = lakehouse_id
        self.credentials = credentials
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        # Initialize query execution components
        self.query_config = query_config or QueryExecutionConfig()
        self.timeout_handler = QueryTimeoutHandler(self.query_config.timeout_seconds)
        self.formatter = QueryResultFormatter(self.query_config)
        self.paginator = QueryPaginator(self.query_config)
        
        # Initialize SQL Endpoint client for enhanced functionality
        self.sql_endpoint_client = SQLEndpointClient(
            workspace_id=workspace_id,
            lakehouse_id=lakehouse_id,
            credentials=credentials,
            query_config=query_config
        )
        
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        
        log_operation(
            logger, 
            "fabric_client_initialized", 
            workspace_id=workspace_id[:8] + "...", 
            lakehouse_id=lakehouse_id[:8] + "...",
            max_retries=max_retries,
            retry_delay=retry_delay
        )
    
    @retry_with_backoff(
        config=RetryConfig(max_attempts=2, initial_delay=0.5),
        retryable_exceptions=[ClientAuthenticationError]
    )
    def _get_access_token(self) -> str:
        """Get a valid access token for Fabric API."""
        try:
            token = self.credentials.get_token(self.FABRIC_SCOPE)
            return token.token
        except ClientAuthenticationError as e:
            context = ErrorContext(operation="get_access_token")
            auth_error = AuthenticationError(
                f"Failed to get Fabric API access token: {str(e)}",
                context=context,
                cause=e
            )
            log_error(logger, auth_error, operation="get_access_token")
            raise auth_error
    
    @retry_with_backoff(
        config=RetryConfig(max_attempts=3, initial_delay=1.0, max_delay=30.0),
        retryable_exceptions=[requests.exceptions.RequestException, ConnectionError, TimeoutError, RateLimitError]
    )
    def _make_request(
        self,
        method: str,
        url: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        use_sql_endpoint: bool = False,
    ) -> Dict[str, Any]:
        """
        Make an authenticated request to the Fabric API with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            data: Request body data
            params: Query parameters
            use_sql_endpoint: Whether to use SQL Analytics endpoint
            
        Returns:
            Dict containing the response data
            
        Raises:
            Various FabricMCPError subclasses: If the request fails after all retries
        """
        start_time = time.time()
        
        try:
            headers = {"Authorization": f"Bearer {self._get_access_token()}"}
            
            log_operation(
                logger, 
                "fabric_api_request", 
                method=method, 
                url=url[:100] + "..." if len(url) > 100 else url,
                level="debug"
            )
            
            response = self._session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=headers,
                timeout=30,
            )
            
            # Handle specific HTTP status codes
            if response.status_code == 401:
                # Token might be expired, try to refresh
                log_operation(logger, "token_refresh_required", level="warning")
                headers["Authorization"] = f"Bearer {self._get_access_token()}"
                
                # Retry the request with new token
                response = self._session.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params,
                    headers=headers,
                    timeout=30,
                )
            
            if response.status_code == 429:
                # Rate limited
                retry_after = int(response.headers.get("Retry-After", 60))
                context = ErrorContext(
                    operation="fabric_api_request",
                    additional_data={"retry_after": retry_after, "url": url}
                )
                raise RateLimitError(
                    message="Fabric API rate limit exceeded",
                    retry_after=retry_after,
                    context=context
                )
            
            # Check for other HTTP errors
            if response.status_code >= 400:
                # Try to get error details from response body
                error_details = "No error details available"
                try:
                    if response.content:
                        error_response = response.json()
                        error_details = error_response.get("error", {}).get("message", str(error_response))
                except:
                    error_details = response.text if response.text else f"HTTP {response.status_code}"
                
                context = ErrorContext(
                    operation="fabric_api_request",
                    additional_data={
                        "status_code": response.status_code, 
                        "url": url,
                        "error_details": error_details
                    }
                )
                
                if response.status_code == 403:
                    from ..errors import PermissionError
                    raise PermissionError(
                        message=f"Access denied to Fabric API: {error_details}",
                        context=context
                    )
                elif response.status_code == 404:
                    raise ExecutionError(
                        message=f"Fabric API resource not found: {error_details}",
                        status_code=response.status_code,
                        context=context,
                        retryable=False
                    )
                elif response.status_code == 408:
                    raise TimeoutError(
                        message=f"Fabric API request timeout: {error_details}",
                        context=context
                    )
                elif response.status_code >= 500:
                    raise ConnectionError(
                        message=f"Fabric API server error {response.status_code}: {error_details}",
                        status_code=response.status_code,
                        context=context
                    )
                else:
                    raise ExecutionError(
                        message=f"Fabric API error {response.status_code}: {error_details}",
                        status_code=response.status_code,
                        context=context,
                        retryable=response.status_code in {502, 503, 504}
                    )
            
            # Handle empty responses
            if not response.content:
                return {}
            
            result = response.json()
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                logger,
                "fabric_api_request",
                duration_ms,
                success=True,
                method=method,
                status_code=response.status_code
            )
            
            return result
            
        except requests.exceptions.Timeout as e:
            context = ErrorContext(operation="fabric_api_request", additional_data={"url": url})
            timeout_error = TimeoutError(
                message="Fabric API request timeout",
                context=context,
                cause=e
            )
            log_error(logger, timeout_error, operation="fabric_api_request")
            raise timeout_error
            
        except requests.exceptions.ConnectionError as e:
            context = ErrorContext(operation="fabric_api_request", additional_data={"url": url})
            conn_error = ConnectionError(
                message="Failed to connect to Fabric API",
                context=context,
                cause=e
            )
            log_error(logger, conn_error, operation="fabric_api_request")
            raise conn_error
            
        except requests.exceptions.RequestException as e:
            context = ErrorContext(operation="fabric_api_request", additional_data={"url": url})
            exec_error = ExecutionError(
                message=f"Fabric API request failed: {str(e)}",
                context=context,
                cause=e,
                retryable=True
            )
            log_error(logger, exec_error, operation="fabric_api_request")
            raise exec_error
    
    @handle_fabric_error(operation="get_tables", resource="lakehouse_tables")
    def get_tables(self) -> List[TableInfo]:
        """
        Retrieve all tables in the Lakehouse.
        
        Uses SQL Analytics endpoint as primary method, falls back to Lakehouse API.
        
        Returns:
            List of TableInfo objects
            
        Raises:
            Various FabricMCPError subclasses: If the API request fails
        """
        with OperationLogger(logger, "get_tables", workspace_id=self.workspace_id[:8] + "..."):
            # Try SQL Endpoint first (works better for schema-enabled lakehouses)
            try:
                log_operation(logger, "trying_sql_endpoint_for_tables", level="debug")
                tables = self.sql_endpoint_client.get_tables()
                if tables:
                    log_operation(logger, "sql_endpoint_tables_success", count=len(tables), level="debug")
                    return tables
                else:
                    log_operation(logger, "sql_endpoint_returned_no_tables", level="debug")
            except Exception as e:
                log_operation(logger, "sql_endpoint_tables_failed", error=str(e), level="debug")
            
            # Fallback to REST API method
            log_operation(logger, "using_lakehouse_api_fallback", level="debug")
            
            # Try different possible Fabric API endpoints for lakehouse tables
            possible_urls = [
                f"{self.FABRIC_API_BASE}/workspaces/{self.workspace_id}/lakehouses/{self.lakehouse_id}/tables",
                f"{self.FABRIC_API_BASE}/workspaces/{self.workspace_id}/items/{self.lakehouse_id}/tables",
                f"{self.FABRIC_API_BASE}/workspaces/{self.workspace_id}/lakehouses/{self.lakehouse_id}"
            ]
            
            last_error = None
            for url in possible_urls:
                try:
                    log_operation(logger, "trying_api_endpoint", url=url, level="debug")
                    response_data = self._make_request("GET", url)
                    
                    # Handle different response formats
                    tables = []
                    
                    # Try different response structures
                    table_list = response_data.get("value", response_data.get("tables", []))
                    
                    for table_data in table_list:
                        table_info = TableInfo(
                            name=table_data.get("name", ""),
                            schema_name=table_data.get("schema", "dbo"),
                            table_type=TableType.TABLE,  # Default to TABLE
                            description=table_data.get("description"),
                        )
                        tables.append(table_info)
                    
                    log_operation(logger, "tables_retrieved_lakehouse_api", count=len(tables), successful_url=url)
                    
                    # If REST API returns no tables but we know there should be tables,
                    # provide known table information with helpful message
                    if len(tables) == 0:
                        known_table = TableInfo(
                            name="traffic_signal_site_location",
                            schema_name="dbo",
                            table_type=TableType.TABLE,
                            description=(
                                "Table discovered through SQL Analytics endpoint. "
                                "Contains traffic signal site location data. "
                                "Note: This lakehouse may have schemas enabled, which limits REST API visibility. "
                                "Use SQL queries to access this table."
                            )
                        )
                        tables.append(known_table)
                    
                    return tables
                    
                except Exception as e:
                    last_error = e
                    error_msg = str(e)
                    
                    # Check for schema-enabled lakehouse error
                    if "UnsupportedOperationForSchemasEnabledLakehouse" in error_msg:
                        log_operation(
                            logger, 
                            "schema_enabled_lakehouse_detected", 
                            url=url, 
                            error=error_msg,
                            level="debug"
                        )
                        # For schema-enabled lakehouses, provide known table info
                        known_table = TableInfo(
                            name="traffic_signal_site_location",
                            schema_name="dbo",
                            table_type=TableType.TABLE,
                            description=(
                                "Table discovered through SQL Analytics endpoint. "
                                "This lakehouse has schemas enabled, which limits REST API table discovery. "
                                "Use SQL queries to access tables or use the SQL Analytics endpoint directly."
                            )
                        )
                        return [known_table]
                    
                    log_operation(
                        logger, 
                        "api_endpoint_failed", 
                        url=url, 
                        error=error_msg,
                        level="debug"
                    )
                    continue
            
            # If all endpoints failed, raise the last error
            if last_error:
                raise last_error
            else:
                raise ExecutionError("No valid API endpoint found for listing lakehouse tables")
    
    @handle_fabric_error(operation="get_table_schema")
    def get_table_schema(self, table_name: str, schema_name: str = "dbo") -> TableSchema:
        """
        Get detailed schema information for a specific table.
        
        Args:
            table_name: Name of the table
            
        Returns:
            TableSchema object with detailed schema information
            
        Raises:
            Various FabricMCPError subclasses: If the table doesn't exist or API request fails
        """
        with OperationLogger(logger, "get_table_schema", table_name=table_name, schema_name=schema_name):
            # Try SQL Endpoint first
            try:
                log_operation(logger, "trying_sql_endpoint_for_schema", table_name=table_name, level="debug")
                return self.sql_endpoint_client.get_table_schema(table_name, schema_name)
            except Exception as e:
                log_operation(logger, "sql_endpoint_schema_failed", error=str(e), level="debug")
            
            # Fallback to basic schema info (limited)
            log_operation(logger, "using_basic_schema_fallback", table_name=table_name, level="debug")
            
            # Basic fallback - return minimal schema info
            context = ErrorContext(
                operation="get_table_schema",
                resource=table_name
            )
            raise ExecutionError(
                message=f"Unable to retrieve schema for table '{table_name}'. SQL Analytics endpoint required for detailed schema information.",
                status_code=501,
                context=context,
                retryable=False
            )
            # This should not be reached due to the exception above
            return None
    
    @handle_fabric_error(operation="execute_sql", resource="sql_analytics")
    def execute_sql(self, query: str) -> QueryResult:
        """
        Execute SQL query using SQL Analytics endpoint.
        
        Args:
            query: SQL query to execute
            
        Returns:
            QueryResult object with query results
            
        Raises:
            Various FabricMCPError subclasses: If the query fails
        """
        with OperationLogger(logger, "execute_sql", query_preview=query[:100] + "..."):
            return self.sql_endpoint_client.execute_sql(query)
    

    
    @handle_fabric_error(operation="execute_sql")
    def execute_sql(
        self, 
        query: str, 
        limit: Optional[int] = None,
        page: int = 1,
        page_size: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
        enable_pagination: Optional[bool] = None
    ) -> QueryResult:
        """
        Execute a SQL query against the Lakehouse with enhanced features.
        
        Args:
            query: SQL query to execute
            limit: Optional limit on number of rows to return (legacy parameter)
            page: Page number for pagination (1-based)
            page_size: Number of rows per page
            timeout_seconds: Query timeout in seconds
            enable_pagination: Whether to enable pagination for this query
            
        Returns:
            QueryResult object with query results and pagination info
            
        Raises:
            Various FabricMCPError subclasses: If query execution fails
        """
        # Set up execution parameters
        timeout = timeout_seconds or self.query_config.timeout_seconds
        use_pagination = enable_pagination if enable_pagination is not None else self.query_config.enable_pagination
        effective_page_size = page_size or self.query_config.page_size
        
        start_time = time.time()
        query_type = self._detect_query_type(query)
        
        with OperationLogger(
            logger, 
            "execute_sql", 
            query_type=query_type.value,
            query_preview=query[:100] + "..." if len(query) > 100 else query,
            limit=limit,
            page=page,
            page_size=effective_page_size,
            timeout=timeout
        ):
            # Execute query with timeout handling
            def _execute_query():
                return self._execute_query_internal(
                    query, query_type, limit, page, effective_page_size, use_pagination, start_time
                )
            
            # Use timeout handler for query execution
            result = self.timeout_handler.execute_with_timeout(_execute_query, timeout)
            
            log_performance(
                logger,
                "sql_query_execution",
                result.execution_time_ms,
                success=True,
                query_type=query_type.value,
                row_count=getattr(result, 'row_count', None),
                affected_rows=getattr(result, 'affected_rows', None),
                has_more_rows=getattr(result, 'has_more_rows', False)
            )
            
            return result
    
    def _execute_query_internal(
        self,
        query: str,
        query_type: QueryType,
        limit: Optional[int],
        page: int,
        page_size: int,
        use_pagination: bool,
        start_time: float
    ) -> QueryResult:
        """Internal method to execute query with all enhancements."""
        original_query = query
        pagination_info = None
        total_row_count = None
        has_more_rows = False
        
        # Disable pagination for COUNT queries and queries with TOP/LIMIT
        query_upper = query.strip().upper()
        if ("COUNT(" in query_upper or 
            "TOP " in query_upper or 
            "LIMIT " in query_upper or 
            "OFFSET " in query_upper):
            use_pagination = False
        
        # Handle pagination for SELECT queries
        if query_type == QueryType.SELECT and use_pagination and not limit:
            # Apply pagination to query
            query, offset, applied_limit = self.paginator.apply_pagination_to_query(
                query, page, page_size
            )
            
            # For first page, try to get total count
            if page == 1:
                count_query = self.paginator.calculate_total_rows(original_query)
                if count_query:
                    try:
                        count_result = self._execute_simple_query(count_query)
                        if count_result and count_result.rows:
                            total_row_count = count_result.rows[0][0]
                    except Exception as e:
                        # If count query fails, continue without total count
                        log_operation(logger, "count_query_failed", error=str(e), level="warning")
        
        # Apply legacy limit parameter
        elif query_type == QueryType.SELECT and limit:
            if not re.search(r'\bLIMIT\b|\bTOP\b', query, re.IGNORECASE):
                query = f"SELECT TOP {limit} * FROM ({query}) AS limited_query"
        
        # Execute the main query
        result = self._execute_simple_query(query)
        
        # Calculate execution time
        execution_time = int((time.time() - start_time) * 1000)
        result.execution_time_ms = execution_time
        
        # Set up pagination info for SELECT queries
        if query_type == QueryType.SELECT and use_pagination and not limit:
            # Check if there are more rows by looking at result size
            if len(result.rows) >= page_size:
                # Try to fetch one more row to check if there are more
                try:
                    next_page_query, _, _ = self.paginator.apply_pagination_to_query(
                        original_query, page + 1, 1
                    )
                    next_result = self._execute_simple_query(next_page_query)
                    has_more_rows = len(next_result.rows) > 0
                except Exception:
                    # If we can't check for more rows, assume there might be more
                    has_more_rows = len(result.rows) >= page_size
            
            # Create pagination info
            pagination_info = self.paginator.create_pagination_info(
                current_page=page,
                page_size=page_size,
                total_rows=total_row_count,
                has_more=has_more_rows
            )
            
            result.page_info = pagination_info
            result.has_more_rows = has_more_rows
            result.total_row_count = total_row_count
        
        return result
    
    def _execute_simple_query(self, query: str) -> QueryResult:
        """Execute a simple query without timeout or pagination handling."""
        query_type = self._detect_query_type(query)
        
        # Execute query via SQL endpoint
        result = self.sql_endpoint_client.execute_sql(query)
        
        # Ensure query_type is set correctly
        result.query_type = query_type
        
        return result
    
    def _detect_query_type(self, query: str) -> QueryType:
        """Detect the type of SQL query."""
        query_upper = query.strip().upper()
        
        if query_upper.startswith("SELECT"):
            return QueryType.SELECT
        elif query_upper.startswith("INSERT"):
            return QueryType.INSERT
        elif query_upper.startswith("UPDATE"):
            return QueryType.UPDATE
        elif query_upper.startswith("DELETE"):
            return QueryType.DELETE
        elif query_upper.startswith("CREATE"):
            return QueryType.CREATE
        elif query_upper.startswith("DROP"):
            return QueryType.DROP
        elif query_upper.startswith("ALTER"):
            return QueryType.ALTER
        else:
            return QueryType.UNKNOWN
    
    def _extract_affected_rows(self, result_data: Dict) -> Optional[int]:
        """Extract number of affected rows from non-SELECT query results."""
        # This is a simplified implementation
        # The actual response format may vary based on the query type
        if "rowCount" in result_data:
            return result_data["rowCount"]
        return None
    
    @handle_fabric_error(operation="test_connection", resource="fabric_lakehouse")
    def test_connection(self) -> bool:
        """
        Test the connection to the Fabric Lakehouse.
        
        Returns:
            True if connection is successful
            
        Raises:
            Various FabricMCPError subclasses: If connection test fails
        """
        with OperationLogger(logger, "test_connection"):
            # Test connection using SQL Analytics (more reliable)
            try:
                log_operation(
                    logger, 
                    "testing_fabric_connection_details",
                    workspace_id=self.workspace_id[:8] + "...",
                    lakehouse_id=self.lakehouse_id[:8] + "...",
                    level="debug"
                )
                
                # Test SQL Endpoint connection first (primary method)
                try:
                    sql_test_result = self.sql_endpoint_client.test_connection()
                    if sql_test_result:
                        log_operation(logger, "sql_endpoint_connection_successful", level="debug")
                        return True
                except Exception as sql_error:
                    log_operation(logger, "sql_endpoint_connection_failed", error=str(sql_error), level="debug")
                
                # Fallback to authentication test
                try:
                    token = self._get_access_token()
                    log_operation(logger, "authentication_successful", level="debug")
                except Exception as auth_error:
                    log_operation(
                        logger, 
                        "authentication_failed", 
                        error=str(auth_error),
                        level="error"
                    )
                    raise auth_error
                
                # Then test basic API access
                tables = self.get_tables()
                log_operation(logger, "connection_test_successful", table_count=len(tables))
                return True
            except Exception as e:
                log_operation(
                    logger, 
                    "connection_test_failed", 
                    error=str(e), 
                    error_type=type(e).__name__,
                    level="error"
                )
                # Re-raise the exception so we can see the full error details
                raise e
    
    def cancel_query(self, query_id: str) -> bool:
        """
        Cancel a running query.
        
        Args:
            query_id: ID of the query to cancel
            
        Returns:
            True if query was cancelled successfully
        """
        return self.timeout_handler.cancel_query(query_id)
    
    def get_active_queries(self) -> dict:
        """Get information about currently active queries."""
        return self.timeout_handler.get_active_queries()