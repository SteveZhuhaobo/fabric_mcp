"""SQL Analytics Endpoint client for Microsoft Fabric Lakehouse."""

import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from azure.core.credentials import TokenCredential

from ..models import (
    TableInfo,
    TableSchema,
    ColumnInfo,
    QueryResult,
    TableType,
    QueryType,
    QueryExecutionConfig,
)
from ..models.query_formatter import QueryResultFormatter
from ..errors import (
    ConnectionError,
    AuthenticationError,
    ExecutionError,
    TimeoutError,
    ErrorContext,
    get_logger,
    log_error,
    log_operation,
    log_performance,
    handle_fabric_error,
    OperationLogger
)


logger = get_logger(__name__)


class SQLAnalyticsClient:
    """Client for SQL Analytics Endpoint via Power BI REST API."""
    
    # Power BI API endpoints
    POWERBI_API_BASE = "https://api.powerbi.com/v1.0/myorg"
    
    # Required scopes for Power BI API access
    POWERBI_SCOPE = "https://analysis.windows.net/powerbi/api/.default"
    
    def __init__(
        self,
        workspace_id: str,
        lakehouse_id: str,
        credentials: TokenCredential,
        query_config: Optional[QueryExecutionConfig] = None,
    ):
        """
        Initialize the SQL Analytics client.
        
        Args:
            workspace_id: The Fabric workspace ID
            lakehouse_id: The Lakehouse ID
            credentials: Azure credentials for authentication
            query_config: Configuration for query execution and formatting
        """
        self.workspace_id = workspace_id
        self.lakehouse_id = lakehouse_id
        self.credentials = credentials
        self.query_config = query_config or QueryExecutionConfig()
        self.formatter = QueryResultFormatter(self.query_config)
        
        # Cache for dataset ID discovery
        self._dataset_id = None
        
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        
        log_operation(
            logger, 
            "sql_analytics_client_initialized",
            workspace_id=workspace_id[:8] + "...",
            lakehouse_id=lakehouse_id[:8] + "..."
        )
    
    def _get_access_token(self) -> str:
        """Get access token for Power BI API."""
        try:
            token = self.credentials.get_token(self.POWERBI_SCOPE)
            return token.token
        except Exception as e:
            context = ErrorContext(operation="get_access_token")
            auth_error = AuthenticationError(
                message="Failed to get Power BI access token",
                context=context,
                cause=e
            )
            log_error(logger, auth_error, operation="get_access_token")
            raise auth_error
    
    def _make_request(self, method: str, url: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make authenticated request to Power BI API."""
        start_time = time.time()
        
        try:
            # Get access token
            access_token = self._get_access_token()
            headers = {
                **self._session.headers,
                "Authorization": f"Bearer {access_token}"
            }
            
            log_operation(
                logger, 
                "powerbi_api_request", 
                method=method, 
                url=url[:100] + "..." if len(url) > 100 else url,
                level="debug"
            )
            
            # Make request
            if method.upper() == "GET":
                response = self._session.get(url, headers=headers, timeout=30)
            elif method.upper() == "POST":
                response = self._session.post(url, headers=headers, json=data, timeout=30)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Handle response
            if response.status_code == 200:
                duration_ms = (time.time() - start_time) * 1000
                log_performance(
                    logger,
                    "powerbi_api_request",
                    duration_ms,
                    success=True,
                    status_code=response.status_code
                )
                return response.json()
            
            elif response.status_code == 401:
                context = ErrorContext(
                    operation="powerbi_api_request",
                    additional_data={"status_code": 401, "url": url}
                )
                auth_error = AuthenticationError(
                    message="Power BI API authentication failed",
                    context=context,
                    status_code=401
                )
                log_error(logger, auth_error, operation="powerbi_api_request")
                raise auth_error
            
            else:
                context = ErrorContext(
                    operation="powerbi_api_request",
                    additional_data={
                        "status_code": response.status_code, 
                        "url": url,
                        "response_text": response.text[:500]
                    }
                )
                exec_error = ExecutionError(
                    message=f"Power BI API request failed: HTTP {response.status_code}",
                    context=context,
                    status_code=response.status_code,
                    retryable=response.status_code >= 500
                )
                log_error(logger, exec_error, operation="powerbi_api_request")
                raise exec_error
            
        except requests.exceptions.Timeout as e:
            context = ErrorContext(operation="powerbi_api_request", additional_data={"url": url})
            timeout_error = TimeoutError(
                message="Power BI API request timeout",
                context=context,
                cause=e
            )
            log_error(logger, timeout_error, operation="powerbi_api_request")
            raise timeout_error
            
        except requests.exceptions.ConnectionError as e:
            context = ErrorContext(operation="powerbi_api_request", additional_data={"url": url})
            conn_error = ConnectionError(
                message="Failed to connect to Power BI API",
                context=context,
                cause=e
            )
            log_error(logger, conn_error, operation="powerbi_api_request")
            raise conn_error
    
    def _discover_dataset_id(self) -> str:
        """
        Discover the dataset ID associated with the lakehouse.
        
        In Fabric, lakehouses automatically create corresponding datasets.
        We need to find the dataset that corresponds to our lakehouse.
        """
        if self._dataset_id:
            return self._dataset_id
        
        try:
            # List all datasets in the workspace
            url = f"{self.POWERBI_API_BASE}/groups/{self.workspace_id}/datasets"
            response_data = self._make_request("GET", url)
            
            datasets = response_data.get("value", [])
            
            # Look for dataset with lakehouse name or ID
            for dataset in datasets:
                dataset_name = dataset.get("name", "")
                dataset_id = dataset.get("id", "")
                
                # Check if this dataset is associated with our lakehouse
                # Fabric typically names the dataset after the lakehouse
                if (self.lakehouse_id.lower() in dataset_name.lower() or 
                    dataset_name.lower().startswith("lh_") or
                    "lakehouse" in dataset_name.lower()):
                    
                    log_operation(
                        logger, 
                        "dataset_discovered", 
                        dataset_id=dataset_id[:8] + "...",
                        dataset_name=dataset_name,
                        level="debug"
                    )
                    self._dataset_id = dataset_id
                    return dataset_id
            
            # If no obvious match, try the first dataset (fallback)
            if datasets:
                first_dataset = datasets[0]
                dataset_id = first_dataset.get("id", "")
                dataset_name = first_dataset.get("name", "")
                
                log_operation(
                    logger, 
                    "using_first_dataset_as_fallback", 
                    dataset_id=dataset_id[:8] + "...",
                    dataset_name=dataset_name,
                    level="debug"
                )
                self._dataset_id = dataset_id
                return dataset_id
            
            # No datasets found - this is common in Fabric lakehouses
            raise ExecutionError(
                "No datasets found in workspace. To use SQL Analytics with your lakehouse, you need to:\n"
                "1. Create a semantic model from your lakehouse data\n"
                "2. Enable SQL Analytics endpoint in Fabric\n"
                "3. Or use Power BI to create reports from the lakehouse\n"
                "Currently falling back to basic Lakehouse API functionality."
            )
            
        except Exception as e:
            log_operation(logger, "dataset_discovery_failed", error=str(e), level="error")
            # Fallback to using lakehouse_id as dataset_id (original behavior)
            self._dataset_id = self.lakehouse_id
            return self.lakehouse_id
    
    @handle_fabric_error(operation="execute_sql", resource="sql_analytics")
    def execute_sql(self, query: str) -> QueryResult:
        """
        Execute SQL query via Power BI REST API.
        
        Args:
            query: SQL query to execute
            
        Returns:
            QueryResult object with query results
            
        Raises:
            Various FabricMCPError subclasses: If the query fails
        """
        with OperationLogger(logger, "execute_sql_analytics", query_preview=query[:100] + "..."):
            # Discover the correct dataset ID
            dataset_id = self._discover_dataset_id()
            
            # Power BI API endpoint for executing queries
            url = f"{self.POWERBI_API_BASE}/groups/{self.workspace_id}/datasets/{dataset_id}/executeQueries"
            
            # Prepare query payload
            payload = {
                "queries": [
                    {
                        "query": query
                    }
                ],
                "serializerSettings": {
                    "includeNulls": True
                }
            }
            
            response_data = self._make_request("POST", url, payload)
            
            # Parse response
            if "results" in response_data and len(response_data["results"]) > 0:
                result = response_data["results"][0]
                
                # Extract tables (result sets)
                if "tables" in result and len(result["tables"]) > 0:
                    table = result["tables"][0]
                    
                    # Extract columns
                    columns = []
                    if "rows" in table and len(table["rows"]) > 0:
                        # Infer columns from first row keys
                        first_row = table["rows"][0]
                        columns = list(first_row.keys()) if isinstance(first_row, dict) else [f"Column_{i}" for i in range(len(first_row))]
                    
                    # Extract rows
                    rows = []
                    if "rows" in table:
                        for row in table["rows"]:
                            if isinstance(row, dict):
                                rows.append([row.get(col) for col in columns])
                            else:
                                rows.append(row)
                    
                    query_result = QueryResult(
                        columns=columns,
                        rows=rows,
                        row_count=len(rows),
                        query_type=QueryType.SELECT,
                        execution_time_ms=0,  # Not provided by Power BI API
                        metadata={"source": "sql_analytics", "workspace_id": self.workspace_id}
                    )
                    
                    log_operation(logger, "sql_query_executed", row_count=len(rows), column_count=len(columns))
                    return query_result
            
            # Handle empty result
            return QueryResult(
                columns=[],
                rows=[],
                row_count=0,
                query_type=QueryType.SELECT,
                execution_time_ms=0,
                metadata={"source": "sql_analytics", "workspace_id": self.workspace_id}
            )
    
    @handle_fabric_error(operation="get_tables_sql", resource="sql_analytics")
    def get_tables(self) -> List[TableInfo]:
        """
        Get list of tables using SQL Analytics.
        
        Returns:
            List of TableInfo objects
        """
        with OperationLogger(logger, "get_tables_sql_analytics"):
            # Query to get table information
            query = """
            SELECT 
                TABLE_SCHEMA as schema_name,
                TABLE_NAME as table_name,
                TABLE_TYPE as table_type
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_TYPE IN ('BASE TABLE', 'VIEW')
            ORDER BY TABLE_SCHEMA, TABLE_NAME
            """
            
            result = self.execute_sql(query)
            
            tables = []
            for row in result.rows:
                if len(row) >= 3:
                    schema_name = row[0] or "dbo"
                    table_name = row[1]
                    table_type_str = row[2] or "BASE TABLE"
                    
                    # Map table type
                    table_type = TableType.VIEW if table_type_str == "VIEW" else TableType.TABLE
                    
                    table_info = TableInfo(
                        name=table_name,
                        schema_name=schema_name,
                        table_type=table_type,
                        description=None,  # Not available from INFORMATION_SCHEMA
                    )
                    tables.append(table_info)
            
            log_operation(logger, "tables_retrieved_sql", count=len(tables))
            return tables
    
    @handle_fabric_error(operation="get_table_schema_sql", resource="sql_analytics")
    def get_table_schema(self, table_name: str, schema_name: str = "dbo") -> TableSchema:
        """
        Get table schema using SQL Analytics.
        
        Args:
            table_name: Name of the table
            schema_name: Schema name (default: "dbo")
            
        Returns:
            TableSchema object
        """
        with OperationLogger(logger, "get_table_schema_sql", table_name=table_name, schema_name=schema_name):
            # Query to get column information
            query = f"""
            SELECT 
                COLUMN_NAME,
                DATA_TYPE,
                IS_NULLABLE,
                COLUMN_DEFAULT,
                CHARACTER_MAXIMUM_LENGTH,
                NUMERIC_PRECISION,
                NUMERIC_SCALE,
                ORDINAL_POSITION
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = '{schema_name}' AND TABLE_NAME = '{table_name}'
            ORDER BY ORDINAL_POSITION
            """
            
            result = self.execute_sql(query)
            
            columns = []
            for row in result.rows:
                if len(row) >= 8:
                    column_info = ColumnInfo(
                        name=row[0],
                        data_type=row[1],
                        nullable=row[2] == "YES",
                        default_value=row[3],
                        max_length=row[4],
                        precision=row[5],
                        scale=row[6],
                        ordinal_position=row[7]
                    )
                    columns.append(column_info)
            
            table_schema = TableSchema(
                table_name=table_name,
                schema_name=schema_name,
                columns=columns,
                indexes=[],  # Would need separate query for indexes
                constraints=[],  # Would need separate query for constraints
                row_count=None  # Would need separate query for row count
            )
            
            log_operation(logger, "table_schema_retrieved_sql", column_count=len(columns))
            return table_schema
    
    @handle_fabric_error(operation="test_connection_sql", resource="sql_analytics")
    def test_connection(self) -> bool:
        """
        Test connection to SQL Analytics endpoint.
        
        Returns:
            True if connection is successful
        """
        with OperationLogger(logger, "test_connection_sql_analytics"):
            try:
                # Simple test query
                result = self.execute_sql("SELECT 1 as test_connection")
                
                if result.row_count > 0 and len(result.rows) > 0:
                    log_operation(logger, "sql_analytics_connection_test_successful")
                    return True
                else:
                    raise ExecutionError("Test query returned no results")
                    
            except Exception as e:
                log_operation(logger, "sql_analytics_connection_test_failed", error=str(e))
                raise e