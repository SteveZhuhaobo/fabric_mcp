"""SQL Analytics Endpoint client for Microsoft Fabric Lakehouse using TDS protocol."""

import time
from typing import Any, Dict, List, Optional
import pyodbc
import struct

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


class SQLEndpointClient:
    """Client for SQL Analytics Endpoint using TDS protocol."""
    
    # Fabric API endpoints
    FABRIC_API_BASE = "https://api.fabric.microsoft.com/v1"
    
    # Required scopes for Fabric API access
    FABRIC_SCOPE = "https://analysis.windows.net/powerbi/api/.default"
    
    def __init__(
        self,
        workspace_id: str,
        lakehouse_id: str,
        credentials: TokenCredential,
        query_config: Optional[QueryExecutionConfig] = None,
    ):
        """
        Initialize the SQL Endpoint client.
        
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
        
        # Cache for SQL endpoint properties
        self._sql_endpoint_info = None
        self._connection = None
        
        log_operation(
            logger, 
            "sql_endpoint_client_initialized",
            workspace_id=workspace_id[:8] + "...",
            lakehouse_id=lakehouse_id[:8] + "..."
        )
    
    def _get_access_token(self) -> str:
        """Get access token for Fabric API."""
        try:
            token = self.credentials.get_token(self.FABRIC_SCOPE)
            return token.token
        except Exception as e:
            context = ErrorContext(operation="get_access_token")
            auth_error = AuthenticationError(
                message="Failed to get Fabric access token",
                context=context,
                cause=e
            )
            log_error(logger, auth_error, operation="get_access_token")
            raise auth_error
    
    def _get_sql_endpoint_info(self) -> Dict[str, Any]:
        """Get SQL endpoint connection information from lakehouse properties."""
        if self._sql_endpoint_info:
            return self._sql_endpoint_info
        
        try:
            import requests
            
            # Get lakehouse details including SQL endpoint properties
            access_token = self._get_access_token()
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            url = f"{self.FABRIC_API_BASE}/workspaces/{self.workspace_id}/lakehouses/{self.lakehouse_id}"
            
            log_operation(logger, "fetching_sql_endpoint_info", url=url, level="debug")
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                lakehouse_data = response.json()
                
                # Extract SQL endpoint properties
                properties = lakehouse_data.get("properties", {})
                sql_endpoint_props = properties.get("sqlEndpointProperties", {})
                
                if sql_endpoint_props:
                    connection_string = sql_endpoint_props.get("connectionString", "")
                    endpoint_id = sql_endpoint_props.get("id", "")
                    provisioning_status = sql_endpoint_props.get("provisioningStatus", "")
                    
                    if provisioning_status == "Success" and connection_string:
                        self._sql_endpoint_info = {
                            "connection_string": connection_string,
                            "endpoint_id": endpoint_id,
                            "status": provisioning_status
                        }
                        
                        log_operation(
                            logger, 
                            "sql_endpoint_discovered", 
                            connection_string=connection_string[:50] + "...",
                            status=provisioning_status,
                            level="debug"
                        )
                        
                        return self._sql_endpoint_info
                    else:
                        raise ExecutionError(f"SQL endpoint not ready. Status: {provisioning_status}")
                else:
                    raise ExecutionError("No SQL endpoint properties found in lakehouse")
            else:
                raise ExecutionError(f"Failed to get lakehouse info: HTTP {response.status_code}")
                
        except Exception as e:
            context = ErrorContext(operation="get_sql_endpoint_info")
            error = ExecutionError(
                message=f"Failed to get SQL endpoint info: {str(e)}",
                context=context,
                cause=e
            )
            log_error(logger, error, operation="get_sql_endpoint_info")
            raise error
    
    def _get_connection(self):
        """Get or create SQL connection to the lakehouse endpoint."""
        if self._connection:
            try:
                # Test if connection is still alive
                cursor = self._connection.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()
                return self._connection
            except:
                # Connection is dead, create new one
                self._connection = None
        
        try:
            # Get SQL endpoint info
            endpoint_info = self._get_sql_endpoint_info()
            connection_string = endpoint_info["connection_string"]
            
            # Get access token for SQL authentication
            access_token = self._get_access_token()
            
            # Build ODBC connection string for Fabric SQL endpoint with token authentication
            server = connection_string
            
            # Remove any protocol prefix if present
            if "://" in server:
                server = server.split("://")[1]
            
            # Get access token for SQL authentication
            access_token = self._get_access_token()
            
            # Build connection string for token-based authentication
            conn_str = (
                f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                f"SERVER={server};"
                f"Encrypt=yes;"
                f"TrustServerCertificate=no;"
                f"Connection Timeout=30;"
            )
            
            log_operation(logger, "connecting_to_sql_endpoint", server=server[:50] + "...", level="debug")
            
            # Create connection using access token
            # Convert token to bytes for ODBC
            token_bytes = access_token.encode('utf-16-le')
            token_struct = struct.pack('<I', len(token_bytes)) + token_bytes
            
            # Set the token as a connection attribute
            connection = pyodbc.connect(conn_str, attrs_before={1256: token_struct})
            
            self._connection = connection
            
            log_operation(logger, "sql_endpoint_connected", level="debug")
            return connection
            
        except Exception as e:
            context = ErrorContext(operation="get_sql_connection")
            error = ConnectionError(
                message=f"Failed to connect to SQL endpoint: {str(e)}",
                context=context,
                cause=e
            )
            log_error(logger, error, operation="get_sql_connection")
            raise error
    
    @handle_fabric_error(operation="execute_sql", resource="sql_endpoint")
    def execute_sql(self, query: str) -> QueryResult:
        """
        Execute SQL query via SQL Analytics Endpoint.
        
        Args:
            query: SQL query to execute
            
        Returns:
            QueryResult object with query results
            
        Raises:
            Various FabricMCPError subclasses: If the query fails
        """
        with OperationLogger(logger, "execute_sql_endpoint", query_preview=query[:100] + "..."):
            start_time = time.time()
            
            try:
                connection = self._get_connection()
                cursor = connection.cursor()
                
                # Execute query
                cursor.execute(query)
                
                # Get column information
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                
                # Fetch results
                rows = []
                if cursor.description:  # SELECT query
                    rows = cursor.fetchall()
                    # Convert pyodbc.Row to list
                    rows = [list(row) for row in rows]
                
                cursor.close()
                
                execution_time_ms = (time.time() - start_time) * 1000
                
                # Determine query type
                query_upper = query.strip().upper()
                if query_upper.startswith("SELECT"):
                    query_type = QueryType.SELECT
                elif query_upper.startswith("INSERT"):
                    query_type = QueryType.INSERT
                elif query_upper.startswith("UPDATE"):
                    query_type = QueryType.UPDATE
                elif query_upper.startswith("DELETE"):
                    query_type = QueryType.DELETE
                else:
                    query_type = QueryType.UNKNOWN
                
                query_result = QueryResult(
                    columns=columns,
                    rows=rows,
                    row_count=len(rows),
                    query_type=query_type,
                    execution_time_ms=execution_time_ms
                )
                
                log_operation(
                    logger, 
                    "sql_query_executed", 
                    row_count=len(rows), 
                    column_count=len(columns),
                    execution_time_ms=execution_time_ms
                )
                
                return query_result
                
            except Exception as e:
                execution_time_ms = (time.time() - start_time) * 1000
                log_operation(
                    logger, 
                    "sql_query_failed", 
                    error=str(e),
                    execution_time_ms=execution_time_ms,
                    level="error"
                )
                raise e
    
    @handle_fabric_error(operation="get_tables_sql", resource="sql_endpoint")
    def get_tables(self) -> List[TableInfo]:
        """
        Get list of tables using SQL Analytics Endpoint.
        
        Returns:
            List of TableInfo objects
        """
        with OperationLogger(logger, "get_tables_sql_endpoint"):
            # Query to get table information from lakehouse
            query = """
            SELECT 
                SCHEMA_NAME(t.schema_id) as schema_name,
                t.name as table_name,
                CASE 
                    WHEN t.type = 'U' THEN 'BASE TABLE'
                    WHEN t.type = 'V' THEN 'VIEW'
                    ELSE 'TABLE'
                END as table_type
            FROM sys.tables t
            WHERE t.is_ms_shipped = 0
            UNION ALL
            SELECT 
                SCHEMA_NAME(v.schema_id) as schema_name,
                v.name as table_name,
                'VIEW' as table_type
            FROM sys.views v
            WHERE v.is_ms_shipped = 0
            ORDER BY schema_name, table_name
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
                        description=None,  # Could be enhanced with extended properties
                    )
                    tables.append(table_info)
            
            log_operation(logger, "tables_retrieved_sql_endpoint", count=len(tables))
            return tables
    
    @handle_fabric_error(operation="get_table_schema_sql", resource="sql_endpoint")
    def get_table_schema(self, table_name: str, schema_name: str = "dbo") -> TableSchema:
        """
        Get table schema using SQL Analytics Endpoint.
        
        Args:
            table_name: Name of the table
            schema_name: Schema name (default: "dbo")
            
        Returns:
            TableSchema object
        """
        with OperationLogger(logger, "get_table_schema_sql_endpoint", table_name=table_name, schema_name=schema_name):
            # Query to get column information
            query = f"""
            SELECT 
                c.COLUMN_NAME,
                c.DATA_TYPE,
                c.IS_NULLABLE,
                c.COLUMN_DEFAULT,
                c.CHARACTER_MAXIMUM_LENGTH,
                c.NUMERIC_PRECISION,
                c.NUMERIC_SCALE,
                c.ORDINAL_POSITION
            FROM INFORMATION_SCHEMA.COLUMNS c
            WHERE c.TABLE_SCHEMA = '{schema_name}' AND c.TABLE_NAME = '{table_name}'
            ORDER BY c.ORDINAL_POSITION
            """
            
            result = self.execute_sql(query)
            
            if not result.rows:
                raise ExecutionError(f"Table '{schema_name}.{table_name}' not found")
            
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
                indexes=[],  # Could be enhanced with index information
                constraints=[],  # Could be enhanced with constraint information
                row_count=None  # Could be enhanced with row count
            )
            
            log_operation(logger, "table_schema_retrieved_sql_endpoint", column_count=len(columns))
            return table_schema
    
    @handle_fabric_error(operation="test_connection_sql", resource="sql_endpoint")
    def test_connection(self) -> bool:
        """
        Test connection to SQL Analytics endpoint.
        
        Returns:
            True if connection is successful
        """
        with OperationLogger(logger, "test_connection_sql_endpoint"):
            try:
                # Simple test query
                result = self.execute_sql("SELECT 1 as test_connection")
                
                if result.row_count > 0 and len(result.rows) > 0:
                    log_operation(logger, "sql_endpoint_connection_test_successful")
                    return True
                else:
                    raise ExecutionError("Test query returned no results")
                    
            except Exception as e:
                log_operation(logger, "sql_endpoint_connection_test_failed", error=str(e))
                raise e
    
    def close(self):
        """Close the SQL connection."""
        if self._connection:
            try:
                self._connection.close()
                self._connection = None
                log_operation(logger, "sql_endpoint_connection_closed", level="debug")
            except Exception as e:
                log_operation(logger, "sql_endpoint_connection_close_failed", error=str(e), level="debug")