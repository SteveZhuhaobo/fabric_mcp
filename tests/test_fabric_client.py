"""Unit tests for Fabric Lakehouse API client."""

import json
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from requests.exceptions import RequestException, HTTPError
from mcp.server.fastmcp.exceptions import ToolError

from fabric_lakehouse_mcp.client import FabricLakehouseClient
from fabric_lakehouse_mcp.errors import ConnectionError, ExecutionError, AuthenticationError
from fabric_lakehouse_mcp.models import (
    TableInfo,
    TableSchema,
    ColumnInfo,
    TableDefinition,
    ColumnDefinition,
    QueryResult,
    TableType,
    QueryType,
)


@pytest.fixture
def mock_credentials():
    """Mock Azure credentials."""
    mock_cred = Mock()
    mock_token = Mock()
    mock_token.token = "test_access_token"
    mock_cred.get_token.return_value = mock_token
    return mock_cred


@pytest.fixture
def fabric_client(mock_credentials):
    """Create a FabricLakehouseClient instance for testing."""
    return FabricLakehouseClient(
        workspace_id="test_workspace_id",
        lakehouse_id="test_lakehouse_id",
        credentials=mock_credentials,
        max_retries=1,  # Reduce retries for faster tests
        retry_delay=0.1,
    )


class TestFabricLakehouseClient:
    """Test cases for FabricLakehouseClient."""
    
    def test_initialization(self, mock_credentials):
        """Test client initialization."""
        client = FabricLakehouseClient(
            workspace_id="ws123",
            lakehouse_id="lh456",
            credentials=mock_credentials,
        )
        
        assert client.workspace_id == "ws123"
        assert client.lakehouse_id == "lh456"
        assert client.credentials == mock_credentials
        assert client.max_retries == 3  # Default value
        assert client.retry_delay == 1.0  # Default value
    
    def test_get_access_token_success(self, fabric_client):
        """Test successful token retrieval."""
        token = fabric_client._get_access_token()
        assert token == "test_access_token"
        fabric_client.credentials.get_token.assert_called_once_with(
            "https://analysis.windows.net/powerbi/api/.default"
        )
    
    def test_get_access_token_failure(self, fabric_client):
        """Test token retrieval failure."""
        from azure.core.exceptions import ClientAuthenticationError
        
        fabric_client.credentials.get_token.side_effect = ClientAuthenticationError("Auth failed")
        
        with pytest.raises(AuthenticationError, match="Failed to get Fabric API access token"):
            fabric_client._get_access_token()
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.requests.Session.request')
    def test_make_request_success(self, mock_request, fabric_client):
        """Test successful API request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"test": "data"}
        mock_response.content = b'{"test": "data"}'
        mock_request.return_value = mock_response
        
        result = fabric_client._make_request("GET", "https://test.com")
        
        assert result == {"test": "data"}
        mock_request.assert_called_once()
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.requests.Session.request')
    def test_make_request_401_retry(self, mock_request, fabric_client):
        """Test 401 response triggers token refresh and retry."""
        # First call returns 401, second call succeeds
        mock_response_401 = Mock()
        mock_response_401.status_code = 401
        
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {"success": True}
        mock_response_200.content = b'{"success": true}'
        
        mock_request.side_effect = [mock_response_401, mock_response_200]
        
        result = fabric_client._make_request("GET", "https://test.com")
        
        assert result == {"success": True}
        assert mock_request.call_count == 2
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.requests.Session.request')
    @patch('fabric_lakehouse_mcp.client.fabric_client.time.sleep')
    def test_make_request_429_retry(self, mock_sleep, mock_request, fabric_client):
        """Test 429 response triggers rate limit handling."""
        # First call returns 429, second call succeeds
        mock_response_429 = Mock()
        mock_response_429.status_code = 429
        mock_response_429.headers = {"Retry-After": "2"}
        
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {"success": True}
        mock_response_200.content = b'{"success": true}'
        
        mock_request.side_effect = [mock_response_429, mock_response_200]
        
        result = fabric_client._make_request("GET", "https://test.com")
        
        assert result == {"success": True}
        mock_sleep.assert_called_once_with(2)
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.requests.Session.request')
    def test_make_request_max_retries_exceeded(self, mock_request, fabric_client):
        """Test request failure after max retries."""
        mock_request.side_effect = RequestException("Network error")
        
        with pytest.raises(ConnectionError, match="Failed to connect to Fabric API"):
            fabric_client._make_request("GET", "https://test.com")
        
        # Should retry max_retries + 1 times (1 initial + 1 retry for this test setup)
        assert mock_request.call_count == 2
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient._make_request')
    def test_get_tables_success(self, mock_request, fabric_client):
        """Test successful table listing."""
        mock_response = {
            "value": [
                {
                    "name": "customers",
                    "schema": "dbo",
                    "description": "Customer data table"
                },
                {
                    "name": "orders",
                    "schema": "sales"
                }
            ]
        }
        mock_request.return_value = mock_response
        
        tables = fabric_client.get_tables()
        
        assert len(tables) == 2
        assert tables[0].name == "customers"
        assert tables[0].schema_name == "dbo"
        assert tables[0].table_type == TableType.TABLE
        assert tables[0].description == "Customer data table"
        
        assert tables[1].name == "orders"
        assert tables[1].schema_name == "sales"
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient._make_request')
    def test_get_tables_empty_response(self, mock_request, fabric_client):
        """Test table listing with empty response."""
        mock_request.return_value = {"value": []}
        
        tables = fabric_client.get_tables()
        
        assert len(tables) == 0
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient._make_request')
    def test_get_tables_api_error(self, mock_request, fabric_client):
        """Test table listing API error."""
        mock_request.side_effect = Exception("API Error")
        
        with pytest.raises(ExecutionError):
            fabric_client.get_tables()
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient.execute_sql')
    def test_get_table_schema_success(self, mock_execute_sql, fabric_client):
        """Test successful table schema retrieval."""
        # Mock schema query result
        schema_result = QueryResult(
            columns=["COLUMN_NAME", "DATA_TYPE", "IS_NULLABLE", "COLUMN_DEFAULT", "ORDINAL_POSITION", "DESCRIPTION"],
            rows=[
                ["id", "int", "NO", None, 1, "Primary key"],
                ["name", "varchar(100)", "YES", None, 2, "Customer name"],
                ["email", "varchar(255)", "NO", None, 3, None]
            ],
            row_count=3,
            execution_time_ms=50,
            query_type=QueryType.SELECT
        )
        
        # Mock primary key query result
        pk_result = QueryResult(
            columns=["COLUMN_NAME"],
            rows=[["id"]],
            row_count=1,
            execution_time_ms=25,
            query_type=QueryType.SELECT
        )
        
        mock_execute_sql.side_effect = [schema_result, pk_result]
        
        schema = fabric_client.get_table_schema("customers")
        
        assert schema.table_name == "customers"
        assert schema.schema_name == "dbo"
        assert len(schema.columns) == 3
        assert schema.primary_keys == ["id"]
        assert len(schema.indexes) == 1
        
        # Check column details
        assert schema.columns[0].name == "id"
        assert schema.columns[0].data_type == "int"
        assert schema.columns[0].is_nullable == False
        assert schema.columns[0].description == "Primary key"
        
        assert schema.columns[1].name == "name"
        assert schema.columns[1].is_nullable == True
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient.execute_sql')
    def test_get_table_schema_table_not_found(self, mock_execute_sql, fabric_client):
        """Test table schema retrieval for non-existent table."""
        # Mock empty result
        empty_result = QueryResult(
            columns=[],
            rows=[],
            row_count=0,
            execution_time_ms=10,
            query_type=QueryType.SELECT
        )
        
        mock_execute_sql.return_value = empty_result
        
        with pytest.raises(ToolError):
            fabric_client.get_table_schema("nonexistent")
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient.execute_sql')
    def test_create_table_success(self, mock_execute_sql, fabric_client):
        """Test successful table creation."""
        table_def = TableDefinition(
            name="test_table",
            columns=[
                ColumnDefinition(name="id", data_type="int", nullable=False),
                ColumnDefinition(name="name", data_type="varchar(100)", nullable=True),
            ],
            schema_name="dbo"
        )
        
        # Mock successful execution
        mock_result = QueryResult(
            columns=[],
            rows=[],
            row_count=0,
            execution_time_ms=100,
            query_type=QueryType.CREATE
        )
        mock_execute_sql.return_value = mock_result
        
        result = fabric_client.create_table(table_def)
        
        assert result == True
        mock_execute_sql.assert_called_once()
        
        # Verify the SQL contains expected elements
        call_args = mock_execute_sql.call_args[0][0]
        assert "CREATE TABLE dbo.test_table" in call_args
        assert "id int NOT NULL" in call_args
        assert "name varchar(100) NULL" in call_args
        assert "USING DELTA" in call_args
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient.execute_sql')
    def test_create_table_failure(self, mock_execute_sql, fabric_client):
        """Test table creation failure."""
        table_def = TableDefinition(
            name="test_table",
            columns=[ColumnDefinition(name="id", data_type="int")],
        )
        
        mock_execute_sql.side_effect = Exception("Table already exists")
        
        with pytest.raises(ExecutionError):
            fabric_client.create_table(table_def)
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient._make_request')
    @patch('fabric_lakehouse_mcp.client.fabric_client.time.time')
    def test_execute_sql_select_success(self, mock_time, mock_request, fabric_client):
        """Test successful SELECT query execution."""
        mock_time.side_effect = [1000.0, 1000.5]  # 500ms execution time
        
        mock_response = {
            "results": [
                {
                    "tables": [
                        {
                            "columns": [
                                {"name": "id"},
                                {"name": "name"}
                            ],
                            "rows": [
                                [{"value": 1}, {"value": "John"}],
                                [{"value": 2}, {"value": "Jane"}]
                            ]
                        }
                    ]
                }
            ]
        }
        mock_request.return_value = mock_response
        
        result = fabric_client.execute_sql("SELECT * FROM customers")
        
        assert result.query_type == QueryType.SELECT
        assert result.columns == ["id", "name"]
        assert len(result.rows) == 2
        assert result.rows[0] == [1, "John"]
        assert result.rows[1] == [2, "Jane"]
        assert result.row_count == 2
        assert result.execution_time_ms == 500
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient._make_request')
    def test_execute_sql_non_select_success(self, mock_request, fabric_client):
        """Test successful non-SELECT query execution."""
        mock_response = {
            "results": [
                {
                    "rowCount": 5
                }
            ]
        }
        mock_request.return_value = mock_response
        
        result = fabric_client.execute_sql("INSERT INTO customers VALUES (1, 'Test')")
        
        assert result.query_type == QueryType.INSERT
        assert result.columns == []
        assert result.rows == []
        assert result.row_count == 0
        assert result.affected_rows == 5
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient._make_request')
    def test_execute_sql_with_limit(self, mock_request, fabric_client):
        """Test SELECT query with limit parameter."""
        mock_response = {
            "results": [
                {
                    "tables": [
                        {
                            "columns": [{"name": "id"}],
                            "rows": [[{"value": 1}]]
                        }
                    ]
                }
            ]
        }
        mock_request.return_value = mock_response
        
        fabric_client.execute_sql("SELECT * FROM customers", limit=10)
        
        # Verify the request was made with TOP clause
        call_args = mock_request.call_args[1]["data"]
        query = call_args["queries"][0]["query"]
        assert "SELECT TOP 10" in query
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient._make_request')
    def test_execute_sql_api_error(self, mock_request, fabric_client):
        """Test SQL execution API error."""
        mock_request.side_effect = Exception("SQL Error")
        
        with pytest.raises(ExecutionError):
            fabric_client.execute_sql("SELECT * FROM customers")
    
    def test_detect_query_type(self, fabric_client):
        """Test SQL query type detection."""
        assert fabric_client._detect_query_type("SELECT * FROM table") == QueryType.SELECT
        assert fabric_client._detect_query_type("  select id from table") == QueryType.SELECT
        assert fabric_client._detect_query_type("INSERT INTO table VALUES (1)") == QueryType.INSERT
        assert fabric_client._detect_query_type("UPDATE table SET col=1") == QueryType.UPDATE
        assert fabric_client._detect_query_type("DELETE FROM table") == QueryType.DELETE
        assert fabric_client._detect_query_type("CREATE TABLE test (id int)") == QueryType.CREATE
        assert fabric_client._detect_query_type("DROP TABLE test") == QueryType.DROP
        assert fabric_client._detect_query_type("ALTER TABLE test ADD col int") == QueryType.ALTER
        assert fabric_client._detect_query_type("UNKNOWN QUERY") == QueryType.UNKNOWN
    
    def test_extract_affected_rows(self, fabric_client):
        """Test affected rows extraction."""
        result_with_count = {"rowCount": 42}
        assert fabric_client._extract_affected_rows(result_with_count) == 42
        
        result_without_count = {"message": "Success"}
        assert fabric_client._extract_affected_rows(result_without_count) is None
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient.execute_sql')
    def test_test_connection_success(self, mock_execute_sql, fabric_client):
        """Test successful connection test."""
        mock_result = QueryResult(
            columns=["test_connection"],
            rows=[[1]],
            row_count=1,
            execution_time_ms=10,
            query_type=QueryType.SELECT
        )
        mock_execute_sql.return_value = mock_result
        
        result = fabric_client.test_connection()
        
        assert result == True
        mock_execute_sql.assert_called_once_with("SELECT 1 as test_connection")
    
    @patch('fabric_lakehouse_mcp.client.fabric_client.FabricLakehouseClient.execute_sql')
    def test_test_connection_failure(self, mock_execute_sql, fabric_client):
        """Test connection test failure."""
        mock_execute_sql.side_effect = Exception("Connection failed")
        
        with pytest.raises(ExecutionError):
            fabric_client.test_connection()


class TestErrorHandling:
    """Test cases for error handling in Fabric client."""
    
    def test_connection_error(self):
        """Test connection error creation."""
        error = ConnectionError("Test connection error")
        assert str(error) == "Test connection error"
        assert error.category.value == "connection"
        assert error.retryable is True
    
    def test_execution_error(self):
        """Test execution error creation."""
        error = ExecutionError("Test execution error", status_code=404)
        assert str(error) == "Test execution error"
        assert error.category.value == "execution"
        assert error.status_code == 404