"""Integration tests for MCP tools."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
from typing import List, Dict, Any

from mcp import types
from mcp.server.fastmcp.exceptions import ToolError

from fabric_lakehouse_mcp.tools.mcp_tools import (
    app,
    initialize_client,
    list_tables,
    describe_table,
    execute_query,
)
from fabric_lakehouse_mcp.client.fabric_client import FabricLakehouseClient
from fabric_lakehouse_mcp.errors import ExecutionError, ValidationError
from fabric_lakehouse_mcp.models.data_models import (
    TableInfo,
    TableSchema,
    ColumnInfo,
    IndexInfo,
    QueryResult,
    TableType,
    QueryType,
)


class TestMCPToolsIntegration:
    """Integration tests for MCP tools with mock Fabric responses."""
    
    @pytest.fixture
    def mock_fabric_client(self):
        """Create a mock Fabric client for testing."""
        client = Mock(spec=FabricLakehouseClient)
        return client
    
    @pytest.fixture
    def sample_tables(self):
        """Sample table data for testing."""
        return [
            TableInfo(
                name="customers",
                schema_name="dbo",
                table_type=TableType.TABLE,
                created_date=datetime(2024, 1, 1),
                row_count=1000,
                description="Customer information table"
            ),
            TableInfo(
                name="orders",
                schema_name="dbo",
                table_type=TableType.TABLE,
                created_date=datetime(2024, 1, 2),
                row_count=5000,
                description="Order transactions"
            ),
            TableInfo(
                name="products_view",
                schema_name="analytics",
                table_type=TableType.VIEW,
                description="Product analytics view"
            )
        ]
    
    @pytest.fixture
    def sample_table_schema(self):
        """Sample table schema for testing."""
        columns = [
            ColumnInfo(
                name="id",
                data_type="BIGINT",
                is_nullable=False,
                ordinal_position=1,
                description="Primary key"
            ),
            ColumnInfo(
                name="name",
                data_type="VARCHAR(255)",
                is_nullable=False,
                ordinal_position=2,
                description="Customer name"
            ),
            ColumnInfo(
                name="email",
                data_type="VARCHAR(255)",
                is_nullable=True,
                ordinal_position=3,
                description="Email address"
            ),
            ColumnInfo(
                name="created_at",
                data_type="DATETIME2",
                is_nullable=False,
                default_value="GETDATE()",
                ordinal_position=4,
                description="Creation timestamp"
            )
        ]
        
        indexes = [
            IndexInfo(
                name="PK_customers",
                columns=["id"],
                is_unique=True,
                is_primary=True
            ),
            IndexInfo(
                name="IX_customers_email",
                columns=["email"],
                is_unique=True,
                is_primary=False
            )
        ]
        
        return TableSchema(
            table_name="customers",
            schema_name="dbo",
            columns=columns,
            primary_keys=["id"],
            indexes=indexes
        )
    
    @pytest.fixture
    def sample_query_result(self):
        """Sample query result for testing."""
        return QueryResult(
            columns=["id", "name", "email"],
            rows=[
                [1, "John Doe", "john@example.com"],
                [2, "Jane Smith", "jane@example.com"],
                [3, "Bob Johnson", "bob@example.com"]
            ],
            row_count=3,
            execution_time_ms=150,
            query_type=QueryType.SELECT
        )
    
    def setup_method(self):
        """Set up test environment before each test."""
        # Reset the global client
        import fabric_lakehouse_mcp.tools.mcp_tools as tools_module
        tools_module._fabric_client = None


class TestListTables(TestMCPToolsIntegration):
    """Test list_tables tool."""
    
    def test_list_tables_success(self, mock_fabric_client, sample_tables):
        """Test successful table listing."""
        # Setup mock
        mock_fabric_client.get_tables.return_value = sample_tables
        initialize_client(mock_fabric_client)
        
        # Execute tool
        result = list_tables()
        
        # Verify results
        assert isinstance(result, list)
        assert len(result) == 3
        
        # Check first table
        table1 = result[0]
        assert table1["name"] == "customers"
        assert table1["schema_name"] == "dbo"
        assert table1["table_type"] == "TABLE"
        assert table1["description"] == "Customer information table"
        assert table1["row_count"] == 1000
        assert "created_date" in table1
        
        # Check view table
        table3 = result[2]
        assert table3["name"] == "products_view"
        assert table3["table_type"] == "VIEW"
        assert table3["schema_name"] == "analytics"
        
        # Verify client was called
        mock_fabric_client.get_tables.assert_called_once()
    
    def test_list_tables_fabric_api_error(self, mock_fabric_client):
        """Test list_tables with Fabric API error."""
        # Setup mock to raise error
        mock_fabric_client.get_tables.side_effect = ExecutionError("Connection failed", status_code=500)
        initialize_client(mock_fabric_client)
        
        # Execute tool and expect error
        with pytest.raises(ToolError) as exc_info:
            list_tables()
        
        assert exc_info.value.args[0] == "FABRIC_ERROR"
        assert "Failed to list tables" in exc_info.value.args[1]
        assert exc_info.value.args[2]["error_type"] == "connection"
    
    def test_list_tables_client_not_initialized(self):
        """Test list_tables without initialized client."""
        with pytest.raises(ToolError) as exc_info:
            list_tables()
        
        assert exc_info.value.args[0] == "INTERNAL_ERROR"
        assert "Fabric client not initialized" in exc_info.value.args[1]


class TestDescribeTable(TestMCPToolsIntegration):
    """Test describe_table tool."""
    
    def test_describe_table_success(self, mock_fabric_client, sample_table_schema):
        """Test successful table description."""
        # Setup mock
        mock_fabric_client.get_table_schema.return_value = sample_table_schema
        initialize_client(mock_fabric_client)
        
        # Execute tool
        result = describe_table("customers")
        
        # Verify results
        assert isinstance(result, dict)
        assert result["table_name"] == "customers"
        assert result["schema_name"] == "dbo"
        assert result["primary_keys"] == ["id"]
        
        # Check columns
        assert len(result["columns"]) == 4
        id_column = result["columns"][0]
        assert id_column["name"] == "id"
        assert id_column["data_type"] == "BIGINT"
        assert id_column["is_nullable"] is False
        assert id_column["ordinal_position"] == 1
        assert id_column["description"] == "Primary key"
        
        # Check indexes
        assert len(result["indexes"]) == 2
        pk_index = result["indexes"][0]
        assert pk_index["name"] == "PK_customers"
        assert pk_index["is_primary"] is True
        assert pk_index["columns"] == ["id"]
        
        # Verify client was called
        mock_fabric_client.get_table_schema.assert_called_once_with("customers")
    
    def test_describe_table_empty_name(self, mock_fabric_client):
        """Test describe_table with empty table name."""
        initialize_client(mock_fabric_client)
        
        with pytest.raises(ToolError) as exc_info:
            describe_table("")
        
        assert exc_info.value.args[0] == "INVALID_PARAMS"
        assert "Table name cannot be empty" in exc_info.value.args[1]
    
    def test_describe_table_not_found(self, mock_fabric_client):
        """Test describe_table with non-existent table."""
        # Setup mock to raise 404 error
        mock_fabric_client.get_table_schema.side_effect = ExecutionError("Table not found", status_code=404)
        initialize_client(mock_fabric_client)
        
        with pytest.raises(ToolError) as exc_info:
            describe_table("nonexistent_table")
        
        assert exc_info.value.args[0] == "FABRIC_ERROR"
        assert "Table 'nonexistent_table' not found" in exc_info.value.args[1]
        assert exc_info.value.args[2]["error_type"] == "validation"



class TestExecuteQuery(TestMCPToolsIntegration):
    """Test execute_query tool."""
    
    def test_execute_query_select_success(self, mock_fabric_client, sample_query_result):
        """Test successful SELECT query execution."""
        # Setup mock
        mock_fabric_client.execute_sql.return_value = sample_query_result
        initialize_client(mock_fabric_client)
        
        # Execute tool
        result = execute_query("SELECT * FROM customers LIMIT 3")
        
        # Verify results
        assert isinstance(result, dict)
        assert result["query_type"] == "SELECT"
        assert result["success"] is True
        assert result["execution_time_ms"] == 150
        assert result["row_count"] == 3
        assert result["truncated"] is False
        
        # Check data
        assert result["columns"] == ["id", "name", "email"]
        assert len(result["rows"]) == 3
        assert result["rows"][0] == [1, "John Doe", "john@example.com"]
        
        # Verify client was called
        mock_fabric_client.execute_sql.assert_called_once_with("SELECT * FROM customers LIMIT 3", None)
    
    def test_execute_query_with_limit(self, mock_fabric_client, sample_query_result):
        """Test SELECT query with limit parameter."""
        # Modify sample result to simulate truncation
        sample_query_result.row_count = 100
        mock_fabric_client.execute_sql.return_value = sample_query_result
        initialize_client(mock_fabric_client)
        
        # Execute tool with limit
        result = execute_query("SELECT * FROM customers", limit=100)
        
        # Verify results
        assert result["row_count"] == 100
        assert result["truncated"] is True
        assert "limited to 100 rows" in result["message"]
        
        # Verify client was called with limit
        mock_fabric_client.execute_sql.assert_called_once_with("SELECT * FROM customers", 100)
    
    def test_execute_query_insert_success(self, mock_fabric_client):
        """Test successful INSERT query execution."""
        # Setup mock for INSERT query
        insert_result = QueryResult(
            columns=[],
            rows=[],
            row_count=0,
            execution_time_ms=75,
            query_type=QueryType.INSERT,
            affected_rows=1
        )
        mock_fabric_client.execute_sql.return_value = insert_result
        initialize_client(mock_fabric_client)
        
        # Execute tool
        result = execute_query("INSERT INTO customers (name, email) VALUES ('Test User', 'test@example.com')")
        
        # Verify results
        assert result["query_type"] == "INSERT"
        assert result["success"] is True
        assert result["affected_rows"] == 1
        assert "INSERT query executed successfully" in result["message"]
        assert "1 rows affected" in result["message"]
    
    def test_execute_query_empty_query(self, mock_fabric_client):
        """Test execute_query with empty query."""
        initialize_client(mock_fabric_client)
        
        with pytest.raises(ToolError) as exc_info:
            execute_query("")
        
        assert exc_info.value.args[0] == "INVALID_PARAMS"
        assert "Query cannot be empty" in exc_info.value.args[1]
    
    def test_execute_query_invalid_limit(self, mock_fabric_client):
        """Test execute_query with invalid limit."""
        initialize_client(mock_fabric_client)
        
        with pytest.raises(ToolError) as exc_info:
            execute_query("SELECT * FROM customers", limit=-1)
        
        assert exc_info.value.args[0] == "INVALID_PARAMS"
        assert "Limit must be a positive integer" in exc_info.value.args[1]
    
    def test_execute_query_limit_too_large(self, mock_fabric_client):
        """Test execute_query with limit too large."""
        initialize_client(mock_fabric_client)
        
        with pytest.raises(ToolError) as exc_info:
            execute_query("SELECT * FROM customers", limit=20000)
        
        assert exc_info.value.args[0] == "INVALID_PARAMS"
        assert "Limit cannot exceed 10,000 rows" in exc_info.value.args[1]
    
    def test_execute_query_sql_injection_prevention(self, mock_fabric_client):
        """Test execute_query with potentially dangerous SQL."""
        initialize_client(mock_fabric_client)
        
        dangerous_query = "SELECT * FROM customers; DROP TABLE customers;"
        
        with pytest.raises(ToolError) as exc_info:
            execute_query(dangerous_query)
        
        assert exc_info.value.args[0] == "INVALID_PARAMS"
        assert "Query validation error" in exc_info.value.args[1]


class TestMCPProtocolCompliance(TestMCPToolsIntegration):
    """Test MCP protocol compliance and error handling."""
    
    def test_error_format_compliance(self, mock_fabric_client):
        """Test that errors follow MCP error format."""
        mock_fabric_client.get_tables.side_effect = ExecutionError("API Error", status_code=500, fabric_error_code="FABRIC_500")
        initialize_client(mock_fabric_client)
        
        with pytest.raises(ToolError) as exc_info:
            list_tables()
        
        error = exc_info.value
        
        # Verify MCP error structure
        assert len(error.args) >= 2
        assert error.args[0] == "FABRIC_ERROR"  # code
        assert "Failed to list tables" in error.args[1]  # message
        assert len(error.args) >= 3 and isinstance(error.args[2], dict)  # data
        
        # Verify error data structure
        assert isinstance(error.args[2], dict)
        assert "error_type" in error.args[2]
        assert error.args[2]["error_type"] in ["authentication", "connection", "permission", "validation", "execution"]
    
    def test_tool_parameter_validation(self, mock_fabric_client):
        """Test that tools properly validate parameters."""
        initialize_client(mock_fabric_client)
        
        # Test various invalid parameter scenarios
        test_cases = [
            (lambda: describe_table(None), "INVALID_PARAMS"),
            (lambda: describe_table(""), "INVALID_PARAMS"),
            (lambda: create_table("", []), "INVALID_PARAMS"),
            (lambda: execute_query(""), "INVALID_PARAMS"),
            (lambda: execute_query("SELECT 1", limit=0), "INVALID_PARAMS"),
        ]
        
        for test_func, expected_code in test_cases:
            with pytest.raises(ToolError) as exc_info:
                test_func()
            assert exc_info.value.args[0] == expected_code
    
    def test_tool_return_types(self, mock_fabric_client, sample_tables, sample_table_schema, sample_query_result):
        """Test that tools return correct data types."""
        # Setup mocks
        mock_fabric_client.get_tables.return_value = sample_tables
        mock_fabric_client.get_table_schema.return_value = sample_table_schema
        mock_fabric_client.execute_sql.return_value = sample_query_result
        initialize_client(mock_fabric_client)
        
        # Test return types
        tables_result = list_tables()
        assert isinstance(tables_result, list)
        assert all(isinstance(table, dict) for table in tables_result)
        
        describe_result = describe_table("customers")
        assert isinstance(describe_result, dict)
        assert "table_name" in describe_result
        assert "columns" in describe_result
        
        create_result = create_table("test", [{"name": "id", "data_type": "INT"}])
        assert isinstance(create_result, dict)
        assert "success" in create_result
        
        query_result = execute_query("SELECT 1")
        assert isinstance(query_result, dict)
        assert "query_type" in query_result
        assert "success" in query_result