"""Tests for data models and validation logic."""

import pytest
from datetime import datetime
from fabric_lakehouse_mcp.models.data_models import (
    TableInfo, TableSchema, QueryResult,
    MCPError, FabricError, ValidationError, ErrorType, QueryType, TableType,
    validate_table_name, validate_column_name, validate_data_type,
    validate_sql_query
)


class TestDataModels:
    """Test data model classes."""
    
    def test_table_info_creation(self):
        """Test TableInfo dataclass creation."""
        table_info = TableInfo(
            name="test_table",
            schema_name="dbo",
            table_type=TableType.TABLE,
            created_date=datetime.now(),
            row_count=100
        )
        assert table_info.name == "test_table"
        assert table_info.schema_name == "dbo"
        assert table_info.table_type == TableType.TABLE
        assert table_info.row_count == 100
    
    def test_query_result_creation(self):
        """Test QueryResult dataclass creation."""
        result = QueryResult(
            columns=["id", "name"],
            rows=[[1, "test"], [2, "test2"]],
            row_count=2,
            execution_time_ms=150,
            query_type=QueryType.SELECT
        )
        assert len(result.columns) == 2
        assert len(result.rows) == 2
        assert result.row_count == 2
        assert result.query_type == QueryType.SELECT
    
    def test_mcp_error_to_dict(self):
        """Test MCPError conversion to dictionary."""
        error = MCPError(
            code="VALIDATION_ERROR",
            message="Invalid table name",
            data={"field": "table_name"}
        )
        error_dict = error.to_dict()
        assert error_dict["error"]["code"] == "VALIDATION_ERROR"
        assert error_dict["error"]["message"] == "Invalid table name"
        assert error_dict["error"]["data"]["field"] == "table_name"
    
    def test_fabric_error_to_mcp_error(self):
        """Test FabricError conversion to MCP format."""
        fabric_error = FabricError(
            error_type=ErrorType.VALIDATION,
            fabric_error_code="FB001",
            details="Column type mismatch"
        )
        mcp_error = fabric_error.to_mcp_error("Validation failed")
        
        assert mcp_error.code == "FABRIC_ERROR"
        assert mcp_error.message == "Validation failed"
        assert mcp_error.data["error_type"] == "validation"
        assert mcp_error.data["fabric_error_code"] == "FB001"


class TestValidation:
    """Test validation functions."""
    
    def test_validate_table_name_valid(self):
        """Test valid table names."""
        valid_names = ["test_table", "Table1", "_private_table", "user_data_2024"]
        for name in valid_names:
            validate_table_name(name)  # Should not raise
    
    def test_validate_table_name_invalid(self):
        """Test invalid table names."""
        invalid_cases = [
            ("", "Table name cannot be empty"),
            ("1table", "must start with a letter or underscore"),
            ("table-name", "contain only letters, numbers, and underscores"),
            ("table name", "contain only letters, numbers, and underscores"),
            ("SELECT", "reserved keyword"),
            ("a" * 129, "cannot exceed 128 characters")
        ]
        
        for name, expected_error in invalid_cases:
            with pytest.raises(ValidationError) as exc_info:
                validate_table_name(name)
            assert expected_error in str(exc_info.value)
    
    def test_validate_column_name_valid(self):
        """Test valid column names."""
        valid_names = ["id", "user_name", "created_at", "_internal_id"]
        for name in valid_names:
            validate_column_name(name)  # Should not raise
    
    def test_validate_column_name_invalid(self):
        """Test invalid column names."""
        with pytest.raises(ValidationError):
            validate_column_name("")
        
        with pytest.raises(ValidationError):
            validate_column_name("1column")
        
        with pytest.raises(ValidationError):
            validate_column_name("column-name")
    
    def test_validate_data_type_valid(self):
        """Test valid data types."""
        valid_types = [
            "VARCHAR(255)", "INT", "BIGINT", "DECIMAL(10,2)",
            "DATETIME", "BOOLEAN", "TEXT", "DOUBLE"
        ]
        for data_type in valid_types:
            validate_data_type(data_type)  # Should not raise
    
    def test_validate_data_type_invalid(self):
        """Test invalid data types."""
        invalid_types = ["", "INVALID_TYPE", "XML", "BLOB"]
        for data_type in invalid_types:
            with pytest.raises(ValidationError):
                validate_data_type(data_type)
    

    
    def test_validate_sql_query_valid(self):
        """Test valid SQL queries."""
        queries = [
            ("SELECT * FROM users", QueryType.SELECT),
            ("INSERT INTO users (name) VALUES ('test')", QueryType.INSERT),
            ("UPDATE users SET name = 'new'", QueryType.UPDATE),
            ("DELETE FROM users WHERE id = 1", QueryType.DELETE),
            ("CREATE TABLE test (id INT)", QueryType.CREATE)
        ]
        
        for query, expected_type in queries:
            result_type = validate_sql_query(query)
            assert result_type == expected_type
    
    def test_validate_sql_query_invalid(self):
        """Test invalid SQL queries."""
        invalid_queries = [
            "",
            "   ",
            "/* comment only */",
            "SELECT * FROM users; DROP TABLE users;",  # SQL injection attempt
            "EXEC xp_cmdshell 'dir'"  # Dangerous stored procedure
        ]
        
        for query in invalid_queries:
            with pytest.raises(ValidationError):
                validate_sql_query(query)
    
    def test_validate_sql_query_with_comments(self):
        """Test SQL query validation with comments."""
        query_with_comments = """
        -- This is a comment
        SELECT id, name 
        FROM users /* inline comment */
        WHERE active = 1
        """
        result_type = validate_sql_query(query_with_comments)
        assert result_type == QueryType.SELECT