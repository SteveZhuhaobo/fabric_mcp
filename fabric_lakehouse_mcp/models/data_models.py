"""Data models for Fabric Lakehouse operations."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Optional, Dict
from enum import Enum
import re


class TableType(Enum):
    """Supported table types in Fabric Lakehouse."""
    TABLE = "TABLE"
    VIEW = "VIEW"
    EXTERNAL = "EXTERNAL"


class QueryType(Enum):
    """SQL query types."""
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    CREATE = "CREATE"
    DROP = "DROP"
    ALTER = "ALTER"
    UNKNOWN = "UNKNOWN"


@dataclass
class TableInfo:
    """Information about a table in the Lakehouse."""
    name: str
    schema_name: str
    table_type: TableType
    created_date: Optional[datetime] = None
    row_count: Optional[int] = None
    description: Optional[str] = None


@dataclass
class ColumnInfo:
    """Information about a table column."""
    name: str
    data_type: str
    is_nullable: bool
    default_value: Optional[str] = None
    description: Optional[str] = None
    ordinal_position: Optional[int] = None


@dataclass
class IndexInfo:
    """Information about a table index."""
    name: str
    columns: List[str]
    is_unique: bool
    is_primary: bool = False


@dataclass
class TableSchema:
    """Complete schema information for a table."""
    table_name: str
    schema_name: str
    columns: List[ColumnInfo]
    primary_keys: List[str]
    indexes: List[IndexInfo]


@dataclass
class ColumnDefinition:
    """Definition for creating a new column."""
    name: str
    data_type: str
    nullable: bool = True
    description: Optional[str] = None




@dataclass
class QueryResult:
    """Result of a SQL query execution."""
    columns: List[str]
    rows: List[List[Any]]
    row_count: int
    execution_time_ms: int
    query_type: QueryType
    affected_rows: Optional[int] = None  # For INSERT/UPDATE/DELETE
    has_more_rows: bool = False  # Indicates if there are more rows available
    total_row_count: Optional[int] = None  # Total rows in result set (if known)
    page_info: Optional['PaginationInfo'] = None  # Pagination information


@dataclass
class PaginationInfo:
    """Information about result pagination."""
    page_size: int
    current_page: int
    total_pages: Optional[int] = None
    has_next_page: bool = False
    has_previous_page: bool = False
    next_page_token: Optional[str] = None


@dataclass
class QueryExecutionConfig:
    """Configuration for query execution."""
    timeout_seconds: int = 300
    max_result_rows: int = 10000
    page_size: int = 1000
    enable_pagination: bool = True
    format_results: bool = True
    include_metadata: bool = True


class ErrorType(Enum):
    """Categories of errors that can occur."""
    AUTHENTICATION = "authentication"
    CONNECTION = "connection"
    PERMISSION = "permission"
    VALIDATION = "validation"
    EXECUTION = "execution"


@dataclass
class MCPError:
    """MCP-compliant error response model."""
    code: str
    message: str
    data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format for MCP response."""
        error_dict = {
            "code": self.code,
            "message": self.message
        }
        if self.data:
            error_dict["data"] = self.data
        return {"error": error_dict}


@dataclass
class FabricError:
    """Detailed error information from Fabric operations."""
    error_type: ErrorType
    fabric_error_code: Optional[str] = None
    details: Optional[str] = None
    
    def to_mcp_error(self, message: str, code: str = "FABRIC_ERROR") -> MCPError:
        """Convert to MCP error format."""
        data = {
            "error_type": self.error_type.value,
        }
        if self.fabric_error_code:
            data["fabric_error_code"] = self.fabric_error_code
        if self.details:
            data["details"] = self.details
            
        return MCPError(
            code=code,
            message=message,
            data=data
        )


class ValidationError(Exception):
    """Exception raised when validation fails."""
    def __init__(self, message: str, field: Optional[str] = None):
        self.message = message
        self.field = field
        super().__init__(message)


# Validation functions
def validate_table_name(name: str) -> None:
    """Validate table name according to SQL standards."""
    if not name:
        raise ValidationError("Table name cannot be empty")
    
    if len(name) > 128:
        raise ValidationError("Table name cannot exceed 128 characters")
    
    # Check for valid SQL identifier pattern
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        raise ValidationError(
            "Table name must start with a letter or underscore and contain only letters, numbers, and underscores"
        )
    
    # Check for reserved keywords (basic set)
    reserved_keywords = {
        'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP',
        'ALTER', 'TABLE', 'INDEX', 'VIEW', 'DATABASE', 'SCHEMA', 'PRIMARY', 'KEY',
        'FOREIGN', 'REFERENCES', 'CONSTRAINT', 'UNIQUE', 'NOT', 'NULL', 'DEFAULT'
    }
    
    if name.upper() in reserved_keywords:
        raise ValidationError(f"'{name}' is a reserved keyword and cannot be used as a table name")


def validate_column_name(name: str) -> None:
    """Validate column name according to SQL standards."""
    if not name:
        raise ValidationError("Column name cannot be empty")
    
    if len(name) > 128:
        raise ValidationError("Column name cannot exceed 128 characters")
    
    # Check for valid SQL identifier pattern
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        raise ValidationError(
            "Column name must start with a letter or underscore and contain only letters, numbers, and underscores"
        )


def validate_data_type(data_type: str) -> None:
    """Validate SQL data type."""
    if not data_type:
        raise ValidationError("Data type cannot be empty")
    
    # Supported Fabric Lakehouse data types
    valid_types = {
        'BIGINT', 'INT', 'SMALLINT', 'TINYINT',
        'DECIMAL', 'NUMERIC', 'FLOAT', 'REAL', 'DOUBLE',
        'VARCHAR', 'CHAR', 'NVARCHAR', 'NCHAR', 'TEXT', 'STRING',
        'DATE', 'DATETIME', 'DATETIME2', 'TIME', 'TIMESTAMP',
        'BOOLEAN', 'BIT',
        'BINARY', 'VARBINARY',
        'ARRAY', 'MAP', 'STRUCT'
    }
    
    # Extract base type (handle types like VARCHAR(255))
    base_type = data_type.split('(')[0].upper().strip()
    
    if base_type not in valid_types:
        raise ValidationError(f"Unsupported data type: {data_type}")




def validate_sql_query(query: str) -> QueryType:
    """Validate SQL query and determine its type."""
    if not query or not query.strip():
        raise ValidationError("Query cannot be empty")
    
    # Remove comments and normalize whitespace
    cleaned_query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
    cleaned_query = re.sub(r'/\*.*?\*/', '', cleaned_query, flags=re.DOTALL)
    cleaned_query = cleaned_query.strip()
    
    if not cleaned_query:
        raise ValidationError("Query cannot be empty after removing comments")
    
    # Determine query type
    first_word = cleaned_query.split()[0].upper()
    
    query_type_mapping = {
        'SELECT': QueryType.SELECT,
        'INSERT': QueryType.INSERT,
        'UPDATE': QueryType.UPDATE,
        'DELETE': QueryType.DELETE,
        'CREATE': QueryType.CREATE,
        'DROP': QueryType.DROP,
        'ALTER': QueryType.ALTER
    }
    
    query_type = query_type_mapping.get(first_word, QueryType.UNKNOWN)
    
    # Enhanced SQL injection prevention - moved to security module
    # This is kept for backward compatibility but enhanced validation
    # should use the SQLValidator from the security module
    dangerous_patterns = [
        r';\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)\s+',
        r'EXEC\s*\(',
        r'EXECUTE\s*\(',
        r'xp_\w+',
        r'sp_\w+'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, cleaned_query, re.IGNORECASE):
            raise ValidationError("Query contains potentially dangerous SQL patterns")
    
    return query_type