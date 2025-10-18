"""Data models for Fabric Lakehouse MCP server."""

from .data_models import (
    TableInfo,
    TableSchema,
    ColumnInfo,
    IndexInfo,
    TableDefinition,
    ColumnDefinition,
    QueryResult,
    TableType,
    QueryType,
    QueryExecutionConfig,
    PaginationInfo,
)

__all__ = [
    "TableInfo",
    "TableSchema", 
    "ColumnInfo",
    "IndexInfo",
    "TableDefinition",
    "ColumnDefinition",
    "QueryResult",
    "TableType",
    "QueryType",
    "QueryExecutionConfig",
    "PaginationInfo",
]