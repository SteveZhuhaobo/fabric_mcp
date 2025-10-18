"""Query result formatting and pagination utilities."""

import math
from datetime import datetime, date
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
from dataclasses import asdict

from .data_models import QueryResult, QueryType, PaginationInfo, QueryExecutionConfig


class QueryResultFormatter:
    """Formats query results for different output types and handles pagination."""
    
    def __init__(self, config: QueryExecutionConfig):
        self.config = config
    
    def format_result(
        self, 
        result: QueryResult, 
        format_type: str = "structured",
        page: int = 1
    ) -> Dict[str, Any]:
        """
        Format query result based on the specified format type.
        
        Args:
            result: The query result to format
            format_type: Output format ('structured', 'table', 'csv', 'json')
            page: Current page number for pagination
            
        Returns:
            Formatted result dictionary
        """
        if format_type == "structured":
            return self._format_structured(result, page)
        elif format_type == "table":
            return self._format_table(result, page)
        elif format_type == "csv":
            return self._format_csv(result, page)
        elif format_type == "json":
            return self._format_json(result, page)
        else:
            # Default to structured format
            return self._format_structured(result, page)
    
    def _format_structured(self, result: QueryResult, page: int) -> Dict[str, Any]:
        """Format result in structured dictionary format."""
        formatted = {
            "query_type": result.query_type.value,
            "execution_time_ms": result.execution_time_ms,
            "success": True
        }
        
        if result.query_type == QueryType.SELECT:
            # Format SELECT query results
            formatted.update({
                "columns": self._format_columns(result.columns),
                "rows": self._format_rows(result.rows, result.columns),
                "row_count": result.row_count,
                "message": self._generate_select_message(result)
            })
            
            # Add pagination info if applicable
            if result.page_info:
                formatted["pagination"] = asdict(result.page_info)
                formatted["has_more_rows"] = result.has_more_rows
                if result.total_row_count is not None:
                    formatted["total_row_count"] = result.total_row_count
            
            # Add truncated field for backward compatibility
            formatted["truncated"] = result.has_more_rows
        else:
            # Format modification query results
            formatted.update({
                "affected_rows": result.affected_rows or 0,
                "message": self._generate_modification_message(result)
            })
        
        # Add metadata if enabled
        if self.config.include_metadata:
            formatted["metadata"] = self._generate_metadata(result)
        
        return formatted
    
    def _format_table(self, result: QueryResult, page: int) -> Dict[str, Any]:
        """Format result as a table-like structure."""
        if result.query_type != QueryType.SELECT:
            return self._format_structured(result, page)
        
        # Create table headers
        headers = [{"name": col, "type": self._infer_column_type(result.rows, i)} 
                  for i, col in enumerate(result.columns)]
        
        # Format rows with proper alignment
        formatted_rows = []
        for row in result.rows:
            formatted_row = {}
            for i, (col_name, value) in enumerate(zip(result.columns, row)):
                formatted_row[col_name] = self._format_cell_value(value)
            formatted_rows.append(formatted_row)
        
        return {
            "query_type": result.query_type.value,
            "format": "table",
            "headers": headers,
            "data": formatted_rows,
            "row_count": result.row_count,
            "execution_time_ms": result.execution_time_ms,
            "pagination": asdict(result.page_info) if result.page_info else None,
            "message": self._generate_select_message(result)
        }
    
    def _format_csv(self, result: QueryResult, page: int) -> Dict[str, Any]:
        """Format result as CSV string."""
        if result.query_type != QueryType.SELECT:
            return self._format_structured(result, page)
        
        csv_lines = []
        
        # Add header row
        csv_lines.append(",".join(f'"{col}"' for col in result.columns))
        
        # Add data rows
        for row in result.rows:
            csv_row = []
            for value in row:
                if value is None:
                    csv_row.append("")
                else:
                    # Escape quotes and wrap in quotes
                    str_value = str(value).replace('"', '""')
                    csv_row.append(f'"{str_value}"')
            csv_lines.append(",".join(csv_row))
        
        return {
            "query_type": result.query_type.value,
            "format": "csv",
            "data": "\n".join(csv_lines),
            "row_count": result.row_count,
            "execution_time_ms": result.execution_time_ms,
            "pagination": asdict(result.page_info) if result.page_info else None,
            "message": self._generate_select_message(result)
        }
    
    def _format_json(self, result: QueryResult, page: int) -> Dict[str, Any]:
        """Format result as JSON-compatible structure."""
        if result.query_type != QueryType.SELECT:
            return self._format_structured(result, page)
        
        # Convert rows to list of dictionaries
        json_data = []
        for row in result.rows:
            row_dict = {}
            for col_name, value in zip(result.columns, row):
                row_dict[col_name] = self._serialize_json_value(value)
            json_data.append(row_dict)
        
        return {
            "query_type": result.query_type.value,
            "format": "json",
            "data": json_data,
            "row_count": result.row_count,
            "execution_time_ms": result.execution_time_ms,
            "pagination": asdict(result.page_info) if result.page_info else None,
            "message": self._generate_select_message(result)
        }
    
    def _format_columns(self, columns: List[str]) -> List[str]:
        """Format column information - maintain backward compatibility."""
        return columns
    
    def _format_rows(self, rows: List[List[Any]], columns: List[str]) -> List[List[Any]]:
        """Format rows with proper value formatting - maintain backward compatibility."""
        formatted_rows = []
        for row in rows:
            formatted_row = []
            for value in row:
                formatted_row.append(self._format_cell_value(value))
            formatted_rows.append(formatted_row)
        return formatted_rows
    
    def _format_cell_value(self, value: Any) -> Any:
        """Format individual cell values."""
        if value is None:
            return None
        elif isinstance(value, (datetime, date)):
            return value.isoformat()
        elif isinstance(value, Decimal):
            return float(value)
        elif isinstance(value, bytes):
            return value.decode('utf-8', errors='replace')
        else:
            return value
    
    def _serialize_json_value(self, value: Any) -> Any:
        """Serialize value for JSON compatibility."""
        if value is None:
            return None
        elif isinstance(value, (datetime, date)):
            return value.isoformat()
        elif isinstance(value, Decimal):
            return str(value)  # Keep precision for JSON
        elif isinstance(value, bytes):
            return value.decode('utf-8', errors='replace')
        elif isinstance(value, (int, float, str, bool)):
            return value
        else:
            return str(value)
    
    def _infer_column_type(self, rows: List[List[Any]], col_index: int) -> str:
        """Infer column data type from sample values."""
        if not rows:
            return "unknown"
        
        # Sample first few non-null values
        sample_values = []
        for row in rows[:10]:  # Check first 10 rows
            if col_index < len(row) and row[col_index] is not None:
                sample_values.append(row[col_index])
                if len(sample_values) >= 3:  # Enough samples
                    break
        
        if not sample_values:
            return "null"
        
        # Determine type based on first non-null value
        first_value = sample_values[0]
        if isinstance(first_value, bool):
            return "boolean"
        elif isinstance(first_value, int):
            return "integer"
        elif isinstance(first_value, float):
            return "float"
        elif isinstance(first_value, (datetime, date)):
            return "datetime"
        elif isinstance(first_value, str):
            return "string"
        else:
            return "unknown"
    
    def _generate_select_message(self, result: QueryResult) -> str:
        """Generate message for SELECT query results."""
        base_message = f"Query executed successfully, returned {result.row_count} rows"
        
        if result.page_info:
            base_message += f" (page {result.page_info.current_page}"
            if result.page_info.total_pages:
                base_message += f" of {result.page_info.total_pages}"
            base_message += ")"
        
        if result.has_more_rows:
            base_message += " - more rows available"
        
        return base_message
    
    def _generate_modification_message(self, result: QueryResult) -> str:
        """Generate message for modification query results."""
        message = f"{result.query_type.value} query executed successfully"
        if result.affected_rows is not None:
            message += f", {result.affected_rows} rows affected"
        return message
    
    def _generate_metadata(self, result: QueryResult) -> Dict[str, Any]:
        """Generate metadata about the query execution."""
        metadata = {
            "execution_timestamp": datetime.now().isoformat(),
            "query_type": result.query_type.value,
            "execution_time_ms": result.execution_time_ms,
        }
        
        if result.query_type == QueryType.SELECT:
            metadata.update({
                "column_count": len(result.columns),
                "row_count": result.row_count,
                "has_more_rows": result.has_more_rows,
            })
            
            if result.total_row_count is not None:
                metadata["total_row_count"] = result.total_row_count
        else:
            metadata["affected_rows"] = result.affected_rows or 0
        
        return metadata


class QueryPaginator:
    """Handles pagination of query results."""
    
    def __init__(self, config: QueryExecutionConfig):
        self.config = config
    
    def create_pagination_info(
        self,
        current_page: int,
        page_size: int,
        total_rows: Optional[int] = None,
        has_more: bool = False
    ) -> PaginationInfo:
        """Create pagination information."""
        total_pages = None
        if total_rows is not None:
            total_pages = math.ceil(total_rows / page_size) if page_size > 0 else 1
        
        return PaginationInfo(
            page_size=page_size,
            current_page=current_page,
            total_pages=total_pages,
            has_next_page=has_more or (total_pages is not None and current_page < total_pages),
            has_previous_page=current_page > 1,
            next_page_token=str(current_page + 1) if has_more else None
        )
    
    def apply_pagination_to_query(
        self,
        query: str,
        page: int = 1,
        page_size: Optional[int] = None
    ) -> tuple[str, int, int]:
        """
        Apply pagination to a SQL query.
        
        Args:
            query: Original SQL query
            page: Page number (1-based)
            page_size: Number of rows per page
            
        Returns:
            Tuple of (modified_query, offset, limit)
        """
        if page_size is None:
            page_size = self.config.page_size
        
        # Ensure page is at least 1
        page = max(1, page)
        
        # Calculate offset and limit
        offset = (page - 1) * page_size
        limit = page_size
        
        # Apply pagination to SELECT queries only
        query_upper = query.strip().upper()
        if not query_upper.startswith("SELECT"):
            return query, 0, 0
        
        # Check if query already has LIMIT/OFFSET
        if "LIMIT" in query_upper or "OFFSET" in query_upper:
            # Query already has pagination, return as-is
            return query, 0, 0
        
        # Add OFFSET and LIMIT to the query
        paginated_query = f"{query.rstrip(';')} OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY"
        
        return paginated_query, offset, limit
    
    def calculate_total_rows(self, original_query: str) -> Optional[int]:
        """
        Calculate total number of rows for a query (for pagination).
        This creates a COUNT query from the original query.
        
        Args:
            original_query: Original SELECT query
            
        Returns:
            Total row count or None if cannot be determined
        """
        query_upper = original_query.strip().upper()
        if not query_upper.startswith("SELECT"):
            return None
        
        try:
            # Create a COUNT query by wrapping the original query
            count_query = f"SELECT COUNT(*) as total_count FROM ({original_query.rstrip(';')}) AS count_subquery"
            return count_query
        except Exception:
            # If we can't create a count query, return None
            return None