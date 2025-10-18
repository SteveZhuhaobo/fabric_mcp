"""Query complexity analysis and restrictions."""

import re
from typing import Dict, List, Set, Any
from dataclasses import dataclass
from enum import Enum

from ..errors import ValidationError, ErrorContext, get_logger

logger = get_logger(__name__)


class QueryComplexityError(ValidationError):
    """Exception raised when query complexity validation fails."""
    
    def __init__(self, message: str, complexity_issue: str, context: ErrorContext = None):
        super().__init__(message, context=context)
        self.complexity_issue = complexity_issue


class ComplexityLevel(Enum):
    """Query complexity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXTREME = "extreme"


@dataclass
class QueryComplexityMetrics:
    """Metrics for query complexity analysis."""
    total_score: int = 0
    join_count: int = 0
    subquery_count: int = 0
    union_count: int = 0
    aggregate_count: int = 0
    window_function_count: int = 0
    cte_count: int = 0
    table_count: int = 0
    where_condition_count: int = 0
    order_by_column_count: int = 0
    group_by_column_count: int = 0
    having_condition_count: int = 0
    estimated_rows_examined: int = 0
    complexity_level: ComplexityLevel = ComplexityLevel.LOW
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_score": self.total_score,
            "join_count": self.join_count,
            "subquery_count": self.subquery_count,
            "union_count": self.union_count,
            "aggregate_count": self.aggregate_count,
            "window_function_count": self.window_function_count,
            "cte_count": self.cte_count,
            "table_count": self.table_count,
            "where_condition_count": self.where_condition_count,
            "order_by_column_count": self.order_by_column_count,
            "group_by_column_count": self.group_by_column_count,
            "having_condition_count": self.having_condition_count,
            "estimated_rows_examined": self.estimated_rows_examined,
            "complexity_level": self.complexity_level.value
        }


@dataclass
class ComplexityLimits:
    """Limits for query complexity."""
    max_total_score: int = 100
    max_joins: int = 10
    max_subqueries: int = 5
    max_unions: int = 3
    max_tables: int = 15
    max_ctes: int = 5
    max_window_functions: int = 10
    max_aggregates: int = 20
    max_where_conditions: int = 20
    max_order_by_columns: int = 10
    max_group_by_columns: int = 10
    max_having_conditions: int = 5
    max_estimated_rows: int = 1000000
    
    # Scoring weights
    join_weight: int = 5
    subquery_weight: int = 8
    union_weight: int = 6
    aggregate_weight: int = 2
    window_function_weight: int = 4
    cte_weight: int = 3
    table_weight: int = 1
    where_condition_weight: int = 1
    order_by_weight: int = 1
    group_by_weight: int = 2
    having_weight: int = 3


class QueryComplexityAnalyzer:
    """Analyzes SQL query complexity and enforces limits."""
    
    def __init__(self, limits: ComplexityLimits = None):
        self.limits = limits or ComplexityLimits()
        self._join_patterns = self._build_join_patterns()
        self._aggregate_functions = self._build_aggregate_functions()
        self._window_functions = self._build_window_functions()
    
    def analyze_query(self, query: str, operation_context: str = None) -> QueryComplexityMetrics:
        """
        Analyze query complexity and return metrics.
        
        Args:
            query: SQL query to analyze
            operation_context: Context of the operation for logging
            
        Returns:
            QueryComplexityMetrics with analysis results
            
        Raises:
            QueryComplexityError: If query exceeds complexity limits
        """
        context = ErrorContext(
            operation="query_complexity_analysis",
            additional_data={"operation_context": operation_context}
        )
        
        # Clean query for analysis
        cleaned_query = self._clean_query(query)
        
        # Calculate metrics
        metrics = QueryComplexityMetrics()
        
        metrics.join_count = self._count_joins(cleaned_query)
        metrics.subquery_count = self._count_subqueries(cleaned_query)
        metrics.union_count = self._count_unions(cleaned_query)
        metrics.aggregate_count = self._count_aggregates(cleaned_query)
        metrics.window_function_count = self._count_window_functions(cleaned_query)
        metrics.cte_count = self._count_ctes(cleaned_query)
        metrics.table_count = self._count_tables(cleaned_query)
        metrics.where_condition_count = self._count_where_conditions(cleaned_query)
        metrics.order_by_column_count = self._count_order_by_columns(cleaned_query)
        metrics.group_by_column_count = self._count_group_by_columns(cleaned_query)
        metrics.having_condition_count = self._count_having_conditions(cleaned_query)
        
        # Calculate total complexity score
        metrics.total_score = self._calculate_complexity_score(metrics)
        
        # Determine complexity level
        metrics.complexity_level = self._determine_complexity_level(metrics.total_score)
        
        # Estimate rows examined (simplified heuristic)
        metrics.estimated_rows_examined = self._estimate_rows_examined(metrics)
        
        # Validate against limits
        self._validate_complexity(metrics, context)
        
        # Log analysis results
        logger.info(
            "Query complexity analysis completed",
            extra={
                "operation": "query_complexity_analysis",
                "complexity_score": metrics.total_score,
                "complexity_level": metrics.complexity_level.value,
                "operation_context": operation_context,
                "metrics": metrics.to_dict()
            }
        )
        
        return metrics
    
    def _clean_query(self, query: str) -> str:
        """Clean query for analysis by removing comments and normalizing whitespace."""
        # Remove single-line comments
        query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
        
        # Remove multi-line comments
        query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
        
        # Normalize whitespace
        query = re.sub(r'\s+', ' ', query)
        
        return query.strip().upper()
    
    def _count_joins(self, query: str) -> int:
        """Count JOIN operations in the query."""
        join_count = 0
        for pattern in self._join_patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            join_count += len(matches)
        return join_count
    
    def _count_subqueries(self, query: str) -> int:
        """Count subqueries in the query."""
        # Count SELECT statements that are not the main query
        select_count = len(re.findall(r'\bSELECT\b', query, re.IGNORECASE))
        # Subtract 1 for the main query (assuming it starts with SELECT)
        return max(0, select_count - 1)
    
    def _count_unions(self, query: str) -> int:
        """Count UNION operations in the query."""
        return len(re.findall(r'\bUNION\s+(ALL\s+)?', query, re.IGNORECASE))
    
    def _count_aggregates(self, query: str) -> int:
        """Count aggregate functions in the query."""
        aggregate_count = 0
        for func in self._aggregate_functions:
            pattern = r'\b' + re.escape(func) + r'\s*\('
            matches = re.findall(pattern, query, re.IGNORECASE)
            aggregate_count += len(matches)
        return aggregate_count
    
    def _count_window_functions(self, query: str) -> int:
        """Count window functions in the query."""
        window_count = 0
        
        # Count OVER clauses
        over_count = len(re.findall(r'\bOVER\s*\(', query, re.IGNORECASE))
        window_count += over_count
        
        # Count specific window functions
        for func in self._window_functions:
            pattern = r'\b' + re.escape(func) + r'\s*\('
            matches = re.findall(pattern, query, re.IGNORECASE)
            window_count += len(matches)
        
        return window_count
    
    def _count_ctes(self, query: str) -> int:
        """Count Common Table Expressions (CTEs) in the query."""
        # Count WITH clauses
        with_count = len(re.findall(r'\bWITH\s+', query, re.IGNORECASE))
        
        # Count comma-separated CTEs within WITH clauses
        cte_pattern = r'\bWITH\s+.*?(?=\bSELECT\b)'
        with_clauses = re.findall(cte_pattern, query, re.IGNORECASE | re.DOTALL)
        
        total_ctes = 0
        for with_clause in with_clauses:
            # Count commas that separate CTEs (simplified approach)
            comma_count = with_clause.count(',')
            total_ctes += comma_count + 1  # +1 for the first CTE
        
        return total_ctes
    
    def _count_tables(self, query: str) -> int:
        """Count tables referenced in the query."""
        # This is a simplified approach - count FROM and JOIN clauses
        from_count = len(re.findall(r'\bFROM\s+\w+', query, re.IGNORECASE))
        join_count = self._count_joins(query)
        return from_count + join_count
    
    def _count_where_conditions(self, query: str) -> int:
        """Count WHERE conditions in the query."""
        where_clauses = re.findall(r'\bWHERE\s+.*?(?=\bGROUP\s+BY|\bHAVING|\bORDER\s+BY|\bLIMIT|\bOFFSET|$)', 
                                 query, re.IGNORECASE | re.DOTALL)
        
        condition_count = 0
        for where_clause in where_clauses:
            # Count AND/OR operators as indicators of multiple conditions
            and_count = len(re.findall(r'\bAND\b', where_clause, re.IGNORECASE))
            or_count = len(re.findall(r'\bOR\b', where_clause, re.IGNORECASE))
            condition_count += and_count + or_count + 1  # +1 for the base condition
        
        return condition_count
    
    def _count_order_by_columns(self, query: str) -> int:
        """Count columns in ORDER BY clauses."""
        order_by_clauses = re.findall(r'\bORDER\s+BY\s+([^;]+?)(?=\bLIMIT|\bOFFSET|$)', 
                                    query, re.IGNORECASE | re.DOTALL)
        
        column_count = 0
        for clause in order_by_clauses:
            # Count commas to determine number of columns
            column_count += clause.count(',') + 1
        
        return column_count
    
    def _count_group_by_columns(self, query: str) -> int:
        """Count columns in GROUP BY clauses."""
        group_by_clauses = re.findall(r'\bGROUP\s+BY\s+([^;]+?)(?=\bHAVING|\bORDER\s+BY|\bLIMIT|\bOFFSET|$)', 
                                    query, re.IGNORECASE | re.DOTALL)
        
        column_count = 0
        for clause in group_by_clauses:
            # Count commas to determine number of columns
            column_count += clause.count(',') + 1
        
        return column_count
    
    def _count_having_conditions(self, query: str) -> int:
        """Count HAVING conditions in the query."""
        having_clauses = re.findall(r'\bHAVING\s+.*?(?=\bORDER\s+BY|\bLIMIT|\bOFFSET|$)', 
                                  query, re.IGNORECASE | re.DOTALL)
        
        condition_count = 0
        for having_clause in having_clauses:
            # Count AND/OR operators
            and_count = len(re.findall(r'\bAND\b', having_clause, re.IGNORECASE))
            or_count = len(re.findall(r'\bOR\b', having_clause, re.IGNORECASE))
            condition_count += and_count + or_count + 1
        
        return condition_count
    
    def _calculate_complexity_score(self, metrics: QueryComplexityMetrics) -> int:
        """Calculate total complexity score based on metrics."""
        score = 0
        score += metrics.join_count * self.limits.join_weight
        score += metrics.subquery_count * self.limits.subquery_weight
        score += metrics.union_count * self.limits.union_weight
        score += metrics.aggregate_count * self.limits.aggregate_weight
        score += metrics.window_function_count * self.limits.window_function_weight
        score += metrics.cte_count * self.limits.cte_weight
        score += metrics.table_count * self.limits.table_weight
        score += metrics.where_condition_count * self.limits.where_condition_weight
        score += metrics.order_by_column_count * self.limits.order_by_weight
        score += metrics.group_by_column_count * self.limits.group_by_weight
        score += metrics.having_condition_count * self.limits.having_weight
        
        return score
    
    def _determine_complexity_level(self, score: int) -> ComplexityLevel:
        """Determine complexity level based on score."""
        if score <= 20:
            return ComplexityLevel.LOW
        elif score <= 50:
            return ComplexityLevel.MEDIUM
        elif score <= 100:
            return ComplexityLevel.HIGH
        else:
            return ComplexityLevel.EXTREME
    
    def _estimate_rows_examined(self, metrics: QueryComplexityMetrics) -> int:
        """Estimate number of rows that might be examined (simplified heuristic)."""
        base_rows = 1000  # Base assumption
        
        # Multiply by factors based on complexity
        multiplier = 1
        multiplier *= (1 + metrics.join_count * 0.5)  # JOINs increase row examination
        multiplier *= (1 + metrics.subquery_count * 0.3)  # Subqueries add overhead
        multiplier *= (1 + metrics.table_count * 0.2)  # More tables = more rows
        
        # Reduce for aggregates (they typically reduce result size)
        if metrics.aggregate_count > 0:
            multiplier *= 0.8
        
        return int(base_rows * multiplier)
    
    def _validate_complexity(self, metrics: QueryComplexityMetrics, context: ErrorContext) -> None:
        """Validate query complexity against limits."""
        violations = []
        
        if metrics.total_score > self.limits.max_total_score:
            violations.append(f"Total complexity score ({metrics.total_score}) exceeds limit ({self.limits.max_total_score})")
        
        if metrics.join_count > self.limits.max_joins:
            violations.append(f"Join count ({metrics.join_count}) exceeds limit ({self.limits.max_joins})")
        
        if metrics.subquery_count > self.limits.max_subqueries:
            violations.append(f"Subquery count ({metrics.subquery_count}) exceeds limit ({self.limits.max_subqueries})")
        
        if metrics.union_count > self.limits.max_unions:
            violations.append(f"Union count ({metrics.union_count}) exceeds limit ({self.limits.max_unions})")
        
        if metrics.table_count > self.limits.max_tables:
            violations.append(f"Table count ({metrics.table_count}) exceeds limit ({self.limits.max_tables})")
        
        if metrics.cte_count > self.limits.max_ctes:
            violations.append(f"CTE count ({metrics.cte_count}) exceeds limit ({self.limits.max_ctes})")
        
        if metrics.window_function_count > self.limits.max_window_functions:
            violations.append(f"Window function count ({metrics.window_function_count}) exceeds limit ({self.limits.max_window_functions})")
        
        if metrics.aggregate_count > self.limits.max_aggregates:
            violations.append(f"Aggregate count ({metrics.aggregate_count}) exceeds limit ({self.limits.max_aggregates})")
        
        if metrics.estimated_rows_examined > self.limits.max_estimated_rows:
            violations.append(f"Estimated rows examined ({metrics.estimated_rows_examined}) exceeds limit ({self.limits.max_estimated_rows})")
        
        if violations:
            violation_message = "; ".join(violations)
            raise QueryComplexityError(
                f"Query complexity exceeds limits: {violation_message}",
                complexity_issue="complexity_limit_exceeded",
                context=context
            )
    
    def _build_join_patterns(self) -> List[str]:
        """Build list of JOIN patterns to match."""
        return [
            r'\bINNER\s+JOIN\b',
            r'\bLEFT\s+(OUTER\s+)?JOIN\b',
            r'\bRIGHT\s+(OUTER\s+)?JOIN\b',
            r'\bFULL\s+(OUTER\s+)?JOIN\b',
            r'\bCROSS\s+JOIN\b',
            r'\bJOIN\b'  # Generic JOIN
        ]
    
    def _build_aggregate_functions(self) -> Set[str]:
        """Build set of aggregate function names."""
        return {
            'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
            'STDEV', 'STDEVP', 'VAR', 'VARP',
            'STRING_AGG', 'LISTAGG', 'ARRAY_AGG',
            'GROUPING', 'GROUPING_ID'
        }
    
    def _build_window_functions(self) -> Set[str]:
        """Build set of window function names."""
        return {
            'ROW_NUMBER', 'RANK', 'DENSE_RANK', 'NTILE',
            'LAG', 'LEAD', 'FIRST_VALUE', 'LAST_VALUE',
            'PERCENT_RANK', 'CUME_DIST', 'PERCENTILE_CONT', 'PERCENTILE_DISC'
        }


def create_complexity_analyzer(
    max_complexity_score: int = 100,
    max_joins: int = 10,
    max_subqueries: int = 5
) -> QueryComplexityAnalyzer:
    """Create query complexity analyzer with custom limits."""
    limits = ComplexityLimits(
        max_total_score=max_complexity_score,
        max_joins=max_joins,
        max_subqueries=max_subqueries
    )
    return QueryComplexityAnalyzer(limits)