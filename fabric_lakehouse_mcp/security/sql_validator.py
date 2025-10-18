"""SQL injection prevention and validation."""

import re
from typing import List, Set, Dict, Any
from dataclasses import dataclass
from enum import Enum

from ..errors import ValidationError, ErrorContext, get_logger

logger = get_logger(__name__)


class SQLSecurityError(ValidationError):
    """Exception raised when SQL security validation fails."""
    
    def __init__(self, message: str, security_issue: str, context: ErrorContext = None):
        super().__init__(message, context=context)
        self.security_issue = security_issue


class SecurityLevel(Enum):
    """Security validation levels."""
    STRICT = "strict"      # Maximum security, blocks many patterns
    MODERATE = "moderate"  # Balanced security and functionality
    PERMISSIVE = "permissive"  # Minimal security checks


@dataclass
class SQLValidationConfig:
    """Configuration for SQL validation."""
    security_level: SecurityLevel = SecurityLevel.MODERATE
    allow_multiple_statements: bool = False
    allow_stored_procedures: bool = False
    allow_dynamic_sql: bool = False
    max_query_length: int = 50000
    blocked_keywords: Set[str] = None
    allowed_functions: Set[str] = None
    
    def __post_init__(self):
        if self.blocked_keywords is None:
            self.blocked_keywords = set()
        if self.allowed_functions is None:
            self.allowed_functions = self._get_default_allowed_functions()
    
    def _get_default_allowed_functions(self) -> Set[str]:
        """Get default set of allowed SQL functions."""
        return {
            # String functions
            'CONCAT', 'SUBSTRING', 'LEFT', 'RIGHT', 'UPPER', 'LOWER', 'TRIM', 'LTRIM', 'RTRIM',
            'LEN', 'LENGTH', 'CHARINDEX', 'PATINDEX', 'REPLACE', 'REVERSE', 'STUFF',
            
            # Numeric functions
            'ABS', 'CEILING', 'FLOOR', 'ROUND', 'SQRT', 'POWER', 'EXP', 'LOG', 'LOG10',
            'SIN', 'COS', 'TAN', 'ASIN', 'ACOS', 'ATAN', 'DEGREES', 'RADIANS',
            'RAND', 'SIGN', 'PI',
            
            # Date functions
            'GETDATE', 'GETUTCDATE', 'DATEADD', 'DATEDIFF', 'DATEPART', 'DATENAME',
            'YEAR', 'MONTH', 'DAY', 'HOUR', 'MINUTE', 'SECOND',
            'CAST', 'CONVERT', 'FORMAT',
            
            # Aggregate functions
            'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'STDEV', 'VAR',
            'STRING_AGG', 'LISTAGG',
            
            # Window functions
            'ROW_NUMBER', 'RANK', 'DENSE_RANK', 'NTILE', 'LAG', 'LEAD',
            'FIRST_VALUE', 'LAST_VALUE',
            
            # Conditional functions
            'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'IIF', 'CHOOSE', 'COALESCE', 'NULLIF',
            'ISNULL', 'ISDATE', 'ISNUMERIC',
            
            # Type conversion
            'TRY_CAST', 'TRY_CONVERT', 'TRY_PARSE'
        }


class SQLValidator:
    """Validates SQL queries for security and safety."""
    
    def __init__(self, config: SQLValidationConfig = None):
        self.config = config or SQLValidationConfig()
        self._dangerous_patterns = self._build_dangerous_patterns()
        self._suspicious_keywords = self._build_suspicious_keywords()
    
    def validate_query(self, query: str, operation_context: str = None) -> None:
        """
        Validate SQL query for security issues.
        
        Args:
            query: SQL query to validate
            operation_context: Context of the operation for logging
            
        Raises:
            SQLSecurityError: If security validation fails
        """
        context = ErrorContext(
            operation="sql_validation",
            additional_data={"operation_context": operation_context}
        )
        
        # Basic validation
        self._validate_query_length(query, context)
        self._validate_query_structure(query, context)
        
        # Security validation
        self._check_sql_injection_patterns(query, context)
        self._check_dangerous_keywords(query, context)
        self._check_suspicious_functions(query, context)
        self._check_multiple_statements(query, context)
        self._check_dynamic_sql(query, context)
        
        # Log successful validation
        logger.debug(
            "SQL query validation passed",
            extra={
                "operation": "sql_validation",
                "query_length": len(query),
                "security_level": self.config.security_level.value,
                "operation_context": operation_context
            }
        )
    
    def _validate_query_length(self, query: str, context: ErrorContext) -> None:
        """Validate query length."""
        if len(query) > self.config.max_query_length:
            raise SQLSecurityError(
                f"Query exceeds maximum length of {self.config.max_query_length} characters",
                security_issue="query_too_long",
                context=context
            )
    
    def _validate_query_structure(self, query: str, context: ErrorContext) -> None:
        """Validate basic query structure."""
        if not query or not query.strip():
            raise SQLSecurityError(
                "Query cannot be empty",
                security_issue="empty_query",
                context=context
            )
        
        # Check for balanced parentheses
        paren_count = 0
        in_string = False
        escape_next = False
        
        for char in query:
            if escape_next:
                escape_next = False
                continue
            
            if char == '\\':
                escape_next = True
                continue
            
            if char in ("'", '"') and not in_string:
                in_string = True
            elif char in ("'", '"') and in_string:
                in_string = False
            elif not in_string:
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
        
        if paren_count != 0:
            raise SQLSecurityError(
                "Unbalanced parentheses in query",
                security_issue="unbalanced_parentheses",
                context=context
            )
    
    def _check_sql_injection_patterns(self, query: str, context: ErrorContext) -> None:
        """Check for common SQL injection patterns."""
        query_upper = query.upper()
        
        for pattern_name, pattern in self._dangerous_patterns.items():
            if re.search(pattern, query_upper, re.IGNORECASE | re.MULTILINE):
                raise SQLSecurityError(
                    f"Query contains potentially dangerous pattern: {pattern_name}",
                    security_issue=f"dangerous_pattern_{pattern_name}",
                    context=context
                )
    
    def _check_dangerous_keywords(self, query: str, context: ErrorContext) -> None:
        """Check for dangerous keywords based on security level."""
        query_upper = query.upper()
        
        for keyword in self._suspicious_keywords:
            if keyword in self.config.blocked_keywords:
                if re.search(r'\b' + re.escape(keyword) + r'\b', query_upper):
                    raise SQLSecurityError(
                        f"Query contains blocked keyword: {keyword}",
                        security_issue=f"blocked_keyword_{keyword.lower()}",
                        context=context
                    )
    
    def _check_suspicious_functions(self, query: str, context: ErrorContext) -> None:
        """Check for suspicious function calls."""
        query_upper = query.upper()
        
        # Extract function calls
        function_pattern = r'\b([A-Z_][A-Z0-9_]*)\s*\('
        functions = re.findall(function_pattern, query_upper)
        
        for func in functions:
            if func not in self.config.allowed_functions:
                if self.config.security_level == SecurityLevel.STRICT:
                    raise SQLSecurityError(
                        f"Function '{func}' is not in the allowed functions list",
                        security_issue=f"disallowed_function_{func.lower()}",
                        context=context
                    )
                elif self.config.security_level == SecurityLevel.MODERATE:
                    # Log warning but don't block
                    logger.warning(
                        f"Potentially suspicious function used: {func}",
                        extra={
                            "operation": "sql_validation",
                            "function": func,
                            "security_issue": "suspicious_function"
                        }
                    )
    
    def _check_multiple_statements(self, query: str, context: ErrorContext) -> None:
        """Check for multiple SQL statements."""
        if not self.config.allow_multiple_statements:
            # Remove string literals to avoid false positives
            cleaned_query = self._remove_string_literals(query)
            
            # Count semicolons outside of strings
            semicolon_count = cleaned_query.count(';')
            
            # Allow one trailing semicolon
            if semicolon_count > 1 or (semicolon_count == 1 and not cleaned_query.rstrip().endswith(';')):
                raise SQLSecurityError(
                    "Multiple SQL statements are not allowed",
                    security_issue="multiple_statements",
                    context=context
                )
    
    def _check_dynamic_sql(self, query: str, context: ErrorContext) -> None:
        """Check for dynamic SQL construction."""
        if not self.config.allow_dynamic_sql:
            query_upper = query.upper()
            
            dynamic_sql_patterns = [
                r'EXEC\s*\(',
                r'EXECUTE\s*\(',
                r'SP_EXECUTESQL',
                r'EXEC\s+@',
                r'EXECUTE\s+@'
            ]
            
            for pattern in dynamic_sql_patterns:
                if re.search(pattern, query_upper):
                    raise SQLSecurityError(
                        "Dynamic SQL execution is not allowed",
                        security_issue="dynamic_sql",
                        context=context
                    )
    
    def _remove_string_literals(self, query: str) -> str:
        """Remove string literals from query to avoid false positives."""
        # Simple implementation - replace string contents with spaces
        result = []
        in_string = False
        string_char = None
        escape_next = False
        
        for char in query:
            if escape_next:
                result.append(' ')
                escape_next = False
                continue
            
            if char == '\\':
                escape_next = True
                result.append(' ')
                continue
            
            if not in_string and char in ("'", '"'):
                in_string = True
                string_char = char
                result.append(' ')
            elif in_string and char == string_char:
                in_string = False
                string_char = None
                result.append(' ')
            elif in_string:
                result.append(' ')
            else:
                result.append(char)
        
        return ''.join(result)
    
    def _build_dangerous_patterns(self) -> Dict[str, str]:
        """Build dictionary of dangerous SQL patterns."""
        patterns = {
            # SQL injection patterns
            "union_injection": r"UNION\s+(ALL\s+)?SELECT",
            "comment_injection": r"--.*(?:DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|EXECUTE)",
            "stacked_queries": r";\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER|EXEC|EXECUTE)",
            
            # System function abuse
            "system_functions": r"\b(xp_|sp_|fn_|sys\.)",
            "file_operations": r"\b(OPENROWSET|OPENDATASOURCE|BULK\s+INSERT)",
            "registry_access": r"\bxp_regread|xp_regwrite|xp_regdelete",
            
            # Information disclosure
            "error_based": r"CONVERT\s*\(\s*INT\s*,|CAST\s*\(\s*.*\s+AS\s+INT\s*\)",
            "time_based": r"WAITFOR\s+DELAY|BENCHMARK\s*\(",
            
            # Privilege escalation
            "privilege_escalation": r"\b(GRANT|REVOKE)\s+(ALL|SELECT|INSERT|UPDATE|DELETE)",
        }
        
        # Add security level specific patterns
        if self.config.security_level == SecurityLevel.STRICT:
            patterns.update({
                "subquery_injection": r"SELECT\s+.*\s+FROM\s*\(",
                "conditional_injection": r"\b(IF|CASE)\s*\(",
            })
        
        return patterns
    
    def _build_suspicious_keywords(self) -> Set[str]:
        """Build set of suspicious keywords based on security level."""
        base_keywords = {
            # System stored procedures
            'XP_CMDSHELL', 'XP_REGREAD', 'XP_REGWRITE', 'XP_REGDELETE',
            'SP_CONFIGURE', 'SP_ADDEXTENDEDPROC', 'SP_DROPEXTENDEDPROC',
            
            # File operations
            'OPENROWSET', 'OPENDATASOURCE', 'BULK',
            
            # Dynamic SQL
            'EXEC', 'EXECUTE', 'SP_EXECUTESQL',
            
            # System functions
            'SYSTEM_USER', 'SESSION_USER', 'USER_NAME', 'SUSER_NAME',
            'HOST_NAME', 'APP_NAME', 'DB_NAME',
        }
        
        if self.config.security_level == SecurityLevel.STRICT:
            base_keywords.update({
                # Additional strict mode keywords
                'WAITFOR', 'DELAY', 'BENCHMARK',
                'LOAD_FILE', 'INTO OUTFILE', 'INTO DUMPFILE',
            })
        
        return base_keywords


def create_sql_validator(security_level: SecurityLevel = SecurityLevel.MODERATE) -> SQLValidator:
    """Create SQL validator with specified security level."""
    config = SQLValidationConfig(security_level=security_level)
    return SQLValidator(config)