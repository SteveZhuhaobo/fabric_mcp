"""Custom exception classes for Fabric Lakehouse MCP Server."""

from enum import Enum
from typing import Any, Dict, Optional
from dataclasses import dataclass


class ErrorCategory(Enum):
    """Categories of errors that can occur in the system."""
    AUTHENTICATION = "authentication"
    CONNECTION = "connection" 
    PERMISSION = "permission"
    VALIDATION = "validation"
    EXECUTION = "execution"
    CONFIGURATION = "configuration"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorContext:
    """Additional context information for errors."""
    operation: Optional[str] = None
    resource: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None


class FabricMCPError(Exception):
    """Base exception class for all Fabric MCP Server errors."""
    
    def __init__(
        self,
        message: str,
        category: ErrorCategory,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        error_code: Optional[str] = None,
        fabric_error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
        retryable: bool = False
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.error_code = error_code or self._generate_error_code()
        self.fabric_error_code = fabric_error_code
        self.status_code = status_code
        self.context = context or ErrorContext()
        self.cause = cause
        self.retryable = retryable
    
    def _generate_error_code(self) -> str:
        """Generate a default error code based on category."""
        return f"FABRIC_{self.category.value.upper()}_ERROR"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary format for logging and responses."""
        error_dict = {
            "error_code": self.error_code,
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "retryable": self.retryable
        }
        
        if self.fabric_error_code:
            error_dict["fabric_error_code"] = self.fabric_error_code
        if self.status_code:
            error_dict["status_code"] = self.status_code
        if self.cause:
            error_dict["cause"] = str(self.cause)
        
        # Add context information
        if self.context:
            context_dict = {}
            if self.context.operation:
                context_dict["operation"] = self.context.operation
            if self.context.resource:
                context_dict["resource"] = self.context.resource
            if self.context.user_id:
                context_dict["user_id"] = self.context.user_id
            if self.context.request_id:
                context_dict["request_id"] = self.context.request_id
            if self.context.timestamp:
                context_dict["timestamp"] = self.context.timestamp
            if self.context.additional_data:
                context_dict.update(self.context.additional_data)
            
            if context_dict:
                error_dict["context"] = context_dict
        
        return error_dict
    
    def get_user_message(self) -> str:
        """Get a user-friendly error message."""
        return self.message
    
    def get_technical_details(self) -> str:
        """Get technical details for debugging."""
        details = [f"Error: {self.message}"]
        
        if self.fabric_error_code:
            details.append(f"Fabric Error Code: {self.fabric_error_code}")
        if self.status_code:
            details.append(f"HTTP Status: {self.status_code}")
        if self.cause:
            details.append(f"Underlying Cause: {self.cause}")
        
        return " | ".join(details)


class AuthenticationError(FabricMCPError):
    """Exception for authentication-related errors."""
    
    def __init__(
        self,
        message: str = "Authentication failed",
        error_code: Optional[str] = None,
        fabric_error_code: Optional[str] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            error_code=error_code or "AUTH_FAILED",
            fabric_error_code=fabric_error_code,
            status_code=401,
            context=context,
            cause=cause,
            retryable=True  # Auth errors might be retryable after token refresh
        )
    
    def get_user_message(self) -> str:
        """Get user-friendly authentication error message."""
        return "Authentication failed. Please check your credentials and try again."


class ConnectionError(FabricMCPError):
    """Exception for network and connection-related errors."""
    
    def __init__(
        self,
        message: str = "Connection failed",
        error_code: Optional[str] = None,
        fabric_error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.CONNECTION,
            severity=ErrorSeverity.MEDIUM,
            error_code=error_code or "CONNECTION_FAILED",
            fabric_error_code=fabric_error_code,
            status_code=status_code,
            context=context,
            cause=cause,
            retryable=True  # Connection errors are typically retryable
        )
    
    def get_user_message(self) -> str:
        """Get user-friendly connection error message."""
        return "Unable to connect to Microsoft Fabric. Please check your network connection and try again."


class PermissionError(FabricMCPError):
    """Exception for permission and authorization errors."""
    
    def __init__(
        self,
        message: str = "Permission denied",
        error_code: Optional[str] = None,
        fabric_error_code: Optional[str] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.PERMISSION,
            severity=ErrorSeverity.HIGH,
            error_code=error_code or "PERMISSION_DENIED",
            fabric_error_code=fabric_error_code,
            status_code=403,
            context=context,
            cause=cause,
            retryable=False  # Permission errors are not retryable
        )
    
    def get_user_message(self) -> str:
        """Get user-friendly permission error message."""
        return "You don't have permission to perform this operation. Please contact your administrator."


class ValidationError(FabricMCPError):
    """Exception for input validation errors."""
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        error_code: Optional[str] = None,
        context: Optional[ErrorContext] = None
    ):
        # Add field information to context
        if field and context:
            if not context.additional_data:
                context.additional_data = {}
            context.additional_data["field"] = field
        elif field:
            context = ErrorContext(additional_data={"field": field})
        
        super().__init__(
            message=message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.LOW,
            error_code=error_code or "VALIDATION_FAILED",
            status_code=400,
            context=context,
            retryable=False  # Validation errors are not retryable without fixing input
        )
        self.field = field
    
    def get_user_message(self) -> str:
        """Get user-friendly validation error message."""
        if self.field:
            return f"Invalid value for '{self.field}': {self.message}"
        return f"Validation error: {self.message}"


class ExecutionError(FabricMCPError):
    """Exception for query execution and operation errors."""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        fabric_error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
        retryable: bool = False
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.EXECUTION,
            severity=ErrorSeverity.MEDIUM,
            error_code=error_code or "EXECUTION_FAILED",
            fabric_error_code=fabric_error_code,
            status_code=status_code,
            context=context,
            cause=cause,
            retryable=retryable
        )
    
    def get_user_message(self) -> str:
        """Get user-friendly execution error message."""
        return f"Operation failed: {self.message}"


class TimeoutError(FabricMCPError):
    """Exception for timeout-related errors."""
    
    def __init__(
        self,
        message: str = "Operation timed out",
        timeout_seconds: Optional[int] = None,
        error_code: Optional[str] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        # Add timeout information to context
        if timeout_seconds and context:
            if not context.additional_data:
                context.additional_data = {}
            context.additional_data["timeout_seconds"] = timeout_seconds
        elif timeout_seconds:
            context = ErrorContext(additional_data={"timeout_seconds": timeout_seconds})
        
        super().__init__(
            message=message,
            category=ErrorCategory.TIMEOUT,
            severity=ErrorSeverity.MEDIUM,
            error_code=error_code or "OPERATION_TIMEOUT",
            status_code=408,
            context=context,
            cause=cause,
            retryable=True  # Timeouts might be retryable
        )
        self.timeout_seconds = timeout_seconds
    
    def get_user_message(self) -> str:
        """Get user-friendly timeout error message."""
        if self.timeout_seconds:
            return f"Operation timed out after {self.timeout_seconds} seconds. Please try again."
        return "Operation timed out. Please try again."


class RateLimitError(FabricMCPError):
    """Exception for rate limiting errors."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        error_code: Optional[str] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        # Add retry_after information to context
        if retry_after and context:
            if not context.additional_data:
                context.additional_data = {}
            context.additional_data["retry_after"] = retry_after
        elif retry_after:
            context = ErrorContext(additional_data={"retry_after": retry_after})
        
        super().__init__(
            message=message,
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.MEDIUM,
            error_code=error_code or "RATE_LIMIT_EXCEEDED",
            status_code=429,
            context=context,
            cause=cause,
            retryable=True  # Rate limit errors are retryable after waiting
        )
        self.retry_after = retry_after
    
    def get_user_message(self) -> str:
        """Get user-friendly rate limit error message."""
        if self.retry_after:
            return f"Rate limit exceeded. Please wait {self.retry_after} seconds before trying again."
        return "Rate limit exceeded. Please wait before trying again."


class ConfigurationError(FabricMCPError):
    """Exception for configuration-related errors."""
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        error_code: Optional[str] = None,
        context: Optional[ErrorContext] = None
    ):
        # Add config_key information to context
        if config_key and context:
            if not context.additional_data:
                context.additional_data = {}
            context.additional_data["config_key"] = config_key
        elif config_key:
            context = ErrorContext(additional_data={"config_key": config_key})
        
        super().__init__(
            message=message,
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.HIGH,
            error_code=error_code or "CONFIG_ERROR",
            context=context,
            retryable=False  # Config errors are not retryable without fixing config
        )
        self.config_key = config_key
    
    def get_user_message(self) -> str:
        """Get user-friendly configuration error message."""
        if self.config_key:
            return f"Configuration error for '{self.config_key}': {self.message}"
        return f"Configuration error: {self.message}"


# Utility functions for error classification
class RetryableError(FabricMCPError):
    """Base class for errors that can be retried."""
    
    def __init__(self, *args, **kwargs):
        kwargs['retryable'] = True
        super().__init__(*args, **kwargs)


class NonRetryableError(FabricMCPError):
    """Base class for errors that should not be retried."""
    
    def __init__(self, *args, **kwargs):
        kwargs['retryable'] = False
        super().__init__(*args, **kwargs)