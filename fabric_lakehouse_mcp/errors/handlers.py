"""Error handling utilities and context managers."""

import functools
import traceback
from typing import Any, Callable, Dict, Optional, Type, Union
from datetime import datetime, timezone

from mcp.server.fastmcp.exceptions import ToolError
import requests
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

from .exceptions import (
    FabricMCPError,
    AuthenticationError,
    ConnectionError,
    PermissionError,
    ValidationError,
    ExecutionError,
    TimeoutError,
    RateLimitError,
    ConfigurationError,
    ErrorContext,
    ErrorCategory,
    ErrorSeverity
)
from .logging_config import get_logger, log_error


logger = get_logger(__name__)


class ErrorHandler:
    """Central error handler for converting exceptions to appropriate MCP errors."""
    
    @staticmethod
    def handle_fabric_error(
        error: Exception,
        operation: Optional[str] = None,
        resource: Optional[str] = None,
        context: Optional[ErrorContext] = None
    ) -> FabricMCPError:
        """
        Convert various exception types to appropriate FabricMCPError instances.
        
        Args:
            error: The original exception
            operation: Operation that failed
            resource: Resource being accessed
            context: Additional error context
            
        Returns:
            FabricMCPError: Appropriate error type for the exception
        """
        # Create context if not provided
        if context is None:
            context = ErrorContext(
                operation=operation,
                resource=resource,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
        else:
            # Update context with provided values
            if operation and not context.operation:
                context.operation = operation
            if resource and not context.resource:
                context.resource = resource
            if not context.timestamp:
                context.timestamp = datetime.now(timezone.utc).isoformat()
        
        # If it's already a FabricMCPError, just update context and return
        if isinstance(error, FabricMCPError):
            if not error.context or not error.context.operation:
                error.context = context
            return error
        
        # Handle Azure authentication errors
        if isinstance(error, ClientAuthenticationError):
            return AuthenticationError(
                message="Azure authentication failed",
                fabric_error_code=getattr(error, 'error_code', None),
                context=context,
                cause=error
            )
        
        # Handle Azure HTTP response errors
        if isinstance(error, HttpResponseError):
            status_code = error.status_code
            error_message = str(error)
            
            if status_code == 401:
                return AuthenticationError(
                    message="Authentication failed - invalid or expired credentials",
                    fabric_error_code=getattr(error, 'error_code', None),
                    context=context,
                    cause=error
                )
            elif status_code == 403:
                return PermissionError(
                    message="Access denied - insufficient permissions",
                    fabric_error_code=getattr(error, 'error_code', None),
                    context=context,
                    cause=error
                )
            elif status_code == 404:
                return ExecutionError(
                    message=f"Resource not found: {resource or 'unknown'}",
                    fabric_error_code=getattr(error, 'error_code', None),
                    status_code=status_code,
                    context=context,
                    cause=error,
                    retryable=False
                )
            elif status_code == 408:
                return TimeoutError(
                    message="Request timeout",
                    context=context,
                    cause=error
                )
            elif status_code == 429:
                retry_after = None
                if hasattr(error, 'response') and error.response:
                    retry_after = error.response.headers.get('Retry-After')
                    if retry_after:
                        try:
                            retry_after = int(retry_after)
                        except ValueError:
                            retry_after = None
                
                return RateLimitError(
                    message="Rate limit exceeded",
                    retry_after=retry_after,
                    context=context,
                    cause=error
                )
            elif status_code >= 500:
                return ConnectionError(
                    message=f"Server error: {error_message}",
                    fabric_error_code=getattr(error, 'error_code', None),
                    status_code=status_code,
                    context=context,
                    cause=error
                )
            else:
                return ExecutionError(
                    message=f"HTTP error {status_code}: {error_message}",
                    fabric_error_code=getattr(error, 'error_code', None),
                    status_code=status_code,
                    context=context,
                    cause=error,
                    retryable=status_code in {502, 503, 504}
                )
        
        # Handle requests library errors
        if isinstance(error, requests.exceptions.RequestException):
            if isinstance(error, requests.exceptions.Timeout):
                return TimeoutError(
                    message="Request timeout",
                    context=context,
                    cause=error
                )
            elif isinstance(error, requests.exceptions.ConnectionError):
                return ConnectionError(
                    message="Network connection failed",
                    context=context,
                    cause=error
                )
            elif isinstance(error, requests.exceptions.HTTPError):
                status_code = None
                if hasattr(error, 'response') and error.response:
                    status_code = error.response.status_code
                
                return ExecutionError(
                    message=f"HTTP error: {str(error)}",
                    status_code=status_code,
                    context=context,
                    cause=error,
                    retryable=status_code in {429, 500, 502, 503, 504} if status_code else True
                )
            else:
                return ConnectionError(
                    message=f"Request failed: {str(error)}",
                    context=context,
                    cause=error
                )
        
        # Handle validation errors (from our own validation)
        if isinstance(error, ValueError) and "validation" in str(error).lower():
            return ValidationError(
                message=str(error),
                context=context
            )
        
        # Handle timeout errors
        if isinstance(error, TimeoutError) or "timeout" in str(error).lower():
            return TimeoutError(
                message=str(error),
                context=context,
                cause=error
            )
        
        # Handle permission errors
        if isinstance(error, PermissionError) or "permission" in str(error).lower():
            return PermissionError(
                message=str(error),
                context=context,
                cause=error
            )
        
        # Default to execution error for unknown exceptions
        return ExecutionError(
            message=f"Unexpected error: {str(error)}",
            context=context,
            cause=error,
            retryable=False
        )
    
    @staticmethod
    def to_mcp_error(error: FabricMCPError) -> ToolError:
        """
        Convert a FabricMCPError to an MCP ToolError.
        
        Args:
            error: FabricMCPError to convert
            
        Returns:
            ToolError: MCP-compatible error
        """
        # Create error data with technical details
        error_data = {
            "error_type": error.category.value,
            "severity": error.severity.value,
            "retryable": error.retryable
        }
        
        if error.fabric_error_code:
            error_data["fabric_error_code"] = error.fabric_error_code
        if error.status_code:
            error_data["status_code"] = error.status_code
        if error.cause:
            error_data["cause"] = str(error.cause)
        
        # Add context information
        if error.context:
            context_data = {}
            if error.context.operation:
                context_data["operation"] = error.context.operation
            if error.context.resource:
                context_data["resource"] = error.context.resource
            if error.context.request_id:
                context_data["request_id"] = error.context.request_id
            if error.context.additional_data:
                context_data.update(error.context.additional_data)
            
            if context_data:
                error_data["context"] = context_data
        
        # Add technical details for debugging
        error_data["technical_details"] = error.get_technical_details()
        
        return ToolError(
            error.error_code,
            error.get_user_message(),
            error_data
        )


def handle_fabric_error(
    operation: Optional[str] = None,
    resource: Optional[str] = None,
    reraise_as_tool_error: bool = True
):
    """
    Decorator for handling Fabric API errors and converting them to appropriate exceptions.
    
    Args:
        operation: Operation name for context
        resource: Resource name for context
        reraise_as_tool_error: Whether to convert to ToolError for MCP compatibility
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Create error context
                context = ErrorContext(
                    operation=operation or func.__name__,
                    resource=resource,
                    timestamp=datetime.now(timezone.utc).isoformat()
                )
                
                # Convert to FabricMCPError
                fabric_error = ErrorHandler.handle_fabric_error(
                    error=e,
                    operation=operation or func.__name__,
                    resource=resource,
                    context=context
                )
                
                # Log the error
                log_error(logger, fabric_error, operation=operation or func.__name__)
                
                # Convert to ToolError if requested
                if reraise_as_tool_error:
                    raise ErrorHandler.to_mcp_error(fabric_error)
                else:
                    raise fabric_error
        
        return wrapper
    return decorator


def handle_auth_error(func: Callable) -> Callable:
    """Decorator specifically for handling authentication errors."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            context = ErrorContext(
                operation=func.__name__,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
            if isinstance(e, (ClientAuthenticationError, AuthenticationError)):
                auth_error = AuthenticationError(
                    message="Authentication failed",
                    context=context,
                    cause=e
                )
                log_error(logger, auth_error, operation=func.__name__)
                raise auth_error
            else:
                # Re-raise other errors as-is
                raise e
    
    return wrapper


def handle_validation_error(func: Callable) -> Callable:
    """Decorator specifically for handling validation errors."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as e:
            context = ErrorContext(
                operation=func.__name__,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
            validation_error = ValidationError(
                message=str(e),
                context=context
            )
            log_error(logger, validation_error, operation=func.__name__)
            raise validation_error
        except Exception as e:
            # Re-raise other errors as-is
            raise e
    
    return wrapper


class ErrorHandlingContext:
    """Context manager for error handling with automatic logging."""
    
    def __init__(
        self,
        operation: str,
        resource: Optional[str] = None,
        log_errors: bool = True,
        reraise_as_tool_error: bool = True
    ):
        self.operation = operation
        self.resource = resource
        self.log_errors = log_errors
        self.reraise_as_tool_error = reraise_as_tool_error
        self.context = ErrorContext(
            operation=operation,
            resource=resource,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is not None:
            # Convert to FabricMCPError
            fabric_error = ErrorHandler.handle_fabric_error(
                error=exc_val,
                operation=self.operation,
                resource=self.resource,
                context=self.context
            )
            
            # Log the error if requested
            if self.log_errors:
                log_error(logger, fabric_error, operation=self.operation)
            
            # Convert to ToolError if requested
            if self.reraise_as_tool_error:
                tool_error = ErrorHandler.to_mcp_error(fabric_error)
                raise tool_error from exc_val
            else:
                raise fabric_error from exc_val
        
        return False  # Don't suppress exceptions
    
    def add_context(self, **kwargs) -> None:
        """Add additional context information."""
        if not self.context.additional_data:
            self.context.additional_data = {}
        self.context.additional_data.update(kwargs)