"""Structured logging configuration for Fabric Lakehouse MCP Server."""

import logging
import logging.config
import sys
import json
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union
from pathlib import Path
import structlog
from structlog.types import FilteringBoundLogger

from .exceptions import FabricMCPError, ErrorContext


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs structured JSON logs."""
    
    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        # Base log entry
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add thread and process info if available
        if hasattr(record, 'thread') and record.thread:
            log_entry["thread_id"] = record.thread
        if hasattr(record, 'process') and record.process:
            log_entry["process_id"] = record.process
        
        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields from the log record
        if self.include_extra:
            extra_fields = {}
            for key, value in record.__dict__.items():
                if key not in {
                    'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                    'filename', 'module', 'lineno', 'funcName', 'created',
                    'msecs', 'relativeCreated', 'thread', 'threadName',
                    'processName', 'process', 'getMessage', 'exc_info',
                    'exc_text', 'stack_info'
                }:
                    try:
                        # Ensure the value is JSON serializable
                        json.dumps(value)
                        extra_fields[key] = value
                    except (TypeError, ValueError):
                        extra_fields[key] = str(value)
            
            if extra_fields:
                log_entry["extra"] = extra_fields
        
        return json.dumps(log_entry, ensure_ascii=False)


class FabricMCPFilter(logging.Filter):
    """Custom filter for Fabric MCP specific log processing."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and enhance log records."""
        # Add correlation ID if available in thread local storage
        try:
            import threading
            local_data = getattr(threading.current_thread(), 'fabric_mcp_context', None)
            if local_data and hasattr(local_data, 'correlation_id'):
                record.correlation_id = local_data.correlation_id
        except Exception:
            pass
        
        # Enhance error records with additional context
        if record.levelno >= logging.ERROR and hasattr(record, 'exc_info') and record.exc_info:
            exc_type, exc_value, exc_traceback = record.exc_info
            if isinstance(exc_value, FabricMCPError):
                # Add structured error information
                record.error_category = exc_value.category.value
                record.error_severity = exc_value.severity.value
                record.error_code = exc_value.error_code
                record.retryable = exc_value.retryable
                
                if exc_value.fabric_error_code:
                    record.fabric_error_code = exc_value.fabric_error_code
                if exc_value.status_code:
                    record.status_code = exc_value.status_code
                
                # Add context information
                if exc_value.context:
                    if exc_value.context.operation:
                        record.operation = exc_value.context.operation
                    if exc_value.context.resource:
                        record.resource = exc_value.context.resource
                    if exc_value.context.request_id:
                        record.request_id = exc_value.context.request_id
        
        return True


def setup_logging(
    level: Union[str, int] = logging.INFO,
    log_file: Optional[str] = None,
    structured: bool = True,
    include_console: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> None:
    """
    Set up structured logging for the Fabric Lakehouse MCP Server.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file. If None, only console logging is used.
        structured: Whether to use structured JSON logging
        include_console: Whether to include console output
        max_bytes: Maximum size of log file before rotation
        backup_count: Number of backup log files to keep
    """
    # Convert string level to logging constant
    if isinstance(level, str):
        level = getattr(logging, level.upper())
    
    # Clear any existing handlers
    logging.root.handlers.clear()
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.dev.ConsoleRenderer() if not structured else structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.WriteLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Create handlers
    handlers = []
    
    # Console handler
    if include_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        
        if structured:
            console_handler.setFormatter(StructuredFormatter())
        else:
            console_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
        
        console_handler.addFilter(FabricMCPFilter())
        handlers.append(console_handler)
    
    # File handler with rotation
    if log_file:
        from logging.handlers import RotatingFileHandler
        
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(level)
        
        if structured:
            file_handler.setFormatter(StructuredFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
                )
            )
        
        file_handler.addFilter(FabricMCPFilter())
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        handlers=handlers,
        force=True
    )
    
    # Set specific logger levels
    logging.getLogger('azure').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('mcp').setLevel(logging.INFO)


def get_logger(name: str) -> FilteringBoundLogger:
    """
    Get a structured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Structured logger instance
    """
    return structlog.get_logger(name)


def log_operation(
    logger: FilteringBoundLogger,
    operation: str,
    level: str = "info",
    **kwargs
) -> None:
    """
    Log an operation with structured context.
    
    Args:
        logger: Logger instance
        operation: Operation name/description
        level: Log level (debug, info, warning, error, critical)
        **kwargs: Additional context fields
    """
    log_func = getattr(logger, level.lower())
    log_func(f"Operation: {operation}", operation=operation, **kwargs)


def log_error(
    logger: FilteringBoundLogger,
    error: Exception,
    operation: Optional[str] = None,
    context: Optional[ErrorContext] = None,
    **kwargs
) -> None:
    """
    Log an error with full context and structured information.
    
    Args:
        logger: Logger instance
        error: Exception that occurred
        operation: Operation that failed
        context: Additional error context
        **kwargs: Additional context fields
    """
    log_data = {
        "error_type": type(error).__name__,
        "error_message": str(error),
        **kwargs
    }
    
    if operation:
        log_data["operation"] = operation
    
    # Add structured error information for FabricMCPError
    if isinstance(error, FabricMCPError):
        log_data.update({
            "error_category": error.category.value,
            "error_severity": error.severity.value,
            "error_code": error.error_code,
            "retryable": error.retryable
        })
        
        if error.fabric_error_code:
            log_data["fabric_error_code"] = error.fabric_error_code
        if error.status_code:
            log_data["status_code"] = error.status_code
        
        # Use the error's context if none provided
        if not context and error.context:
            context = error.context
    
    # Add context information
    if context:
        if context.operation and "operation" not in log_data:
            log_data["operation"] = context.operation
        if context.resource:
            log_data["resource"] = context.resource
        if context.user_id:
            log_data["user_id"] = context.user_id
        if context.request_id:
            log_data["request_id"] = context.request_id
        if context.additional_data:
            log_data.update(context.additional_data)
    
    logger.error(
        f"Error occurred: {str(error)}",
        exc_info=True,
        **log_data
    )


def log_performance(
    logger: FilteringBoundLogger,
    operation: str,
    duration_ms: float,
    success: bool = True,
    **kwargs
) -> None:
    """
    Log performance metrics for operations.
    
    Args:
        logger: Logger instance
        operation: Operation name
        duration_ms: Operation duration in milliseconds
        success: Whether the operation succeeded
        **kwargs: Additional context fields
    """
    logger.info(
        f"Performance: {operation}",
        operation=operation,
        duration_ms=duration_ms,
        success=success,
        **kwargs
    )


class OperationLogger:
    """Context manager for logging operation start/end with timing."""
    
    def __init__(
        self,
        logger: FilteringBoundLogger,
        operation: str,
        level: str = "info",
        log_args: bool = False,
        **context
    ):
        self.logger = logger
        self.operation = operation
        self.level = level
        self.log_args = log_args
        self.context = context
        self.start_time: Optional[float] = None
        self.success = False
    
    def __enter__(self):
        import time
        self.start_time = time.time()
        
        log_data = {"operation": self.operation, **self.context}
        if self.log_args and "args" in self.context:
            log_data["args"] = self.context["args"]
        
        log_func = getattr(self.logger, self.level.lower())
        log_func(f"Starting operation: {self.operation}", **log_data)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        duration_ms = (time.time() - self.start_time) * 1000 if self.start_time else 0
        
        if exc_type is None:
            self.success = True
            log_performance(
                self.logger,
                self.operation,
                duration_ms,
                success=True,
                **self.context
            )
        else:
            log_error(
                self.logger,
                exc_val,
                operation=self.operation,
                **self.context
            )
            log_performance(
                self.logger,
                self.operation,
                duration_ms,
                success=False,
                **self.context
            )
    
    def set_context(self, **kwargs) -> None:
        """Add additional context to the operation."""
        self.context.update(kwargs)
    
    def mark_success(self) -> None:
        """Mark the operation as successful."""
        self.success = True