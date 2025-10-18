"""Retry logic with exponential backoff for network and transient errors."""

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Type, Union, List
from functools import wraps
import logging

from .exceptions import (
    FabricMCPError,
    ConnectionError,
    TimeoutError,
    RateLimitError,
    AuthenticationError,
    ErrorContext
)


logger = logging.getLogger(__name__)


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    jitter_range: float = 0.1
    backoff_multiplier: float = 1.0
    
    def __post_init__(self):
        """Validate retry configuration."""
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.initial_delay < 0:
            raise ValueError("initial_delay must be non-negative")
        if self.max_delay < self.initial_delay:
            raise ValueError("max_delay must be >= initial_delay")
        if self.exponential_base <= 1:
            raise ValueError("exponential_base must be > 1")
        if self.jitter_range < 0 or self.jitter_range > 1:
            raise ValueError("jitter_range must be between 0 and 1")


class ExponentialBackoff:
    """Implements exponential backoff with jitter for retry delays."""
    
    def __init__(self, config: RetryConfig):
        self.config = config
        self.attempt = 0
    
    def reset(self) -> None:
        """Reset the backoff state."""
        self.attempt = 0
    
    def next_delay(self) -> float:
        """Calculate the next delay duration."""
        if self.attempt == 0:
            delay = 0  # No delay for first attempt
        else:
            # Calculate exponential delay
            delay = (
                self.config.initial_delay * 
                (self.config.exponential_base ** (self.attempt - 1)) *
                self.config.backoff_multiplier
            )
            
            # Apply maximum delay limit
            delay = min(delay, self.config.max_delay)
            
            # Add jitter to prevent thundering herd
            if self.config.jitter:
                jitter_amount = delay * self.config.jitter_range
                jitter = random.uniform(-jitter_amount, jitter_amount)
                delay = max(0, delay + jitter)
        
        self.attempt += 1
        return delay
    
    def should_retry(self) -> bool:
        """Check if we should attempt another retry."""
        return self.attempt < self.config.max_attempts


def is_retryable_error(error: Exception) -> bool:
    """Determine if an error is retryable."""
    # Check if it's a FabricMCPError with retryable flag
    if isinstance(error, FabricMCPError):
        return error.retryable
    
    # Check for specific error types that are typically retryable
    retryable_types = (
        ConnectionError,
        TimeoutError,
        RateLimitError,
    )
    
    if isinstance(error, retryable_types):
        return True
    
    # Check for specific HTTP status codes that are retryable
    if hasattr(error, 'status_code'):
        retryable_status_codes = {500, 502, 503, 504, 408, 429}
        if error.status_code in retryable_status_codes:
            return True
    
    # Check for specific error messages that indicate transient issues
    error_message = str(error).lower()
    transient_indicators = [
        'timeout',
        'connection',
        'network',
        'temporary',
        'rate limit',
        'throttle',
        'service unavailable',
        'internal server error',
        'bad gateway',
        'gateway timeout'
    ]
    
    return any(indicator in error_message for indicator in transient_indicators)


def get_retry_delay_from_error(error: Exception) -> Optional[float]:
    """Extract retry delay from error if available (e.g., from Retry-After header)."""
    if isinstance(error, RateLimitError) and error.retry_after:
        return float(error.retry_after)
    
    if hasattr(error, 'retry_after') and error.retry_after:
        try:
            return float(error.retry_after)
        except (ValueError, TypeError):
            pass
    
    return None


def retry_with_backoff(
    config: Optional[RetryConfig] = None,
    retryable_exceptions: Optional[List[Type[Exception]]] = None,
    on_retry: Optional[Callable[[Exception, int, float], None]] = None
):
    """
    Decorator that adds retry logic with exponential backoff to a function.
    
    Args:
        config: Retry configuration. If None, uses default config.
        retryable_exceptions: List of exception types to retry on. If None, uses is_retryable_error.
        on_retry: Optional callback called before each retry attempt.
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            backoff = ExponentialBackoff(config)
            last_exception = None
            
            while backoff.should_retry():
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Check if this error should be retried
                    should_retry = False
                    if retryable_exceptions:
                        should_retry = isinstance(e, tuple(retryable_exceptions))
                    else:
                        should_retry = is_retryable_error(e)
                    
                    if not should_retry or not backoff.should_retry():
                        # Don't retry this error or we've exhausted attempts
                        raise e
                    
                    # Calculate delay for next attempt
                    delay = backoff.next_delay()
                    
                    # Check if error specifies a custom retry delay
                    error_delay = get_retry_delay_from_error(e)
                    if error_delay is not None:
                        delay = max(delay, error_delay)
                    
                    # Log retry attempt
                    logger.warning(
                        f"Retrying {func.__name__} after error (attempt {backoff.attempt}/{config.max_attempts}): {e}",
                        extra={
                            "function": func.__name__,
                            "attempt": backoff.attempt,
                            "max_attempts": config.max_attempts,
                            "delay": delay,
                            "error": str(e),
                            "error_type": type(e).__name__
                        }
                    )
                    
                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(e, backoff.attempt, delay)
                        except Exception as callback_error:
                            logger.error(f"Error in retry callback: {callback_error}")
                    
                    # Wait before retrying
                    if delay > 0:
                        time.sleep(delay)
            
            # If we get here, we've exhausted all retry attempts
            if last_exception:
                raise last_exception
            else:
                raise RuntimeError("Retry logic failed unexpectedly")
        
        return wrapper
    return decorator


async def async_retry_with_backoff(
    config: Optional[RetryConfig] = None,
    retryable_exceptions: Optional[List[Type[Exception]]] = None,
    on_retry: Optional[Callable[[Exception, int, float], None]] = None
):
    """
    Async version of retry_with_backoff decorator.
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            backoff = ExponentialBackoff(config)
            last_exception = None
            
            while backoff.should_retry():
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Check if this error should be retried
                    should_retry = False
                    if retryable_exceptions:
                        should_retry = isinstance(e, tuple(retryable_exceptions))
                    else:
                        should_retry = is_retryable_error(e)
                    
                    if not should_retry or not backoff.should_retry():
                        # Don't retry this error or we've exhausted attempts
                        raise e
                    
                    # Calculate delay for next attempt
                    delay = backoff.next_delay()
                    
                    # Check if error specifies a custom retry delay
                    error_delay = get_retry_delay_from_error(e)
                    if error_delay is not None:
                        delay = max(delay, error_delay)
                    
                    # Log retry attempt
                    logger.warning(
                        f"Retrying {func.__name__} after error (attempt {backoff.attempt}/{config.max_attempts}): {e}",
                        extra={
                            "function": func.__name__,
                            "attempt": backoff.attempt,
                            "max_attempts": config.max_attempts,
                            "delay": delay,
                            "error": str(e),
                            "error_type": type(e).__name__
                        }
                    )
                    
                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(e, backoff.attempt, delay)
                        except Exception as callback_error:
                            logger.error(f"Error in retry callback: {callback_error}")
                    
                    # Wait before retrying
                    if delay > 0:
                        await asyncio.sleep(delay)
            
            # If we get here, we've exhausted all retry attempts
            if last_exception:
                raise last_exception
            else:
                raise RuntimeError("Retry logic failed unexpectedly")
        
        return wrapper
    return decorator


class RetryableOperation:
    """Context manager for retryable operations with manual control."""
    
    def __init__(
        self,
        config: Optional[RetryConfig] = None,
        operation_name: str = "operation",
        context: Optional[ErrorContext] = None
    ):
        self.config = config or RetryConfig()
        self.operation_name = operation_name
        self.context = context
        self.backoff = ExponentialBackoff(self.config)
        self.last_exception: Optional[Exception] = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val and self.should_retry(exc_val):
            # Suppress the exception to allow retry
            return True
        return False
    
    def should_retry(self, error: Exception) -> bool:
        """Check if the operation should be retried."""
        if not is_retryable_error(error):
            return False
        
        if not self.backoff.should_retry():
            return False
        
        self.last_exception = error
        return True
    
    def wait_for_retry(self) -> None:
        """Wait for the appropriate retry delay."""
        if self.last_exception is None:
            return
        
        delay = self.backoff.next_delay()
        
        # Check if error specifies a custom retry delay
        error_delay = get_retry_delay_from_error(self.last_exception)
        if error_delay is not None:
            delay = max(delay, error_delay)
        
        # Log retry attempt
        logger.warning(
            f"Retrying {self.operation_name} after error (attempt {self.backoff.attempt}/{self.config.max_attempts}): {self.last_exception}",
            extra={
                "operation": self.operation_name,
                "attempt": self.backoff.attempt,
                "max_attempts": self.config.max_attempts,
                "delay": delay,
                "error": str(self.last_exception),
                "error_type": type(self.last_exception).__name__
            }
        )
        
        # Wait before retrying
        if delay > 0:
            time.sleep(delay)
    
    def get_attempts_remaining(self) -> int:
        """Get the number of retry attempts remaining."""
        return max(0, self.config.max_attempts - self.backoff.attempt)
    
    def reset(self) -> None:
        """Reset the retry state."""
        self.backoff.reset()
        self.last_exception = None