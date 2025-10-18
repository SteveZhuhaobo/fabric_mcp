"""Query timeout and cancellation handling."""

import asyncio
import signal
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Optional, TypeVar, Union
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from ..errors import TimeoutError, ErrorContext, get_logger, log_operation, log_error

logger = get_logger(__name__)

T = TypeVar('T')


class QueryTimeoutHandler:
    """Handles query timeouts and cancellation."""
    
    def __init__(self, default_timeout: int = 300):
        self.default_timeout = default_timeout
        self._active_queries = {}
        self._query_counter = 0
        self._lock = threading.Lock()
    
    def execute_with_timeout(
        self,
        func: Callable[..., T],
        timeout_seconds: Optional[int] = None,
        *args,
        **kwargs
    ) -> T:
        """
        Execute a function with timeout handling.
        
        Args:
            func: Function to execute
            timeout_seconds: Timeout in seconds (uses default if None)
            *args: Arguments to pass to function
            **kwargs: Keyword arguments to pass to function
            
        Returns:
            Function result
            
        Raises:
            TimeoutError: If execution times out
        """
        timeout = timeout_seconds or self.default_timeout
        query_id = self._register_query()
        
        try:
            log_operation(logger, "execute_with_timeout_started", timeout=timeout, query_id=query_id)
            # Use ThreadPoolExecutor for timeout handling
            with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(func, *args, **kwargs)
                    
                    try:
                        result = future.result(timeout=timeout)
                        log_operation(logger, "query_completed_within_timeout", query_id=query_id)
                        return result
                    except FutureTimeoutError:
                        # Cancel the future
                        future.cancel()
                        
                        context = ErrorContext(
                            operation="execute_with_timeout",
                            additional_data={"timeout_seconds": timeout, "query_id": query_id}
                        )
                        timeout_error = TimeoutError(
                            f"Query execution timed out after {timeout} seconds",
                            context=context
                        )
                        log_error(logger, timeout_error, operation="execute_with_timeout")
                        raise timeout_error
        finally:
            self._unregister_query(query_id)
    
    async def execute_with_timeout_async(
        self,
        coro: Callable[..., Any],
        timeout_seconds: Optional[int] = None,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute an async function with timeout handling.
        
        Args:
            coro: Coroutine function to execute
            timeout_seconds: Timeout in seconds (uses default if None)
            *args: Arguments to pass to coroutine
            **kwargs: Keyword arguments to pass to coroutine
            
        Returns:
            Coroutine result
            
        Raises:
            TimeoutError: If execution times out
        """
        timeout = timeout_seconds or self.default_timeout
        query_id = self._register_query()
        
        try:
            log_operation(logger, "execute_with_timeout_async_started", timeout=timeout, query_id=query_id)
            try:
                result = await asyncio.wait_for(coro(*args, **kwargs), timeout=timeout)
                log_operation(logger, "async_query_completed_within_timeout", query_id=query_id)
                return result
            except asyncio.TimeoutError:
                context = ErrorContext(
                    operation="execute_with_timeout_async",
                    additional_data={"timeout_seconds": timeout, "query_id": query_id}
                )
                timeout_error = TimeoutError(
                    f"Async query execution timed out after {timeout} seconds",
                    context=context
                )
                log_error(logger, timeout_error, operation="execute_with_timeout_async")
                raise timeout_error
        finally:
            self._unregister_query(query_id)
    
    @contextmanager
    def timeout_context(self, timeout_seconds: Optional[int] = None):
        """
        Context manager for timeout handling using signals (Unix only).
        
        Args:
            timeout_seconds: Timeout in seconds
            
        Yields:
            Query ID for tracking
            
        Raises:
            TimeoutError: If execution times out
        """
        timeout = timeout_seconds or self.default_timeout
        query_id = self._register_query()
        
        def timeout_handler(signum, frame):
            context = ErrorContext(
                operation="timeout_context",
                additional_data={"timeout_seconds": timeout, "query_id": query_id}
            )
            timeout_error = TimeoutError(
                f"Query execution timed out after {timeout} seconds",
                context=context
            )
            log_error(logger, timeout_error, operation="timeout_context")
            raise timeout_error
        
        # Set up signal handler (Unix only)
        old_handler = None
        try:
            if hasattr(signal, 'SIGALRM'):
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout)
            
            log_operation(logger, "timeout_context_started", timeout=timeout, query_id=query_id)
            yield query_id
            
        finally:
            # Clean up signal handler
            if hasattr(signal, 'SIGALRM'):
                signal.alarm(0)  # Cancel alarm
                if old_handler is not None:
                    signal.signal(signal.SIGALRM, old_handler)
            
            self._unregister_query(query_id)
    
    def cancel_query(self, query_id: str) -> bool:
        """
        Cancel a running query by ID.
        
        Args:
            query_id: ID of query to cancel
            
        Returns:
            True if query was found and cancelled
        """
        with self._lock:
            if query_id in self._active_queries:
                query_info = self._active_queries[query_id]
                query_info['cancelled'] = True
                log_operation(logger, "query_cancelled", query_id=query_id)
                return True
            return False
    
    def is_query_cancelled(self, query_id: str) -> bool:
        """
        Check if a query has been cancelled.
        
        Args:
            query_id: Query ID to check
            
        Returns:
            True if query is cancelled
        """
        with self._lock:
            if query_id in self._active_queries:
                return self._active_queries[query_id].get('cancelled', False)
            return False
    
    def get_active_queries(self) -> dict:
        """Get information about currently active queries."""
        with self._lock:
            return {
                qid: {
                    'start_time': info['start_time'],
                    'timeout': info['timeout'],
                    'cancelled': info.get('cancelled', False)
                }
                for qid, info in self._active_queries.items()
            }
    
    def _register_query(self) -> str:
        """Register a new query and return its ID."""
        with self._lock:
            self._query_counter += 1
            query_id = f"query_{self._query_counter}_{int(time.time())}"
            self._active_queries[query_id] = {
                'start_time': time.time(),
                'timeout': self.default_timeout,
                'cancelled': False
            }
            return query_id
    
    def _unregister_query(self, query_id: str) -> None:
        """Unregister a completed query."""
        with self._lock:
            self._active_queries.pop(query_id, None)


class CancellableQuery:
    """Context manager for cancellable query execution."""
    
    def __init__(self, timeout_handler: QueryTimeoutHandler, query_id: Optional[str] = None):
        self.timeout_handler = timeout_handler
        self.query_id = query_id or timeout_handler._register_query()
        self.start_time = time.time()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.timeout_handler._unregister_query(self.query_id)
    
    def check_cancellation(self) -> None:
        """Check if query has been cancelled and raise exception if so."""
        if self.timeout_handler.is_query_cancelled(self.query_id):
            context = ErrorContext(
                operation="check_cancellation",
                additional_data={"query_id": self.query_id}
            )
            raise TimeoutError("Query was cancelled", context=context)
    
    def check_timeout(self, timeout_seconds: int) -> None:
        """Check if query has exceeded timeout and raise exception if so."""
        elapsed = time.time() - self.start_time
        if elapsed > timeout_seconds:
            context = ErrorContext(
                operation="check_timeout",
                additional_data={"query_id": self.query_id, "elapsed_seconds": elapsed, "timeout_seconds": timeout_seconds}
            )
            raise TimeoutError(f"Query timed out after {elapsed:.1f} seconds", context=context)
    
    def get_elapsed_time(self) -> float:
        """Get elapsed execution time in seconds."""
        return time.time() - self.start_time


# OperationLogger is already imported above


def with_query_timeout(timeout_seconds: Optional[int] = None):
    """
    Decorator to add timeout handling to functions.
    
    Args:
        timeout_seconds: Timeout in seconds
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Create timeout handler if not provided
            if hasattr(func, '_timeout_handler'):
                handler = func._timeout_handler
            else:
                handler = QueryTimeoutHandler()
            
            return handler.execute_with_timeout(func, timeout_seconds, *args, **kwargs)
        
        return wrapper
    return decorator


def with_async_query_timeout(timeout_seconds: Optional[int] = None):
    """
    Decorator to add timeout handling to async functions.
    
    Args:
        timeout_seconds: Timeout in seconds
    """
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            # Create timeout handler if not provided
            if hasattr(func, '_timeout_handler'):
                handler = func._timeout_handler
            else:
                handler = QueryTimeoutHandler()
            
            return await handler.execute_with_timeout_async(func, timeout_seconds, *args, **kwargs)
        
        return wrapper
    return decorator