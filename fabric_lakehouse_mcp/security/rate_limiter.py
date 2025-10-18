"""Rate limiting and request throttling."""

import time
import threading
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, deque

from ..errors import RateLimitError, ErrorContext, get_logger

logger = get_logger(__name__)


class RateLimitExceeded(RateLimitError):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(self, message: str, retry_after: int, limit_type: str, context: ErrorContext = None):
        super().__init__(message, retry_after, context=context)
        self.limit_type = limit_type


class RateLimitType(Enum):
    """Types of rate limits."""
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    QUERIES_PER_MINUTE = "queries_per_minute"
    QUERIES_PER_HOUR = "queries_per_hour"
    DATA_OPERATIONS_PER_MINUTE = "data_operations_per_minute"
    SCHEMA_OPERATIONS_PER_HOUR = "schema_operations_per_hour"
    CONCURRENT_QUERIES = "concurrent_queries"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    # Request limits
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
    
    # Query limits
    queries_per_minute: int = 50
    queries_per_hour: int = 500
    
    # Operation-specific limits
    data_operations_per_minute: int = 30
    schema_operations_per_hour: int = 10
    
    # Concurrent limits
    max_concurrent_queries: int = 5
    
    # Burst allowance
    burst_allowance: float = 1.5  # Allow 50% burst above normal rate
    
    # Sliding window size (in seconds)
    window_size_minutes: int = 60
    window_size_hours: int = 3600
    
    # Enable/disable specific limits
    enable_request_limits: bool = True
    enable_query_limits: bool = True
    enable_operation_limits: bool = True
    enable_concurrent_limits: bool = True
    
    # Whitelist/blacklist
    whitelisted_users: set = None
    blacklisted_users: set = None
    
    def __post_init__(self):
        if self.whitelisted_users is None:
            self.whitelisted_users = set()
        if self.blacklisted_users is None:
            self.blacklisted_users = set()


@dataclass
class RateLimitStatus:
    """Current rate limit status for a user/key."""
    current_count: int
    limit: int
    window_start: float
    window_size: int
    retry_after: Optional[int] = None
    
    @property
    def remaining(self) -> int:
        """Get remaining requests in current window."""
        return max(0, self.limit - self.current_count)
    
    @property
    def is_exceeded(self) -> bool:
        """Check if rate limit is exceeded."""
        return self.current_count >= self.limit


class SlidingWindowCounter:
    """Sliding window counter for rate limiting."""
    
    def __init__(self, window_size: int, limit: int):
        self.window_size = window_size  # in seconds
        self.limit = limit
        self.requests = deque()  # Store timestamps
        self.lock = threading.Lock()
    
    def is_allowed(self, current_time: float = None) -> Tuple[bool, int]:
        """
        Check if request is allowed and return (allowed, retry_after).
        
        Args:
            current_time: Current timestamp (defaults to time.time())
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        if current_time is None:
            current_time = time.time()
        
        with self.lock:
            # Remove old requests outside the window
            cutoff_time = current_time - self.window_size
            while self.requests and self.requests[0] <= cutoff_time:
                self.requests.popleft()
            
            # Check if we're under the limit
            if len(self.requests) < self.limit:
                self.requests.append(current_time)
                return True, 0
            else:
                # Calculate retry after based on oldest request in window
                oldest_request = self.requests[0]
                retry_after = int(oldest_request + self.window_size - current_time) + 1
                return False, max(1, retry_after)
    
    def get_status(self, current_time: float = None) -> RateLimitStatus:
        """Get current rate limit status."""
        if current_time is None:
            current_time = time.time()
        
        with self.lock:
            # Clean old requests
            cutoff_time = current_time - self.window_size
            while self.requests and self.requests[0] <= cutoff_time:
                self.requests.popleft()
            
            retry_after = None
            if len(self.requests) >= self.limit and self.requests:
                oldest_request = self.requests[0]
                retry_after = int(oldest_request + self.window_size - current_time) + 1
            
            return RateLimitStatus(
                current_count=len(self.requests),
                limit=self.limit,
                window_start=current_time - self.window_size,
                window_size=self.window_size,
                retry_after=retry_after
            )


class ConcurrentLimiter:
    """Limiter for concurrent operations."""
    
    def __init__(self, max_concurrent: int):
        self.max_concurrent = max_concurrent
        self.current_count = 0
        self.lock = threading.Lock()
    
    def acquire(self) -> bool:
        """Try to acquire a slot for concurrent operation."""
        with self.lock:
            if self.current_count < self.max_concurrent:
                self.current_count += 1
                return True
            return False
    
    def release(self):
        """Release a slot for concurrent operation."""
        with self.lock:
            if self.current_count > 0:
                self.current_count -= 1
    
    def get_status(self) -> RateLimitStatus:
        """Get current concurrent limit status."""
        with self.lock:
            return RateLimitStatus(
                current_count=self.current_count,
                limit=self.max_concurrent,
                window_start=time.time(),
                window_size=0  # Not applicable for concurrent limits
            )


class RateLimiter:
    """Main rate limiter class that manages all types of limits."""
    
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        
        # Per-user rate limiters
        self.user_limiters: Dict[str, Dict[RateLimitType, SlidingWindowCounter]] = defaultdict(dict)
        self.concurrent_limiters: Dict[str, ConcurrentLimiter] = {}
        
        # Global lock for thread safety
        self.lock = threading.Lock()
        
        logger.info(
            "Rate limiter initialized",
            extra={
                "requests_per_minute": self.config.requests_per_minute,
                "queries_per_minute": self.config.queries_per_minute,
                "max_concurrent_queries": self.config.max_concurrent_queries
            }
        )
    
    def check_request_limit(self, user_id: str, operation_context: str = None) -> None:
        """
        Check if request is within rate limits.
        
        Args:
            user_id: User identifier
            operation_context: Context of the operation
            
        Raises:
            RateLimitExceeded: If rate limit is exceeded
        """
        if not self.config.enable_request_limits:
            return
        
        if user_id in self.config.whitelisted_users:
            return
        
        if user_id in self.config.blacklisted_users:
            context = ErrorContext(
                operation="rate_limit_check",
                additional_data={"user_id": user_id, "operation_context": operation_context}
            )
            raise RateLimitExceeded(
                "User is blacklisted",
                retry_after=3600,  # 1 hour
                limit_type="blacklist",
                context=context
            )
        
        # Check per-minute limit
        self._check_limit(
            user_id,
            RateLimitType.REQUESTS_PER_MINUTE,
            self.config.requests_per_minute,
            self.config.window_size_minutes,
            operation_context
        )
        
        # Check per-hour limit
        self._check_limit(
            user_id,
            RateLimitType.REQUESTS_PER_HOUR,
            self.config.requests_per_hour,
            self.config.window_size_hours,
            operation_context
        )
    
    def check_query_limit(self, user_id: str, operation_context: str = None) -> None:
        """Check if query is within rate limits."""
        if not self.config.enable_query_limits:
            return
        
        if user_id in self.config.whitelisted_users:
            return
        
        # Check per-minute limit
        self._check_limit(
            user_id,
            RateLimitType.QUERIES_PER_MINUTE,
            self.config.queries_per_minute,
            self.config.window_size_minutes,
            operation_context
        )
        
        # Check per-hour limit
        self._check_limit(
            user_id,
            RateLimitType.QUERIES_PER_HOUR,
            self.config.queries_per_hour,
            self.config.window_size_hours,
            operation_context
        )
    
    def check_data_operation_limit(self, user_id: str, operation_context: str = None) -> None:
        """Check if data operation is within rate limits."""
        if not self.config.enable_operation_limits:
            return
        
        if user_id in self.config.whitelisted_users:
            return
        
        self._check_limit(
            user_id,
            RateLimitType.DATA_OPERATIONS_PER_MINUTE,
            self.config.data_operations_per_minute,
            self.config.window_size_minutes,
            operation_context
        )
    
    def check_schema_operation_limit(self, user_id: str, operation_context: str = None) -> None:
        """Check if schema operation is within rate limits."""
        if not self.config.enable_operation_limits:
            return
        
        if user_id in self.config.whitelisted_users:
            return
        
        self._check_limit(
            user_id,
            RateLimitType.SCHEMA_OPERATIONS_PER_HOUR,
            self.config.schema_operations_per_hour,
            self.config.window_size_hours,
            operation_context
        )
    
    def acquire_concurrent_query_slot(self, user_id: str, operation_context: str = None) -> str:
        """
        Acquire a slot for concurrent query execution.
        
        Args:
            user_id: User identifier
            operation_context: Context of the operation
            
        Returns:
            Slot ID for releasing later
            
        Raises:
            RateLimitExceeded: If concurrent limit is exceeded
        """
        if not self.config.enable_concurrent_limits:
            return "no_limit"
        
        if user_id in self.config.whitelisted_users:
            return "whitelisted"
        
        # Get or create concurrent limiter for user
        if user_id not in self.concurrent_limiters:
            with self.lock:
                if user_id not in self.concurrent_limiters:
                    self.concurrent_limiters[user_id] = ConcurrentLimiter(
                        self.config.max_concurrent_queries
                    )
        
        limiter = self.concurrent_limiters[user_id]
        
        if limiter.acquire():
            slot_id = f"{user_id}_{int(time.time())}_{id(threading.current_thread())}"
            logger.debug(
                f"Acquired concurrent query slot for user {user_id}",
                extra={
                    "user_id": user_id,
                    "slot_id": slot_id,
                    "operation_context": operation_context
                }
            )
            return slot_id
        else:
            context = ErrorContext(
                operation="concurrent_limit_check",
                additional_data={"user_id": user_id, "operation_context": operation_context}
            )
            raise RateLimitExceeded(
                f"Concurrent query limit exceeded ({self.config.max_concurrent_queries})",
                retry_after=30,  # Suggest retry after 30 seconds
                limit_type="concurrent_queries",
                context=context
            )
    
    def release_concurrent_query_slot(self, user_id: str, slot_id: str) -> None:
        """Release a concurrent query slot."""
        if slot_id in ["no_limit", "whitelisted"]:
            return
        
        if user_id in self.concurrent_limiters:
            self.concurrent_limiters[user_id].release()
            logger.debug(
                f"Released concurrent query slot for user {user_id}",
                extra={
                    "user_id": user_id,
                    "slot_id": slot_id
                }
            )
    
    def get_rate_limit_status(self, user_id: str) -> Dict[str, RateLimitStatus]:
        """Get current rate limit status for a user."""
        status = {}
        
        # Get status for all limit types
        for limit_type in RateLimitType:
            if limit_type == RateLimitType.CONCURRENT_QUERIES:
                if user_id in self.concurrent_limiters:
                    status[limit_type.value] = self.concurrent_limiters[user_id].get_status()
            else:
                if user_id in self.user_limiters and limit_type in self.user_limiters[user_id]:
                    status[limit_type.value] = self.user_limiters[user_id][limit_type].get_status()
        
        return status
    
    def _check_limit(
        self,
        user_id: str,
        limit_type: RateLimitType,
        limit: int,
        window_size: int,
        operation_context: str = None
    ) -> None:
        """Check a specific rate limit."""
        # Get or create limiter for user and limit type
        if user_id not in self.user_limiters:
            with self.lock:
                if user_id not in self.user_limiters:
                    self.user_limiters[user_id] = {}
        
        if limit_type not in self.user_limiters[user_id]:
            with self.lock:
                if limit_type not in self.user_limiters[user_id]:
                    # Apply burst allowance
                    burst_limit = int(limit * self.config.burst_allowance)
                    self.user_limiters[user_id][limit_type] = SlidingWindowCounter(
                        window_size, burst_limit
                    )
        
        limiter = self.user_limiters[user_id][limit_type]
        allowed, retry_after = limiter.is_allowed()
        
        if not allowed:
            context = ErrorContext(
                operation="rate_limit_check",
                additional_data={
                    "user_id": user_id,
                    "limit_type": limit_type.value,
                    "operation_context": operation_context
                }
            )
            
            # Log rate limit violation
            logger.warning(
                f"Rate limit exceeded for user {user_id}",
                extra={
                    "user_id": user_id,
                    "limit_type": limit_type.value,
                    "retry_after": retry_after,
                    "operation_context": operation_context
                }
            )
            
            raise RateLimitExceeded(
                f"Rate limit exceeded for {limit_type.value}: {limit} requests per {window_size} seconds",
                retry_after=retry_after,
                limit_type=limit_type.value,
                context=context
            )
    
    def reset_user_limits(self, user_id: str) -> None:
        """Reset all rate limits for a user (admin function)."""
        with self.lock:
            if user_id in self.user_limiters:
                del self.user_limiters[user_id]
            if user_id in self.concurrent_limiters:
                del self.concurrent_limiters[user_id]
        
        logger.info(
            f"Reset rate limits for user {user_id}",
            extra={"user_id": user_id}
        )
    
    def add_to_whitelist(self, user_id: str) -> None:
        """Add user to whitelist."""
        self.config.whitelisted_users.add(user_id)
        logger.info(f"Added user {user_id} to whitelist")
    
    def remove_from_whitelist(self, user_id: str) -> None:
        """Remove user from whitelist."""
        self.config.whitelisted_users.discard(user_id)
        logger.info(f"Removed user {user_id} from whitelist")
    
    def add_to_blacklist(self, user_id: str) -> None:
        """Add user to blacklist."""
        self.config.blacklisted_users.add(user_id)
        logger.warning(f"Added user {user_id} to blacklist")
    
    def remove_from_blacklist(self, user_id: str) -> None:
        """Remove user from blacklist."""
        self.config.blacklisted_users.discard(user_id)
        logger.info(f"Removed user {user_id} from blacklist")


# Context manager for concurrent query slots
class ConcurrentQuerySlot:
    """Context manager for concurrent query slots."""
    
    def __init__(self, rate_limiter: RateLimiter, user_id: str, operation_context: str = None):
        self.rate_limiter = rate_limiter
        self.user_id = user_id
        self.operation_context = operation_context
        self.slot_id = None
    
    def __enter__(self) -> str:
        self.slot_id = self.rate_limiter.acquire_concurrent_query_slot(
            self.user_id, self.operation_context
        )
        return self.slot_id
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.slot_id:
            self.rate_limiter.release_concurrent_query_slot(self.user_id, self.slot_id)


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter(config: Optional[RateLimitConfig] = None) -> RateLimiter:
    """Get global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(config)
    return _rate_limiter


def initialize_rate_limiter(config: RateLimitConfig) -> RateLimiter:
    """Initialize global rate limiter."""
    global _rate_limiter
    _rate_limiter = RateLimiter(config)
    return _rate_limiter