"""Tests for security enhancements."""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch

from fabric_lakehouse_mcp.security import (
    SQLValidator,
    SQLSecurityError,
    QueryComplexityAnalyzer,
    QueryComplexityError,
    AuditLogger,
    AuditEventStatus,
    RateLimiter,
    RateLimitExceeded,
    SecurityLevel,
    create_sql_validator,
    create_complexity_analyzer
)
from fabric_lakehouse_mcp.security.rate_limiter import RateLimitConfig
from fabric_lakehouse_mcp.errors import ErrorContext


class TestSQLValidator:
    """Test SQL validation and injection prevention."""
    
    def test_valid_select_query(self):
        """Test that valid SELECT queries pass validation."""
        validator = create_sql_validator(SecurityLevel.MODERATE)
        
        # Should not raise any exception
        validator.validate_query("SELECT * FROM users WHERE id = 1")
        validator.validate_query("SELECT name, email FROM users ORDER BY name")
    
    def test_sql_injection_prevention(self):
        """Test that SQL injection attempts are blocked."""
        validator = create_sql_validator(SecurityLevel.MODERATE)
        
        # Test various injection patterns
        with pytest.raises(SQLSecurityError):
            validator.validate_query("SELECT * FROM users; DROP TABLE users;")
        
        # This is actually a valid query, so let's test a more obvious injection
        with pytest.raises(SQLSecurityError):
            validator.validate_query("SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('dir')")
        
        with pytest.raises(SQLSecurityError):
            validator.validate_query("SELECT * FROM users; EXEC xp_cmdshell('dir')")
    
    def test_query_length_validation(self):
        """Test query length limits."""
        validator = create_sql_validator(SecurityLevel.MODERATE)
        
        # Very long query should be rejected
        long_query = "SELECT * FROM users WHERE " + " OR ".join([f"id = {i}" for i in range(10000)])
        
        with pytest.raises(SQLSecurityError):
            validator.validate_query(long_query)
    
    def test_security_levels(self):
        """Test different security levels."""
        strict_validator = create_sql_validator(SecurityLevel.STRICT)
        moderate_validator = create_sql_validator(SecurityLevel.MODERATE)
        permissive_validator = create_sql_validator(SecurityLevel.PERMISSIVE)
        
        # Query that might be blocked in strict mode but allowed in others
        complex_query = "SELECT * FROM (SELECT id FROM users) AS subquery"
        
        # Should work in all modes for this simple subquery
        moderate_validator.validate_query(complex_query)
        permissive_validator.validate_query(complex_query)


class TestQueryComplexityAnalyzer:
    """Test query complexity analysis."""
    
    def test_simple_query_analysis(self):
        """Test analysis of simple queries."""
        analyzer = create_complexity_analyzer()
        
        metrics = analyzer.analyze_query("SELECT * FROM users")
        
        assert metrics.complexity_level.value in ["low", "medium"]
        assert metrics.total_score >= 0
        assert metrics.table_count >= 1
    
    def test_complex_query_analysis(self):
        """Test analysis of complex queries."""
        analyzer = create_complexity_analyzer(max_complexity_score=100)
        
        complex_query = """
        WITH user_stats AS (
            SELECT u.id, COUNT(o.id) as order_count
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            GROUP BY u.id
        )
        SELECT u.name, us.order_count, AVG(o.total) as avg_order
        FROM users u
        JOIN user_stats us ON u.id = us.id
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE us.order_count > 5
        GROUP BY u.name, us.order_count
        ORDER BY avg_order DESC
        """
        
        metrics = analyzer.analyze_query(complex_query)
        
        assert metrics.join_count > 0
        assert metrics.cte_count > 0
        assert metrics.aggregate_count > 0
        assert metrics.complexity_level.value in ["medium", "high"]
    
    def test_complexity_limit_exceeded(self):
        """Test that overly complex queries are rejected."""
        analyzer = create_complexity_analyzer(max_complexity_score=10)
        
        # Very complex query that should exceed limits
        complex_query = """
        SELECT u1.name, u2.name, u3.name
        FROM users u1
        JOIN users u2 ON u1.id = u2.manager_id
        JOIN users u3 ON u2.id = u3.manager_id
        JOIN orders o1 ON u1.id = o1.user_id
        JOIN orders o2 ON u2.id = o2.user_id
        JOIN orders o3 ON u3.id = o3.user_id
        WHERE u1.active = 1 AND u2.active = 1 AND u3.active = 1
        """
        
        with pytest.raises(QueryComplexityError):
            analyzer.analyze_query(complex_query)


class TestAuditLogger:
    """Test audit logging functionality."""
    
    def test_audit_logging_initialization(self):
        """Test audit logger initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = os.path.join(temp_dir, "test_audit.jsonl")
            audit_logger = AuditLogger(audit_file=audit_file)
            
            assert os.path.exists(audit_file)
    
    def test_data_access_logging(self):
        """Test logging of data access operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = os.path.join(temp_dir, "test_audit.jsonl")
            audit_logger = AuditLogger(audit_file=audit_file)
            
            event_id = audit_logger.log_data_access(
                operation="test_query",
                query="SELECT * FROM users",
                user_id="test_user",
                result_count=10,
                execution_time_ms=150
            )
            
            assert event_id is not None
            assert os.path.exists(audit_file)
            
            # Check that audit file contains the event
            with open(audit_file, 'r') as f:
                content = f.read()
                assert "test_query" in content
                assert "test_user" in content
    
    def test_security_violation_logging(self):
        """Test logging of security violations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = os.path.join(temp_dir, "test_audit.jsonl")
            audit_logger = AuditLogger(audit_file=audit_file)
            
            event_id = audit_logger.log_security_violation(
                operation="execute_query",
                violation_type="sql_injection",
                query="SELECT * FROM users; DROP TABLE users;",
                user_id="malicious_user",
                error_message="SQL injection attempt detected"
            )
            
            assert event_id is not None
            
            # Check that audit file contains the violation
            with open(audit_file, 'r') as f:
                content = f.read()
                assert "security_violation" in content
                assert "sql_injection" in content
                assert "malicious_user" in content


class TestRateLimiter:
    """Test rate limiting functionality."""
    
    def test_rate_limiting_basic(self):
        """Test basic rate limiting."""
        config = RateLimitConfig(
            requests_per_minute=5,
            queries_per_minute=3
        )
        rate_limiter = RateLimiter(config)
        
        # Should allow first few requests
        for i in range(3):
            rate_limiter.check_request_limit("test_user")
        
        # Should block after limit
        with pytest.raises(RateLimitExceeded):
            for i in range(10):
                rate_limiter.check_request_limit("test_user")
    
    def test_concurrent_query_limiting(self):
        """Test concurrent query limiting."""
        config = RateLimitConfig(max_concurrent_queries=2)
        rate_limiter = RateLimiter(config)
        
        # Should allow up to max concurrent
        slot1 = rate_limiter.acquire_concurrent_query_slot("test_user")
        slot2 = rate_limiter.acquire_concurrent_query_slot("test_user")
        
        # Should block additional concurrent queries
        with pytest.raises(RateLimitExceeded):
            rate_limiter.acquire_concurrent_query_slot("test_user")
        
        # Should allow after releasing a slot
        rate_limiter.release_concurrent_query_slot("test_user", slot1)
        slot3 = rate_limiter.acquire_concurrent_query_slot("test_user")
        
        # Clean up
        rate_limiter.release_concurrent_query_slot("test_user", slot2)
        rate_limiter.release_concurrent_query_slot("test_user", slot3)
    
    def test_whitelist_functionality(self):
        """Test user whitelisting."""
        config = RateLimitConfig(requests_per_minute=1)
        rate_limiter = RateLimiter(config)
        
        # Add user to whitelist
        rate_limiter.add_to_whitelist("vip_user")
        
        # Whitelisted user should not be rate limited
        for i in range(10):
            rate_limiter.check_request_limit("vip_user")
        
        # Regular user should still be limited
        rate_limiter.check_request_limit("regular_user")
        with pytest.raises(RateLimitExceeded):
            for i in range(5):
                rate_limiter.check_request_limit("regular_user")


class TestIntegratedSecurity:
    """Test integrated security features."""
    
    @patch('fabric_lakehouse_mcp.tools.mcp_tools._get_user_id')
    def test_security_integration(self, mock_get_user_id):
        """Test that all security components work together."""
        mock_get_user_id.return_value = "test_user"
        
        # This would be a more comprehensive integration test
        # that tests the full security pipeline in the MCP tools
        # For now, we just verify the components can be initialized together
        
        validator = create_sql_validator(SecurityLevel.MODERATE)
        analyzer = create_complexity_analyzer()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_file = os.path.join(temp_dir, "test_audit.jsonl")
            audit_logger = AuditLogger(audit_file=audit_file)
            
            config = RateLimitConfig()
            rate_limiter = RateLimiter(config)
            
            # Test a valid query through all security layers
            query = "SELECT name, email FROM users WHERE active = 1"
            
            # Should pass all validations
            validator.validate_query(query)
            metrics = analyzer.analyze_query(query)
            rate_limiter.check_request_limit("test_user")
            rate_limiter.check_query_limit("test_user")
            
            # Log the successful operation
            audit_logger.log_data_access(
                operation="test_integrated_security",
                query=query,
                user_id="test_user",
                status=AuditEventStatus.SUCCESS
            )
            
            assert metrics.complexity_level.value in ["low", "medium"]


if __name__ == "__main__":
    pytest.main([__file__])