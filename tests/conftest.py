"""Pytest configuration and fixtures."""

import pytest
from fabric_lakehouse_mcp.config.settings import ServerConfig


@pytest.fixture
def mock_config():
    """Mock server configuration for testing."""
    return ServerConfig(
        workspace_id="test-workspace-id",
        lakehouse_id="test-lakehouse-id",
        tenant_id="test-tenant-id",
        auth_method="service_principal",
        client_id="test-client-id",
        client_secret="test-client-secret",
        max_query_timeout=300,
        max_result_rows=1000,
        enable_write_operations=True,
        log_level="DEBUG",
    )