"""Tests for configuration management."""

import os
import pytest
from fabric_lakehouse_mcp.config.settings import ServerConfig


def test_server_config_validation(mock_config):
    """Test server configuration validation."""
    # Should not raise any exceptions
    mock_config.validate()


def test_server_config_invalid_timeout():
    """Test server configuration with invalid timeout."""
    config = ServerConfig(
        workspace_id="test",
        lakehouse_id="test",
        tenant_id="test",
        max_query_timeout=-1,  # Invalid
    )
    
    with pytest.raises(ValueError, match="max_query_timeout must be positive"):
        config.validate()


def test_server_config_invalid_auth_method():
    """Test server configuration with invalid auth method."""
    config = ServerConfig(
        workspace_id="test",
        lakehouse_id="test",
        tenant_id="test",
        auth_method="invalid",  # Invalid
    )
    
    with pytest.raises(ValueError, match="auth_method must be one of"):
        config.validate()


def test_server_config_from_env_missing_required():
    """Test configuration creation with missing required environment variables."""
    # Clear environment variables
    for key in ["FABRIC_WORKSPACE_ID", "FABRIC_LAKEHOUSE_ID", "FABRIC_TENANT_ID"]:
        if key in os.environ:
            del os.environ[key]
    
    with pytest.raises(ValueError, match="environment variable is required"):
        ServerConfig.from_env()