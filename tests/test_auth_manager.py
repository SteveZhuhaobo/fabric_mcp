"""Unit tests for AuthenticationManager."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from azure.identity import (
    ClientSecretCredential,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
    ManagedIdentityCredential,
)
from azure.core.exceptions import ClientAuthenticationError
from azure.core.credentials import AccessToken

from fabric_lakehouse_mcp.auth import AuthenticationManager, AuthMethod, AuthenticationError


class TestAuthenticationManager:
    """Test cases for AuthenticationManager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.auth_manager = AuthenticationManager()
    
    def test_init(self):
        """Test AuthenticationManager initialization."""
        assert self.auth_manager._credential is None
        assert self.auth_manager._auth_method is None
        assert self.auth_manager._token_cache == {}
        assert self.auth_manager._last_token_refresh is None
    
    @patch('fabric_lakehouse_mcp.auth.manager.ClientSecretCredential')
    def test_authenticate_service_principal_success(self, mock_credential_class):
        """Test successful service principal authentication."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.return_value = AccessToken("test_token", 1234567890)
        mock_credential_class.return_value = mock_credential
        
        credentials = {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "tenant_id": "test_tenant_id"
        }
        
        # Execute
        result = self.auth_manager.authenticate(AuthMethod.SERVICE_PRINCIPAL, credentials)
        
        # Verify
        assert result == mock_credential
        assert self.auth_manager._credential == mock_credential
        assert self.auth_manager._auth_method == AuthMethod.SERVICE_PRINCIPAL
        mock_credential_class.assert_called_once_with(
            tenant_id="test_tenant_id",
            client_id="test_client_id",
            client_secret="test_client_secret"
        )
        mock_credential.get_token.assert_called_once_with("https://graph.microsoft.com/.default")
    
    def test_authenticate_service_principal_missing_credentials(self):
        """Test service principal authentication with missing credentials."""
        credentials = {
            "client_id": "test_client_id",
            # Missing client_secret and tenant_id
        }
        
        with pytest.raises(AuthenticationError) as exc_info:
            self.auth_manager.authenticate(AuthMethod.SERVICE_PRINCIPAL, credentials)
        
        assert "Missing required credentials" in str(exc_info.value)
        assert "client_secret" in str(exc_info.value)
        assert "tenant_id" in str(exc_info.value)
    
    @patch('fabric_lakehouse_mcp.auth.manager.ManagedIdentityCredential')
    def test_authenticate_managed_identity_system_assigned(self, mock_credential_class):
        """Test managed identity authentication with system-assigned identity."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.return_value = AccessToken("test_token", 1234567890)
        mock_credential_class.return_value = mock_credential
        
        # Execute
        result = self.auth_manager.authenticate(AuthMethod.MANAGED_IDENTITY, {})
        
        # Verify
        assert result == mock_credential
        assert self.auth_manager._auth_method == AuthMethod.MANAGED_IDENTITY
        mock_credential_class.assert_called_once_with()
    
    @patch('fabric_lakehouse_mcp.auth.manager.ManagedIdentityCredential')
    def test_authenticate_managed_identity_user_assigned(self, mock_credential_class):
        """Test managed identity authentication with user-assigned identity."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.return_value = AccessToken("test_token", 1234567890)
        mock_credential_class.return_value = mock_credential
        
        credentials = {"client_id": "test_user_assigned_id"}
        
        # Execute
        result = self.auth_manager.authenticate(AuthMethod.MANAGED_IDENTITY, credentials)
        
        # Verify
        assert result == mock_credential
        mock_credential_class.assert_called_once_with(client_id="test_user_assigned_id")
    
    @patch('fabric_lakehouse_mcp.auth.manager.InteractiveBrowserCredential')
    def test_authenticate_interactive_with_tenant(self, mock_credential_class):
        """Test interactive authentication with tenant ID."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.return_value = AccessToken("test_token", 1234567890)
        mock_credential_class.return_value = mock_credential
        
        credentials = {"tenant_id": "test_tenant_id", "client_id": "test_client_id"}
        
        # Execute
        result = self.auth_manager.authenticate(AuthMethod.INTERACTIVE, credentials)
        
        # Verify
        assert result == mock_credential
        assert self.auth_manager._auth_method == AuthMethod.INTERACTIVE
        mock_credential_class.assert_called_once_with(
            tenant_id="test_tenant_id",
            client_id="test_client_id"
        )
    
    @patch('fabric_lakehouse_mcp.auth.manager.DefaultAzureCredential')
    def test_authenticate_default(self, mock_credential_class):
        """Test default Azure credential authentication."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.return_value = AccessToken("test_token", 1234567890)
        mock_credential_class.return_value = mock_credential
        
        # Execute
        result = self.auth_manager.authenticate(AuthMethod.DEFAULT)
        
        # Verify
        assert result == mock_credential
        assert self.auth_manager._auth_method == AuthMethod.DEFAULT
        mock_credential_class.assert_called_once_with()
    
    def test_authenticate_invalid_method_string(self):
        """Test authentication with invalid method string."""
        with pytest.raises(AuthenticationError) as exc_info:
            self.auth_manager.authenticate("invalid_method", {})
        
        assert "Unsupported authentication method" in str(exc_info.value)
    
    @patch('fabric_lakehouse_mcp.auth.manager.ClientSecretCredential')
    def test_authenticate_credential_validation_failure(self, mock_credential_class):
        """Test authentication failure during credential validation."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.side_effect = ClientAuthenticationError("Invalid credentials")
        mock_credential_class.return_value = mock_credential
        
        credentials = {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "tenant_id": "test_tenant_id"
        }
        
        # Execute & Verify
        with pytest.raises(AuthenticationError) as exc_info:
            self.auth_manager.authenticate(AuthMethod.SERVICE_PRINCIPAL, credentials)
        
        assert "Authentication error" in str(exc_info.value)
    
    def test_refresh_token_no_credential(self):
        """Test token refresh when no credential is available."""
        result = self.auth_manager.refresh_token()
        assert result is False
    
    def test_refresh_token_success(self):
        """Test successful token refresh."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.return_value = AccessToken("new_token", 1234567890)
        self.auth_manager._credential = mock_credential
        
        # Execute
        result = self.auth_manager.refresh_token()
        
        # Verify
        assert result is True
        assert self.auth_manager._last_token_refresh is not None
        mock_credential.get_token.assert_called_with("https://graph.microsoft.com/.default")
    
    def test_refresh_token_failure(self):
        """Test token refresh failure."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.side_effect = ClientAuthenticationError("Token expired")
        self.auth_manager._credential = mock_credential
        
        # Execute
        result = self.auth_manager.refresh_token()
        
        # Verify
        assert result is False
    
    def test_is_authenticated_no_credential(self):
        """Test authentication check when no credential is available."""
        result = self.auth_manager.is_authenticated()
        assert result is False
    
    def test_is_authenticated_valid_credential(self):
        """Test authentication check with valid credential."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.return_value = AccessToken("valid_token", 1234567890)
        self.auth_manager._credential = mock_credential
        
        # Execute
        result = self.auth_manager.is_authenticated()
        
        # Verify
        assert result is True
    
    def test_is_authenticated_invalid_credential(self):
        """Test authentication check with invalid credential."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.side_effect = ClientAuthenticationError("Invalid token")
        self.auth_manager._credential = mock_credential
        
        # Execute
        result = self.auth_manager.is_authenticated()
        
        # Verify
        assert result is False
    
    def test_get_credential(self):
        """Test getting current credential."""
        # Initially None
        assert self.auth_manager.get_credential() is None
        
        # Set credential
        mock_credential = Mock()
        self.auth_manager._credential = mock_credential
        
        assert self.auth_manager.get_credential() == mock_credential
    
    def test_get_auth_method(self):
        """Test getting current authentication method."""
        # Initially None
        assert self.auth_manager.get_auth_method() is None
        
        # Set method
        self.auth_manager._auth_method = AuthMethod.SERVICE_PRINCIPAL
        
        assert self.auth_manager.get_auth_method() == AuthMethod.SERVICE_PRINCIPAL
    
    def test_clear_authentication(self):
        """Test clearing authentication state."""
        # Setup some state
        mock_credential = Mock()
        self.auth_manager._credential = mock_credential
        self.auth_manager._auth_method = AuthMethod.SERVICE_PRINCIPAL
        self.auth_manager._token_cache = {"test": "data"}
        from datetime import timezone
        self.auth_manager._last_token_refresh = datetime.now(timezone.utc)
        
        # Execute
        self.auth_manager.clear_authentication()
        
        # Verify
        assert self.auth_manager._credential is None
        assert self.auth_manager._auth_method is None
        assert self.auth_manager._token_cache == {}
        assert self.auth_manager._last_token_refresh is None
    
    def test_get_token_for_scope_no_credential(self):
        """Test getting token for scope when not authenticated."""
        with pytest.raises(AuthenticationError) as exc_info:
            self.auth_manager.get_token_for_scope("https://test.scope/.default")
        
        assert "Not authenticated" in str(exc_info.value)
    
    def test_get_token_for_scope_success(self):
        """Test successful token retrieval for specific scope."""
        # Setup
        mock_credential = Mock()
        mock_token = AccessToken("scope_token", 1234567890)
        mock_credential.get_token.return_value = mock_token
        self.auth_manager._credential = mock_credential
        
        # Execute
        result = self.auth_manager.get_token_for_scope("https://test.scope/.default")
        
        # Verify
        assert result == "scope_token"
        mock_credential.get_token.assert_called_once_with("https://test.scope/.default")
    
    def test_get_token_for_scope_failure(self):
        """Test token retrieval failure for specific scope."""
        # Setup
        mock_credential = Mock()
        mock_credential.get_token.side_effect = ClientAuthenticationError("Scope not allowed")
        self.auth_manager._credential = mock_credential
        
        # Execute & Verify
        with pytest.raises(AuthenticationError) as exc_info:
            self.auth_manager.get_token_for_scope("https://test.scope/.default")
        
        assert "Token retrieval failed" in str(exc_info.value)


class TestAuthMethod:
    """Test cases for AuthMethod enum."""
    
    def test_auth_method_values(self):
        """Test AuthMethod enum values."""
        assert AuthMethod.SERVICE_PRINCIPAL.value == "service_principal"
        assert AuthMethod.MANAGED_IDENTITY.value == "managed_identity"
        assert AuthMethod.INTERACTIVE.value == "interactive"
        assert AuthMethod.DEFAULT.value == "default"


class TestAuthenticationError:
    """Test cases for AuthenticationError exception."""
    
    def test_authentication_error_creation(self):
        """Test AuthenticationError exception creation."""
        error = AuthenticationError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)