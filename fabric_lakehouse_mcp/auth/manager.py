"""Authentication manager for Microsoft Fabric Lakehouse access."""

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Union
from enum import Enum

from azure.identity import (
    ClientSecretCredential,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
    ManagedIdentityCredential,
)
from azure.core.credentials import TokenCredential
from azure.core.exceptions import ClientAuthenticationError

from ..errors import (
    AuthenticationError,
    ConfigurationError,
    ErrorContext,
    get_logger,
    log_error,
    log_operation,
    handle_auth_error,
    retry_with_backoff,
    RetryConfig
)


logger = get_logger(__name__)


class AuthMethod(Enum):
    """Supported authentication methods."""
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    INTERACTIVE = "interactive"
    DEFAULT = "default"


# Remove the local AuthenticationError class since we're using the one from errors module


class AuthenticationManager:
    """Manages authentication to Microsoft Fabric using various methods."""
    
    def __init__(self):
        self._credential: Optional[TokenCredential] = None
        self._auth_method: Optional[AuthMethod] = None
        self._token_cache: Dict[str, Dict] = {}
        self._last_token_refresh: Optional[datetime] = None
        
    @handle_auth_error
    @retry_with_backoff(
        config=RetryConfig(max_attempts=2, initial_delay=1.0),
        retryable_exceptions=[ClientAuthenticationError]
    )
    def authenticate(
        self, 
        method: Union[str, AuthMethod], 
        credentials: Optional[Dict[str, str]] = None
    ) -> TokenCredential:
        """
        Authenticate using the specified method and credentials.
        
        Args:
            method: Authentication method to use
            credentials: Dictionary containing authentication parameters
            
        Returns:
            TokenCredential: Azure credential object
            
        Raises:
            AuthenticationError: If authentication fails
        """
        if isinstance(method, str):
            try:
                method = AuthMethod(method)
            except ValueError:
                context = ErrorContext(operation="authenticate")
                raise AuthenticationError(
                    f"Unsupported authentication method: {method}",
                    context=context
                )
        
        log_operation(logger, f"authenticate_with_{method.value}", method=method.value)
        
        try:
            if method == AuthMethod.SERVICE_PRINCIPAL:
                self._credential = self._authenticate_service_principal(credentials or {})
            elif method == AuthMethod.MANAGED_IDENTITY:
                self._credential = self._authenticate_managed_identity(credentials or {})
            elif method == AuthMethod.INTERACTIVE:
                self._credential = self._authenticate_interactive(credentials or {})
            elif method == AuthMethod.DEFAULT:
                self._credential = self._authenticate_default()
            else:
                context = ErrorContext(operation="authenticate")
                raise AuthenticationError(
                    f"Authentication method {method.value} not implemented",
                    context=context
                )
            
            self._auth_method = method
            self._validate_credential()
            log_operation(logger, "authentication_successful", method=method.value)
            return self._credential
            
        except ClientAuthenticationError as e:
            context = ErrorContext(operation="authenticate", additional_data={"method": method.value})
            auth_error = AuthenticationError(
                f"Azure authentication failed: {str(e)}",
                context=context,
                cause=e
            )
            log_error(logger, auth_error, operation="authenticate")
            raise auth_error
        except Exception as e:
            context = ErrorContext(operation="authenticate", additional_data={"method": method.value})
            auth_error = AuthenticationError(
                f"Unexpected authentication error: {str(e)}",
                context=context,
                cause=e
            )
            log_error(logger, auth_error, operation="authenticate")
            raise auth_error
    
    def _authenticate_service_principal(self, credentials: Dict[str, str]) -> ClientSecretCredential:
        """Authenticate using service principal credentials."""
        required_fields = ["client_id", "client_secret", "tenant_id"]
        missing_fields = [field for field in required_fields if not credentials.get(field)]
        
        if missing_fields:
            context = ErrorContext(
                operation="authenticate_service_principal",
                additional_data={"missing_fields": missing_fields}
            )
            raise ConfigurationError(
                f"Missing required credentials for service principal: {missing_fields}",
                context=context
            )
        
        log_operation(logger, "create_service_principal_credential", tenant_id=credentials["tenant_id"][:8] + "...")
        
        return ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"]
        )
    
    def _authenticate_managed_identity(self, credentials: Dict[str, str]) -> ManagedIdentityCredential:
        """Authenticate using managed identity."""
        client_id = credentials.get("client_id")
        
        if client_id:
            log_operation(logger, "create_user_assigned_managed_identity", client_id=client_id[:8] + "...")
            return ManagedIdentityCredential(client_id=client_id)
        else:
            log_operation(logger, "create_system_assigned_managed_identity")
            return ManagedIdentityCredential()
    
    def _authenticate_interactive(self, credentials: Dict[str, str]) -> InteractiveBrowserCredential:
        """Authenticate using interactive browser flow."""
        tenant_id = credentials.get("tenant_id")
        client_id = credentials.get("client_id")
        
        kwargs = {}
        if tenant_id:
            kwargs["tenant_id"] = tenant_id
        if client_id:
            kwargs["client_id"] = client_id
            
        return InteractiveBrowserCredential(**kwargs)
    
    def _authenticate_default(self) -> DefaultAzureCredential:
        """Authenticate using default Azure credential chain."""
        return DefaultAzureCredential()
    
    def _validate_credential(self) -> None:
        """Validate the current credential by attempting to get a token."""
        if not self._credential:
            context = ErrorContext(operation="validate_credential")
            raise AuthenticationError("No credential available for validation", context=context)
        
        try:
            # Try to get a token for Microsoft Graph (common scope for validation)
            token = self._credential.get_token("https://graph.microsoft.com/.default")
            self._last_token_refresh = datetime.now(timezone.utc)
            log_operation(logger, "credential_validation_successful", level="debug")
        except Exception as e:
            context = ErrorContext(operation="validate_credential")
            auth_error = AuthenticationError(
                f"Credential validation failed: {str(e)}",
                context=context,
                cause=e
            )
            log_error(logger, auth_error, operation="validate_credential")
            raise auth_error
    
    @retry_with_backoff(
        config=RetryConfig(max_attempts=2, initial_delay=0.5),
        retryable_exceptions=[ClientAuthenticationError]
    )
    def refresh_token(self) -> bool:
        """
        Refresh the authentication token if needed.
        
        Returns:
            bool: True if token was refreshed successfully, False otherwise
        """
        if not self._credential:
            log_operation(logger, "token_refresh_skipped", reason="no_credential", level="warning")
            return False
        
        try:
            # Force token refresh by requesting a new token
            token = self._credential.get_token("https://graph.microsoft.com/.default")
            self._last_token_refresh = datetime.now(timezone.utc)
            log_operation(logger, "token_refresh_successful")
            return True
        except Exception as e:
            log_error(logger, e, operation="refresh_token")
            return False
    
    def is_authenticated(self) -> bool:
        """
        Check if the manager has valid authentication.
        
        Returns:
            bool: True if authenticated, False otherwise
        """
        if not self._credential:
            return False
        
        try:
            # Try to get a token to verify authentication is still valid
            self._credential.get_token("https://graph.microsoft.com/.default")
            return True
        except Exception as e:
            log_operation(logger, "authentication_check_failed", error=str(e), level="debug")
            return False
    
    def get_credential(self) -> Optional[TokenCredential]:
        """
        Get the current credential object.
        
        Returns:
            Optional[TokenCredential]: Current credential or None if not authenticated
        """
        return self._credential
    
    def get_auth_method(self) -> Optional[AuthMethod]:
        """
        Get the current authentication method.
        
        Returns:
            Optional[AuthMethod]: Current authentication method or None
        """
        return self._auth_method
    
    def clear_authentication(self) -> None:
        """Clear current authentication state."""
        self._credential = None
        self._auth_method = None
        self._token_cache.clear()
        self._last_token_refresh = None
        logger.info("Authentication state cleared")
    
    @retry_with_backoff(
        config=RetryConfig(max_attempts=2, initial_delay=0.5),
        retryable_exceptions=[ClientAuthenticationError]
    )
    def get_token_for_scope(self, scope: str) -> str:
        """
        Get an access token for a specific scope.
        
        Args:
            scope: The scope to request the token for
            
        Returns:
            str: Access token
            
        Raises:
            AuthenticationError: If not authenticated or token retrieval fails
        """
        if not self._credential:
            context = ErrorContext(operation="get_token_for_scope", additional_data={"scope": scope})
            raise AuthenticationError("Not authenticated", context=context)
        
        try:
            log_operation(logger, "get_token_for_scope", scope=scope, level="debug")
            token = self._credential.get_token(scope)
            return token.token
        except Exception as e:
            context = ErrorContext(operation="get_token_for_scope", additional_data={"scope": scope})
            auth_error = AuthenticationError(
                f"Token retrieval failed for scope {scope}: {str(e)}",
                context=context,
                cause=e
            )
            log_error(logger, auth_error, operation="get_token_for_scope")
            raise auth_error