"""AAD OAuth handlers."""
import logging
from typing import List, Optional

from itsdangerous import URLSafeSerializer

from fastapi_aad_auth.config import Config
from fastapi_aad_auth.oauth._base import BaseOAuthBackend
from fastapi_aad_auth.oauth.authenticators import AADSessionAuthenticator
from fastapi_aad_auth.oauth.state import User
from fastapi_aad_auth.oauth.validators import AADSessionValidator, AADTokenValidator, get_session_serializer

logger = logging.getLogger(__name__)


class AADOAuthBackend(BaseOAuthBackend):
    """fastapi auth backend for Azure Active Directory."""

    def __init__(
            self,
            session_serializer: URLSafeSerializer,
            client_id: str,
            tenant_id: str,
            redirect_path: str = '/login/oauth/redirect',
            prompt: Optional[str] = None,
            client_secret: Optional[str] = None,
            scopes: Optional[str] = None,
            enabled: bool = True,
            client_app_ids: Optional[List[str]] = None,
            strict_token: bool = True,
            api_audience: Optional[str] = None,
            redirect_uri: Optional[str] = None,
            domain_hint: Optional[str] = None,
            user_klass: type = User):
        """Initialise the auth backend.

        Args:
            session_serializer: Session serializer object
            client_id: Client ID from Azure App Registration
            tenant_id: Tenant ID to connect to for Azure App Registration

        Keyword Args:
            redirect_path: Path to redirect to on return
            prompt: Prompt options for Azure AD
            client_secret: Client secret value
            scopes: Additional scopes requested
            enabled: Boolean flag to enable this backend
            client_app_ids: List of client apps to accept tokens from
            strict_token: Strictly evaluate token
            api_audience: Api Audience declared in Azure AD App registration
            redirect_uri: Full URI for post authentication callbacks
            domain_hint: Hint for the domain
            user_klass: Class to use as a user.
        """
        self.session_serializer = session_serializer
        self.enabled = enabled
        token_validator = AADTokenValidator(client_id=client_id, tenant_id=tenant_id, api_audience=api_audience,
                                            client_app_ids=client_app_ids, scopes={}, enabled=enabled, strict=strict_token,
                                            user_klass=user_klass)
        session_validator = AADSessionValidator(session_serializer)
        session_authenticator = AADSessionAuthenticator(session_validator=session_validator, token_validator=token_validator,
                                                        client_id=client_id, tenant_id=tenant_id, redirect_path=redirect_path,
                                                        prompt=prompt, client_secret=client_secret, scopes=scopes,
                                                        redirect_uri=redirect_uri, domain_hint=domain_hint)
        super().__init__(token_validator, session_validator, authenticator=session_authenticator)

    @classmethod
    def from_config(cls, config: Config, user_klass: type = User):
        """Load the auth backend from a config.

        Args:
            config: Loaded configuration

        Keyword Args:
            user_klass: The class to use as a user
        """
        auth_serializer = get_session_serializer(config.auth_session.secret.get_secret_value(),
                                                 config.auth_session.salt.get_secret_value())
        client_secret = config.aad.client_secret
        if client_secret is not None:
            client_secret = client_secret.get_secret_value()

        return cls(session_serializer=auth_serializer, client_id=config.aad.client_id.get_secret_value(),
                   tenant_id=config.aad.tenant_id.get_secret_value(),
                   redirect_path=config.routing.login_redirect_path,
                   client_secret=client_secret, enabled=config.enabled,
                   scopes=config.aad.scopes, client_app_ids=config.aad.client_app_ids,
                   strict_token=config.aad.strict, api_audience=config.aad.api_audience,
                   prompt=config.aad.prompt, domain_hint=config.aad.domain_hint,
                   redirect_uri=config.aad.redirect_uri, user_klass=user_klass)
