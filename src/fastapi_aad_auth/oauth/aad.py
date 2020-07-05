import logging

from fastapi_aad_auth.oauth._base import BaseOAuthBackend
from fastapi_aad_auth.oauth.authenticators import AADSessionAuthenticator
from fastapi_aad_auth.oauth.state import User
from fastapi_aad_auth.oauth.validators import AADSessionValidator, AADTokenValidator, get_session_serializer

logger = logging.getLogger(__name__)


class AADOAuthBackend(BaseOAuthBackend):

    def __init__(
            self,
            session_serializer,
            client_id,
            tenant_id,
            redirect_path='/login/oauth/redirect',
            prompt=None,
            client_secret=None,
            scopes=None,
            enabled=True,
            client_app_ids=None,
            strict_token=True,
            api_audience=None,
            redirect_uri=None,
            domain_hint=None,
            user_klass=User):

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
    def from_config(cls, config, user_klass=User):
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
