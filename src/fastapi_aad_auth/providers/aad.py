"""AAD OAuth handlers."""

import base64
import logging
from typing import List, Optional

import msal
from authlib.jose import errors as jwt_errors, jwk, jwt
from authlib.jose.util import extract_header
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.security.utils import get_authorization_scheme_param
from pkg_resources import resource_string
from pydantic import BaseSettings, Field, HttpUrl, PrivateAttr, SecretStr, validator
import requests
from starlette.middleware.authentication import AuthenticationError
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_aad_auth import urls
from fastapi_aad_auth._base.authenticators import SessionAuthenticator
from fastapi_aad_auth._base.provider import Provider
from fastapi_aad_auth._base.validators import SessionValidator, TokenValidator
from fastapi_aad_auth._base.state import AuthenticationState, User
from fastapi_aad_auth.errors import ConfigurationError
from fastapi_aad_auth.utilities import bool_from_env, expand_doc, list_from_env


class AADSessionAuthenticator(SessionAuthenticator):
    """AAD Authenticator for interactive (UI) sessions."""

    def __init__(
            self,
            session_validator,
            token_validator,
            client_id,
            tenant_id,
            redirect_path='/oauth/aad/redirect',
            prompt=None,
            client_secret=None,
            scopes=None,
            redirect_uri=None,
            domain_hint=None):
        """Initialise AAD Authenticator for interactive (UI) sessions."""
        super().__init__(session_validator, token_validator)
        self._redirect_path = redirect_path
        self._redirect_uri = redirect_uri
        self._domain_hint = domain_hint
        self._prompt = prompt
        self.client_id = client_id
        if scopes is None:
            scopes = [f'api://{self.client_id}']
        elif isinstance(scopes, str):
            scopes = [scopes]
        self._scopes = scopes
        self._authority = f'https://login.microsoftonline.com/{tenant_id}'

        if client_secret is not None:
            self.logger.info('Client secret provided, using Confidential Client')
            self.msal_application = msal.ConfidentialClientApplication(
                client_id,
                authority=self._authority,
                client_credential=client_secret)
        else:
            self.logger.info('Client secret not provided, using Public Client')
            self.msal_application = msal.PublicClientApplication(
                client_id,
                authority=self._authority)

    def _build_redirect_uri(self, request):
        if self._redirect_uri:
            redirect_uri = self._redirect_uri
        else:
            if request.url.port is None or (request.url.port == 80 and request.url.scheme == 'http') or (request.url.port == 443 and request.url.scheme == 'https'):
                port = ''
            else:
                port = f':{request.url.port}'
            redirect_uri = f'{request.url.scheme}://{request.url.hostname}{port}{self._redirect_path}'
        return redirect_uri

    def _process_code(self, request, auth_state, code):
        # Let's build up the redirect_uri
        result = self.msal_application.acquire_token_by_authorization_code(code, scopes=[],
                                                                           redirect_uri=self._build_redirect_uri(request))
        self.logger.debug(f'Result {result}')
        if 'error' in result and result['error']:
            raise ConfigurationError(result)
        return result['id_token']

    def _get_user_from_token(self, token, options=None):
        if options is None:
            options = self._token_validator._claims_options
        options.pop('azp', None)
        options.pop('appid', None)
        return super()._get_user_from_token(token, options=options)

    def _get_authorization_url(self, request, session_state):
        return self.msal_application.get_authorization_request_url([],
                                                                   state=session_state,
                                                                   claims_challenge='{"id_token": {"roles": {"essential": true} } }',
                                                                   redirect_uri=self._build_redirect_uri(request),
                                                                   prompt=self._prompt,
                                                                   domain_hint=self._domain_hint)

    def get_access_token(self, user):
        """Get the access token for the user."""
        result = None
        account = None
        if user.username:
            account = self.msal_application.get_accounts(user.username)
        if account:
            account = account[0]
            self.logger.info(account)
            # This needs you to register the openid api
            result = self.msal_application.acquire_token_silent_with_error(scopes=[f'api://{self.client_id}/openid'], account=account)
            self.logger.info(result)
        if result is None:
            raise ValueError('Token not found')
        else:
            return {'token_type': result['token_type'],
                    'expires_in': result['expires_in'],
                    'access_token': result['access_token']}


class AADTokenValidator(TokenValidator):
    """Validator for AAD token based authentication."""

    def __init__(self,
                 client_id: str,
                 tenant_id: str,
                 api_audience: str = None,
                 scheme_name: str = None,
                 scopes: dict = None,
                 auto_error: bool = False,
                 enabled: bool = True,
                 use_pkce: bool = True,
                 strict: bool = True,
                 client_app_ids: Optional[List[str]] = None,
                 user_klass: type = User):
        """Initialise validator for AAD token based authentication."""
        authorization_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        self.key_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        self.tenant_id = tenant_id
        super().__init__(client_id=client_id, authorizationUrl=authorization_url, tokenUrl=token_url, api_audience=api_audience, scheme_name=scheme_name,
                         scopes=scopes, auto_error=auto_error, enabled=enabled, use_pkce=use_pkce, user_klass=user_klass)
        self.strict = strict
        if client_app_ids is None:
            client_app_ids = []
        self.client_app_ids = client_app_ids

    def _get_ms_jwk(self, token):
        try:
            self.logger.info(f'Getting signing keys from {self.key_url}')
            jwks = requests.get(self.key_url).json()
            token_header = token.split(".")[0].encode()
            unverified_header = extract_header(token_header, jwt_errors.DecodeError)
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    self.logger.info(f'Identified key {key["kid"]}')
                    return jwk.loads(key)
        except jwt_errors.DecodeError:
            self.logger.exception('Error parsing signing keys')
        raise AuthenticationError("Unable to parse signing keys")

    def _decode_token(self, token):
        jwk_ = self._get_ms_jwk(token)
        claims = None
        self.logger.debug(f'Key is {jwk_}')
        try:
            if hasattr(jwk, 'public_bytes'):
                public_bytes = jwk_.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
            else:
                public_bytes = jwk_.raw_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
            claims = jwt.decode(
                token,
                public_bytes,
            )
        except Exception:
            self.logger.exception('Unable to parse error')
            raise AuthenticationError("Unable to parse authentication token")
        return claims

    def _validate_claims(self, claims, options=None):
        if options is None:
            options = self._claims_options
        # We need to do some 1.0/2.0 handling because it doesn't seem to work properly
        # TODO: validate whether we want this claim here?
        # TODO: validate whether the user is approved for the app
        if 'appid' in options and 'azp' in options:
            if 'appid' not in claims:
                options.pop('appid')
            elif 'azp'not in claims:
                options.pop('azp')
            if not ('appid' in claims or 'azp' in claims):
                if self.strict:
                    self.logger.error('No appid/azp claims found in token')
                    raise AuthenticationError('No appid/azp claims found in token')
                else:
                    self.logger.warning('No appid/azp claims found in token - we are ignoring for now')
        return super()._validate_claims(claims, options)

    @property
    def _claims_options(self):
        options = super()._claims_options
        options["iss"] = {"essential": True, "values": [f"https://sts.windows.net/{self.tenant_id}/", f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"]}
        options["aud"] = {"essential": True, "values": [self.api_audience] + [self.client_id] + self.client_app_ids}
        options["azp"] = {"essential": True, "values": [self.client_id] + self.client_app_ids}
        options["appid"] = {"essential": True, "values": [self.client_id] + self.client_app_ids}
        self.logger.debug(f'Claims options {options}')
        return options

    def _get_user_from_claims(self, claims):
        self.logger.debug(f'Processing claims: {claims}')
        username_key = 'preferred_username'
        if username_key not in claims:
            username_key = 'unique_name'
        if 'name' not in claims and 'appid' in claims:
            # This is an application/service principal
            return self._user_klass(name=claims['appid'], email='', username=claims['appid'], groups=claims.get('groups', None), roles=claims.get('roles', None))

        else:
            return self._user_klass(name=claims['name'], email=claims[username_key], username=claims[username_key], groups=claims.get('groups', None), roles=claims.get('roles', None))


class AADProvider(Provider):
    """fastapi auth backend for Azure Active Directory."""
    name: str = 'aad'

    def __init__(
            self,
            session_validator: SessionValidator,
            client_id: str,
            tenant_id: str,
            redirect_path: str = '/login/oauth/redirect',
            prompt: Optional[str] = None,
            client_secret: Optional[str] = None,
            scopes: Optional[List[str]] = None,
            enabled: bool = True,
            client_app_ids: Optional[List[str]] = None,
            strict_token: bool = True,
            api_audience: Optional[str] = None,
            redirect_uri: Optional[str] = None,
            domain_hint: Optional[str] = None,
            user_klass: type = User,
            oauth_base_route: str = '/oauth'):
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
        redirect_path = self._build_oauth_url(oauth_base_route, 'redirect')
        token_validator = AADTokenValidator(client_id=client_id, tenant_id=tenant_id, api_audience=api_audience,
                                            client_app_ids=client_app_ids, scopes={}, enabled=enabled, strict=strict_token,
                                            user_klass=user_klass)
        session_authenticator = AADSessionAuthenticator(session_validator=session_validator, token_validator=token_validator,
                                                        client_id=client_id, tenant_id=tenant_id, redirect_path=redirect_path,
                                                        prompt=prompt, client_secret=client_secret, scopes=scopes,
                                                        redirect_uri=redirect_uri, domain_hint=domain_hint)
        super().__init__(validators=[token_validator], authenticator=session_authenticator, enabled=enabled, oauth_base_route=oauth_base_route)

    @classmethod
    def from_config(cls, session_validator, config: 'Config', provider_config: 'AADConfig', user_klass: Optional[type] = None, oauth_base_route: str = '/oauth'):
        """Load the auth backend from a config.

        Args:
            session_validator (SessionValidator): the session validator to use
            config: Loaded configuration

        Keyword Args:
            user_klass: The class to use as a user
        """
        client_secret = provider_config.client_secret
        if client_secret is not None:
            client_secret = client_secret.get_secret_value()  # type: ignore
        
        if user_klass is None:
            user_klass = config.user_klass
        logging.warning(f'*******{user_klass}')

        return cls(session_validator=session_validator, client_id=provider_config.client_id.get_secret_value(),
                   tenant_id=provider_config.tenant_id.get_secret_value(),
                   client_secret=client_secret, enabled=config.enabled,   # type: ignore
                   scopes=provider_config.scopes, client_app_ids=provider_config.client_app_ids,
                   strict_token=provider_config.strict, api_audience=provider_config.api_audience,
                   prompt=provider_config.prompt, domain_hint=provider_config.domain_hint,
                   redirect_uri=provider_config.redirect_uri, user_klass=user_klass, oauth_base_route=oauth_base_route)

    def get_login_button(self, post_redirect='/'):
        """Get the AAD Login Button."""
        url = urls.with_redirect(self.login_url, post_redirect)
        logo = base64.b64encode(resource_string('fastapi_aad_auth.providers', 'ms-logo.png')).decode()
        return f'<a class="btn btn-lg btn-light btn-ms" href="{url}"><div class="row align-items-center justify-center login-ms"><img alt="Microsoft Logo" class="rounded splash-ms" src="data:image/png;base64,{logo}" />Sign in with Microsoft Work Account</div></a>'


@expand_doc
class AADConfig(BaseSettings):
    """Configuration for the AAD application.

    Includes expected claims, application registration, etc.

    Can also provide additional client application ids to accept.

    A list of roles can be provided to accept (requires configuring the
    roles in the AAD application registration manifest)
    """
    client_id: SecretStr = Field(..., description="Application Registration Client ID", env='AAD_CLIENT_ID')
    tenant_id: SecretStr = Field(..., description="Application Registration Tenant ID", env='AAD_TENANT_ID')
    client_secret: Optional[SecretStr] = Field(None, description="Application Registration Client Secret (if required)", env='AAD_CLIENT_SECRET')
    scopes: List[str] = Field(["Read"], description="Additional scopes requested")
    client_app_ids: Optional[List[str]] = Field(None, description="Additional Client App IDs to accept tokens from (when running as a backend service)",
                                                env='AAD_CLIENT_APP_IDS')
    strict: bool = Field(True, description="Check that all claims are provided", env='AAD_STRICT_CLAIM_CHECK')
    api_audience: Optional[str] = Field(None, description="Corresponds to the Application ID URI - used for token validation, defaults to api://{client_id}",
                                        env='AAD_API_AUDIENCE')
    redirect_uri: Optional[HttpUrl] = Field(None, description="The redirect URI to use - overwrites the default path handling etc",
                                            env='AAD_REDIRECT_URI')
    prompt: Optional[str] = Field(None, description="AAD prompt to request", env='AAD_PROMPT')
    domain_hint: Optional[str] = Field(None, description="AAD domain hint", env='AAD_DOMAIN_HINT')
    roles: Optional[List[str]] = Field(None, description="AAD roles required in claims", env='AAD_ROLES')
    _provider_klass: type = PrivateAttr(AADProvider)

    class Config:  # noqa D106
        env_file = '.env'
        

    _validate_strict = validator('strict', allow_reuse=True)(bool_from_env)
    _validate_client_app_ids = validator('client_app_ids', allow_reuse=True)(list_from_env)
    _validate_roles = validator('roles', allow_reuse=True)(list_from_env)