"""Validator for token based authentication."""
import logging
from typing import List, Optional

from authlib.jose import errors as jwt_errors, jwk, jwt
from authlib.jose.util import extract_header
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import BaseModel
import requests
from starlette.middleware.authentication import AuthenticationError
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_aad_auth.oauth.state import AuthenticationState, User

logger = logging.getLogger(__name__)


class InitOAuth(BaseModel):
    """OAuth information for openapi docs."""
    clientId: str
    scopes: str
    usePkceWithAuthorizationCodeGrant: bool


class TokenValidator(OAuth2AuthorizationCodeBearer):
    """Validator for token based authentication."""

    def __init__(
        self,
        client_id: str,
        authorizationUrl: str,
        tokenUrl: str,
        api_audience: str = None,
        scheme_name: str = None,
        scopes: dict = None,
        auto_error: bool = False,
        enabled: bool = True,
        use_pkce: bool = True,
        user_klass: type = User
    ):
        """Initialise validator for token based authentication."""
        super().__init__(authorizationUrl=authorizationUrl, tokenUrl=tokenUrl, refreshUrl=api_audience, scheme_name=scheme_name, scopes=scopes, auto_error=auto_error)
        self.client_id = client_id
        self.enabled = enabled
        if api_audience is None:
            api_audience = f"api://{client_id}"
        self.api_audience = api_audience
        self._use_pkce = use_pkce
        self._user_klass = user_klass

    def check(self, request):
        """Check the authentication from the request."""
        token = self.get_token(request)
        if token is None:
            return AuthenticationState.as_unauthenticated(None, None)
        claims = self.validate_token(token)
        user = self._get_user_from_claims(claims)
        return AuthenticationState.authenticate_as(user, None, None)

    def get_token(self, request):
        """Get the token from the request."""
        authorization = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None  # pragma: nocover
        return param

    @property
    def init_oauth(self):
        """Get the openapi docs config."""
        return InitOAuth(clientId=self.client_id, scopes=f'{self.api_audience}/openid', usePkceWithAuthorizationCodeGrant=self._use_pkce).dict()

    def _validate_claims(self, claims, options=None):
        if options is None:
            options = self._claims_options
        claims.options = options
        try:
            claims.validate()
        except jwt_errors.ExpiredTokenError as e:
            logger.error(f'Expired token:\n\t{self._compare_claims(claims)}')
            raise AuthenticationError(f"Token is expired {e.args}")
        except jwt_errors.InvalidClaimError as e:
            logger.error(f'Invalid claims:\n\t{self._compare_claims(claims)}')
            raise AuthenticationError(f"Invalid claims {e.args}")
        except jwt_errors.MissingClaimError as e:
            logger.error(f'Missing claims:\n\t{self._compare_claims(claims)}')
            raise AuthenticationError(f"Missing claims {e.args}")
        except Exception as e:
            logger.exception('Unable to parse error')
            raise AuthenticationError(f"Unable to parse authentication token {e.args}")
        return claims

    @property
    def _claims_options(self):
        options = {"sub": {"essential": True},
                   "aud": {"essential": True, "values": [self.api_audience]},
                   "exp": {"essential": True},
                   "nbf": {"essential": True},
                   "iat": {"essential": True}}
        return options

    def _decode_token(self, token):
        raise NotImplementedError('Implement in base class')

    def validate_token(self, token, options=None):
        """Validate provided token."""
        claims = self._decode_token(token)
        return self._validate_claims(claims, options)

    @staticmethod
    def _compare_claims(claims):
        return '\n\t'.join([f'{key}: {value} - {claims.options.get(key, None)}' for key, value in claims.items()])

    def _get_user_from_claims(self, claims):
        raise NotImplementedError('Implement in sub class')

    async def __call__(self, request: Request) -> Optional[AuthenticationState]:
        """Validate the request authentication"""
        result = self.check(request)
        logger.info(f'Identified state {result}')
        if not result.is_authenticated():
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
                )
        return result


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
            logger.info(f'Getting signing keys from {self.key_url}')
            jwks = requests.get(self.key_url).json()
            token_header = token.split(".")[0].encode()
            unverified_header = extract_header(token_header, jwt_errors.DecodeError)
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    logger.info(f'Identified key {key["kid"]}')
                    return jwk.loads(key)
        except jwt_errors.DecodeError:
            logger.exception('Error parsing signing keys')
        raise AuthenticationError("Unable to parse signing keys")

    def _decode_token(self, token):
        jwk_ = self._get_ms_jwk(token)
        claims = None
        logger.debug(f'Key is {jwk_}')
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
            logger.exception('Unable to parse error')
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
                    logger.error('No appid/azp claims found in token')
                    raise AuthenticationError('No appid/azp claims found in token')
                else:
                    logger.warning('No appid/azp claims found in token - we are ignoring for now')
        return super()._validate_claims(claims, options)

    @property
    def _claims_options(self):
        options = super()._claims_options
        options["iss"] = {"essential": True, "values": [f"https://sts.windows.net/{self.tenant_id}/", f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"]}
        options["aud"] = {"essential": True, "values": [self.api_audience] + [self.client_id] + self.client_app_ids}
        options["azp"] = {"essential": True, "values": [self.client_id] + self.client_app_ids}
        options["appid"] = {"essential": True, "values": [self.client_id] + self.client_app_ids}
        logger.debug(f'Claims options {options}')
        return options

    def _get_user_from_claims(self, claims):
        logger.debug(f'Processing claims: {claims}')
        username_key = 'preferred_username'
        if username_key not in claims:
            username_key = 'unique_name'
        return self._user_klass(name=claims['name'], email=claims[username_key], username=claims[username_key], groups=claims.get('groups', []), roles=claims.get('roles', []))
