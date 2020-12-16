"""Base validator for token based authentication."""
from authlib.jose import errors as jwt_errors
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import BaseModel
from starlette.middleware.authentication import AuthenticationError
from starlette.requests import Request

from fastapi_aad_auth._base.state import AuthenticationState, User
from fastapi_aad_auth._base.validators.base import Validator


class InitOAuth(BaseModel):
    """OAuth information for openapi docs."""
    clientId: str
    scopes: str
    usePkceWithAuthorizationCodeGrant: bool


class TokenValidator(Validator, OAuth2AuthorizationCodeBearer):  # type: ignore
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

    def check(self, request: Request):
        """Check the authentication from the request."""
        state = AuthenticationState.as_unauthenticated(None, None)
        try:
            token = self.get_token(request)
            if token is not None:
                claims = self.validate_token(token)
                user = self._get_user_from_claims(claims)
                state = AuthenticationState.authenticate_as(user, None, None)
        except Exception:
            self.logger.exception('Error authenticating via token')
        return state

    def get_token(self, request: Request):
        """Get the token from the request."""
        authorization = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise self.not_authenticated
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
            self.logger.error(f'Expired token:\n\t{self._compare_claims(claims)}')
            raise AuthenticationError(f"Token is expired {e.args}")
        except jwt_errors.InvalidClaimError as e:
            self.logger.error(f'Invalid claims:\n\t{self._compare_claims(claims)}')
            raise AuthenticationError(f"Invalid claims {e.args}")
        except jwt_errors.MissingClaimError as e:
            self.logger.error(f'Missing claims:\n\t{self._compare_claims(claims)}')
            raise AuthenticationError(f"Missing claims {e.args}")
        except Exception as e:
            self.logger.exception('Unable to parse error')
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
