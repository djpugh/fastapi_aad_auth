"""Base OAuthBackend with token and session validators."""
from typing import List, Optional, Union

from fastapi.security import OAuth2
from starlette.authentication import AuthCredentials, AuthenticationBackend, UnauthenticatedUser
from starlette.requests import Request

from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth._base.validators import SessionValidator, TokenValidator, Validator
from fastapi_aad_auth.errors import AuthorisationError
from fastapi_aad_auth.mixins import LoggingMixin, NotAuthenticatedMixin
from fastapi_aad_auth.utilities import deprecate


class BaseOAuthBackend(NotAuthenticatedMixin, LoggingMixin, AuthenticationBackend):
    """Base OAuthBackend with token and session validators."""

    def __init__(self, validators: List[Validator], enabled: bool = True):
        """Initialise the validators."""
        super().__init__()
        self.enabled = enabled
        self.validators = validators[:]

    async def authenticate(self, request):
        """Authenticate a request.

        Required by starlette authentication middleware
        """
        state = self.check(request, allow_session=True)
        if state is None:
            return AuthCredentials([]), UnauthenticatedUser()
        return state.credentials, state.authenticated_user

    def is_authenticated(self, request: Request):
        """Check if a request is authenticated."""
        state = self.check(request, allow_session=True)
        return state is not None and state.is_authenticated()

    async def __call__(self, request: Request) -> Optional[AuthenticationState]:
        """Check/validate a request."""
        return self.check(request)

    def check(self, request: Request, allow_session=True) -> Optional[AuthenticationState]:
        """Check/validate a request."""
        state = None
        for validator in self.validators:
            if not allow_session and isinstance(validator, SessionValidator):
                self.logger.info('Skipping Session Validator as allow_session is False')
                continue
            state = validator.check(request)
            self.logger.debug(f'Authentication state {state} from validator {validator}')
            if state is not None and state.is_authenticated():
                break
        self.logger.info(f'Identified state {state}')
        return state

    def _iter_validators(self):
        """Iterate over authentication validators."""
        for validator in self.validators:
            yield validator

    def requires_auth(self,
                      scopes: str = 'authenticated',
                      allow_session: bool = False,
                      roles: Optional[Union[List[str], str]] = None,
                      groups: Optional[Union[List[str], str]] = None):
        """Require authentication, use with fastapi Depends."""
        # This is a bit horrible, but is needed for fastapi to get this into OpenAPI (or similar) - it needs to be an OAuth2 object
        # We create this here "dynamically" for each endpoint, as we allow customisation on whether a session is permissible

        if self.enabled:

            class OAuthValidator(OAuth2):
                """OAuthValidator for API Auth."""

                def __init__(self_):
                    """Initialise the validator."""
                    token_validators = [u for u in self.validators if isinstance(u, TokenValidator)]
                    super().__init__(flows=token_validators[0].model.flows)

                async def __call__(self_, request: Request):
                    """Validate a request."""
                    state = self.check(request, allow_session)
                    if state is None or not state.is_authenticated():
                        raise self.not_authenticated
                    elif not state.check_scopes(scopes):
                        raise AuthorisationError(f'Not authorised for this API endpoint - Requires {scopes} scopes')
                    elif not state.check_roles(roles):
                        raise AuthorisationError(f'Not authorised for this API endpoint - Requires {roles} roles')
                    elif not state.check_groups(groups):
                        raise AuthorisationError(f'Not authorised for this API endpoint - Requires {groups} groups')

                    return state

            return OAuthValidator()

        else:
            def noauth(request: Request):
                return AuthenticationState()

        return noauth

    @property  # type: ignore
    @deprecate('0.2.0', replaced_by=f'{__name__}:BaseOAuthBackend.requires_auth', warn_from='0.1.22')
    def api_auth_scheme(self):
        """Get the API Authentication Schema."""
        return self.requires_auth()
