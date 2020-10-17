"""Base OAuthBackend with token and session validators."""

import logging
from typing import Optional

from starlette.authentication import AuthCredentials, AuthenticationBackend, UnauthenticatedUser
from starlette.requests import Request

from fastapi_aad_auth.oauth.state import AuthenticationState

logger = logging.getLogger(__name__)


class BaseOAuthBackend(AuthenticationBackend):
    """Base OAuthBackend with token and session validators."""

    def __init__(self, token_validator, session_validator=None, authenticator=None):
        """Initialise the validators and authenticator."""
        self.validators = []
        if session_validator:
            self.validators.append(session_validator)
        self.validators.append(token_validator)
        self._token_validator = token_validator
        self.authenticator = authenticator

    async def authenticate(self, request):
        """Authenticate a request."""
        state = self.check(request)
        if state is None:
            return AuthCredentials([]), UnauthenticatedUser()
        return state.credentials, state.authenticated_user

    def is_authenticated(self, request):
        """Check if a request is authenticated."""
        state = self.check(request)
        return state is not None

    async def __call__(self, request: Request) -> Optional[AuthenticationState]:
        """Check/validate a request."""
        return self.check(request)

    def check(self, request: Request) -> Optional[AuthenticationState]:
        """Check/validate a request."""
        state = None
        while state is None:
            validator = next(self.iter_validators())
            state = validator.check(request)
            logger.debug(f'Authentication state {state} from validator {validator}')
        return state

    def iter_validators(self):
        """Iterate over authentication validators."""
        for validator in self.validators:
            yield validator

    @property
    def api_auth_scheme(self):
        """Get the API Authentication Schema."""
        return self._token_validator
