"""Base OAuthBackend with token and session validators."""

import logging
from typing import Optional

from starlette.authentication import AuthCredentials, AuthenticationBackend, UnauthenticatedUser
from starlette.requests import Request

from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth._base.validators import TokenValidator
from fastapi_aad_auth.mixins import LoggingMixin


class BaseOAuthBackend(LoggingMixin, AuthenticationBackend):
    """Base OAuthBackend with token and session validators."""

    def __init__(self, validators):
        """Initialise the validators"""
        self.validators = validators[:]
        super().__init__()

    async def authenticate(self, request):
        """Authenticate a request.
        
        Required by starlette authentication middleware
        """
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
            validator = next(self._iter_validators())
            state = validator.check(request)
            self.logger.debug(f'Authentication state {state} from validator {validator}')
        return state

    def _iter_validators(self):
        """Iterate over authentication validators."""
        for validator in self.validators:
            yield validator
