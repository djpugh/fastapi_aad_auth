import logging
from typing import Optional

from starlette.authentication import AuthenticationBackend, AuthCredentials, UnauthenticatedUser
from starlette.requests import Request

from fastapi_aad_auth.oauth.state import AuthenticationState

logger = logging.getLogger(__name__)


class BaseOAuthBackend(AuthenticationBackend):

    def __init__(self, token_validator, session_validator=None, authenticator=None):
        self.validators = []
        if session_validator:
            self.validators.append(session_validator)
        self.validators.append(token_validator)
        self._token_validator = token_validator
        self.authenticator = authenticator

    async def authenticate(self, request):
        state = self.check(request)
        if state is None:
            return AuthCredentials([]), UnauthenticatedUser()
        return state.credentials, state.authenticated_user

    def is_authenticated(self, request):
        state = self.check(request)
        return state is not None

    async def __call__(self, request: Request) -> Optional[AuthenticationState]:
        return self.check(request)

    def check(self, request: Request) -> Optional[AuthenticationState]:
        state = None
        while state is None:
            validator = next(self.iter_validators())
            state = validator.check(request)
            logger.debug(f'Authentication state {state} from validator {validator}')
        return state

    def iter_validators(self):
        for validator in self.validators:
            yield validator

    @property
    def api_auth_scheme(self):
        return self._token_validator
