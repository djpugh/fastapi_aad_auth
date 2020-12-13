"""Base OAuthBackend with token and session validators."""

import logging
from typing import Optional

from fastapi.security import OAuth2, OAuth2AuthorizationCodeBearer
from starlette.authentication import AuthCredentials, AuthenticationBackend, UnauthenticatedUser
from starlette.requests import Request

from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth._base.validators import SessionValidator, TokenValidator
from fastapi_aad_auth.mixins import LoggingMixin, NotAuthenticatedMixin


class BaseOAuthBackend(NotAuthenticatedMixin, LoggingMixin, AuthenticationBackend):
    """Base OAuthBackend with token and session validators."""

    def __init__(self, validators):
        """Initialise the validators"""
        super().__init__()
        self.validators = validators[:]

    async def authenticate(self, request):
        """Authenticate a request.
        
        Required by starlette authentication middleware
        """
        state = await self.check(request, allow_session=True)
        if state is None:
            return AuthCredentials([]), UnauthenticatedUser()
        return state.credentials, state.authenticated_user

    def is_authenticated(self, request):
        """Check if a request is authenticated."""
        state = self.check(request)
        return state is not None and state.is_authenticated()

    async def __call__(self, request: Request) -> Optional[AuthenticationState]:
        """Check/validate a request."""
        state = self.check(request)
        return state

    async def check(self, request: Request, allow_session=True) -> Optional[AuthenticationState]:
        """Check/validate a request."""
        state = None
        for validator in self.validators:
            if not allow_session and isinstance(validator, SessionValidator):
                self.logger.info('Skipping Session Validator as allow_session is False')
                continue
            state = validator.check(request)
            self.logger.debug(f'Authentication state {state} from validator {validator}')
            if state is not None:
                break
        self.logger.info(f'Identified state {state}')
        return state

    def _iter_validators(self):
        """Iterate over authentication validators."""
        for validator in self.validators:
            yield validator

    def requires_auth(self, allow_session=False):

        # This is a bit horrible, but is needed for fastapi to get this into OpenAPI (or similar) - it needs to be an OAuth2 object
        # We create this here "dynamically" for each endpoint, as we allow customisation on whether a session is permissible

        class OAuthValidator(OAuth2AuthorizationCodeBearer):
            

            def __init__(self_):
                token_validators = [u for u in self.validators if isinstance(u, TokenValidator)]
                super().__init__(authorizationUrl=token_validators[0].model.flows.authorizationCode.authorizationUrl,
                                tokenUrl=token_validators[0].model.flows.authorizationCode.tokenUrl,
                                scopes=token_validators[0].model.flows.authorizationCode.scopes,
                                refreshUrl=token_validators[0].model.flows.authorizationCode.refreshUrl)
        
            async def __call__(self_,request: Request):
                state = await self.check(request, allow_session)
                if state is None or not state.is_authenticated():
                    raise self.not_authenticated
                return state
        
        return OAuthValidator()
