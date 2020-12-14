from typing import List, Optional

from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.routing import Route

from fastapi_aad_auth._base.authenticators import SessionAuthenticator
from fastapi_aad_auth._base.validators import Validator
from fastapi_aad_auth.mixins import LoggingMixin
from fastapi_aad_auth.utilities import urls


class Provider(LoggingMixin):
    """Authentication Provider."""
    name: Optional[str] = None

    def __init__(self, validators: List[Validator], authenticator: SessionAuthenticator, enabled: bool = True, oauth_base_route: str = '/oauth'):
        """Initialise the authentication provider."""
        self.validators = validators
        self.authenticator = authenticator
        self.enabled = enabled
        self.oauth_base_route = oauth_base_route
        self._login_url = None
        self._redirect_url = None
        super().__init__()

    def get_routes(self, noauth_redirect='/'):
        """Get the authenticator routes."""

        async def login(request: Request):
            self.logger.debug(f'Logging in with {self.name} - request url {request.url}')
            if self.enabled:
                self.logger.debug(f'Auth {request.auth}')
                return self.authenticator.process_login_request(request)
            else:
                self.logger.debug('Auth not enabled')
                return RedirectResponse(noauth_redirect)

        async def login_callback(request: Request):
            self.logger.info(f'Processing login callback for {self.name}')
            self.logger.debug(f'request url {request.url}')
            if self.enabled:
                return self.authenticator.process_login_callback(request)
            else:
                self.logger.debug('Auth not enabled')
                return RedirectResponse(noauth_redirect)

        routes = [Route(self.login_url,
                        endpoint=login, methods=['GET'], name=f'oauth_login_{self.name}'),
                  Route(self.redirect_url,
                        endpoint=login_callback, methods=['GET'], name=f'oauth_login_{self.name}_callback')]
        return routes

    def _build_oauth_url(self, oauth_base_route, route):
        return urls.append(oauth_base_route, self.name, route)

    def logout(self, request):
        """Logout from the authenticator."""
        pass

    @property
    def login_url(self):
        """Get the login url."""
        if self._login_url is None:
            self._login_url = self._build_oauth_url(self.oauth_base_route, 'login')
        return self._login_url

    @property
    def redirect_url(self):
        """Get the login redirect url."""
        if self._redirect_url is None:
            self._redirect_url = self._build_oauth_url(self.oauth_base_route, 'redirect')
        return self._redirect_url
