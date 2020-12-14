"""UI Components and templates.

Includes:

    * ``static``: static content (css/js/fonts) for the ui components
    * ``error.html``: Template for error messages
    * ``login.html``: Login page for UI login
    * ``user.html``: View the user's information and get an access token
"""
from pathlib import Path
from typing import Any, Dict

from fastapi import Depends
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles


from fastapi_aad_auth import auth, config  # noqa: F401
from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth.mixins import LoggingMixin
from fastapi_aad_auth.ui.jinja import Jinja2Templates


class UI(LoggingMixin):
    """Provides Login endpoint methods, which are then wrapped in a factory method."""
    def __init__(self, config: 'config.Config', authenticator: 'auth.Authenticator', base_context: Dict[str, Any] = None):
        """Initialise the UI based on the provided configuration.

        Keyword Args:
            config (fastapi_aad_auth.config.Config): Authentication configuration (includes ui and routing, as well as AAD Application and Tenant IDs)
            authenticator (fastapi_aad_auth.auth.Authenticator): The authenticator object
            base_context (Dict[str, Any]): Add the authentication to the router
        """
        super().__init__()
        self.config = config
        self._base_context = base_context
        self._authenticator = authenticator

        self.login_template_path = Path(self.config.login_ui.template_file)
        self.user_template_path = Path(self.config.login_ui.user_template_file)
        self.login_templates = Jinja2Templates(directory=str(self.login_template_path.parent))
        self.user_templates = Jinja2Templates(directory=str(self.user_template_path.parent))

    def _login(self, request: Request, *args, **kwargs):
        """Provide the Login UI."""
        context = self._base_context.copy()
        context.update(kwargs)  # type: ignore
        if 'app_name' not in context:
            context['app_name'] = self.config.login_ui.app_name
        if not self.config.enabled or request.user.is_authenticated:
            # This is authenticated so go straight to the homepage
            return RedirectResponse(self.config.routing.home_path)
        context['request'] = request  # type: ignore
        if 'login' not in context or context['login'] is None:  # type: ignore
            post_redirect = self._authenticator._session_validator.pop_post_auth_redirect(request)
            context['login'] = '<br>'.join([provider.get_login_button(post_redirect) for provider in self._authenticator._providers])  # type: ignore
        return self.login_templates.TemplateResponse(self.login_template_path.name, context)  # type: ignore

    def _get_user(self, request: Request, **kwargs):
        """Provide a UI with information on the user."""
        context = self._base_context.copy()  # type: ignore
        context.update(kwargs)
        if 'app_name' not in context:
            context['app_name'] = self.config.login_ui.app_name
        self.logger.debug(f'Getting token for {request.user}')
        context['request'] = request  # type: ignore
        context['token_api_path'] = f'{self.config.routing.user_path}/token'
        if self.config.enabled:
            self.logger.debug(f'Auth {request.auth}')
            try:
                context['user'] = self._authenticator._session_validator.get_state_from_session(request).user
            except ValueError:
                # If we have one provider, we can force the login, otherwise...
                return self.__force_authenticate(request)
        else:
            self.logger.debug('Auth not enabled')
            context['token'] = None  # type: ignore
        return self.user_templates.TemplateResponse(self.user_template_path.name, context)

    def _get_token(self, request: Request, auth_state: AuthenticationState):
        """Return the access token for the user."""
        if not isinstance(auth_state, AuthenticationState):
            user = self.__get_user_from_request(request)
        else:
            user = auth_state.user
        if hasattr(user, 'username'):  # type: ignore
            access_token = self.__get_access_token(user)
            if access_token:
                # We want to get the token for each provider that is authenticated
                return JSONResponse(access_token)   # type: ignore
            else:
                if any([u in request.headers['user-agent'] for u in ['Mozilla', 'Gecko', 'Trident', 'WebKit', 'Presto', 'Edge', 'Blink']]):
                    # If we have one provider, we can force the login, otherwise we need to request which login route
                    return self.__force_authenticate(request)
                else:
                    return JSONResponse('Unable to access token as user has not authenticated via session')
        return RedirectResponse(f'{self.config.routing.landing_path}?redirect=/me/token')

    @property
    def routes(self):
        """Return the routes for the UI.

        Provides the login UI route, and if the routing config has
        the ``user_path`` set, it also provides the user description
        view (and token endpoint)
        """
        async def login(request: Request, *args, **kwargs):
            return self._login(request)

        routes = [Route(self.config.routing.landing_path, endpoint=login, methods=['GET'], name='login'),
                  Mount(self.config.login_ui.static_path, StaticFiles(directory=str(self.config.login_ui.static_directory)), name='static-login')]

        if self.config.routing.user_path:

            @self._authenticator.auth_required()
            async def get_user(request: Request):
                return self._get_user(request)

            async def get_token(request: Request, auth_state: AuthenticationState = Depends(self._authenticator.auth_backend)):
                return self._get_token(request, auth_state)

            routes += [Route(self.config.routing.user_path, endpoint=get_user, methods=['GET'], name='user'),
                       Route(f'{self.config.routing.user_path}/token', endpoint=get_token, methods=['GET'], name='get-token')]

        return routes

    def __force_authenticate(self, request: Request):
        if len(self._authenticator._providers) == 1:
            return self._authenticator._providers[0].authenticator.process_login_request(request, force=True, redirect=request.url.path)
        else:
            return RedirectResponse(f'{self.config.routing.landing_path}?redirect={request.url.path}')

    def __get_access_token(self, user):
        access_token = None
        for provider in self._authenticator._providers:
            try:
                access_token = provider.authenticator.get_access_token(user)
            except ValueError:
                pass
            if access_token is not None:
                break
        return access_token

    def __get_user_from_request(self, request: Request):
        if hasattr(request.user, 'username'):
            user = request.user
        else:
            auth_state = self._authenticator.auth_backend.check(request)
            user = auth_state.user
        return user
