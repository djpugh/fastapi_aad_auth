"""UI Components and templates.

Includes:

    * ``static``: static content (css/js/fonts) for the ui components
    * ``error.html``: Template for error messages
    * ``login.html``: Login page for UI login
    * ``user.html``: View the user's information and get an access token
"""
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import Depends
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles


from fastapi_aad_auth import auth, config  # noqa: F401
from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth.mixins import LoggingMixin
from fastapi_aad_auth.ui.jinja import Jinja2Templates
from fastapi_aad_auth.utilities import urls


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
        if base_context is None:
            base_context = dict()
        self._base_context = base_context
        self._authenticator = authenticator

        self.login_template_path = Path(self.config.login_ui.template_file)
        self.user_template_path = Path(self.config.login_ui.user_template_file)
        self.login_templates = Jinja2Templates(directory=str(self.login_template_path.parent))
        self.user_templates = Jinja2Templates(directory=str(self.user_template_path.parent))

    def _login(self, request: Request, *args, **kwargs):
        """Provide the Login UI."""
        if not self.config.enabled or self._authenticator.auth_backend.is_authenticated(request):
            return RedirectResponse(self.config.routing.home_path)
        context = self._base_context.copy()
        context.update(kwargs)  # type: ignore
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
        if not self.config.enabled:
            return RedirectResponse(self.config.routing.home_path)
        context = self._base_context.copy()  # type: ignore
        context.update(kwargs)
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
            context['token_api_path'] = None  # type: ignore
        return self.user_templates.TemplateResponse(self.user_template_path.name, context)

    def _get_token(self, request: Request, auth_state: AuthenticationState, scopes: Optional[List[str]] = None, ajax: bool = False):
        """Return the access token for the user."""
        if not isinstance(auth_state, AuthenticationState):
            user = self.__get_user_from_request(request)
        else:
            user = auth_state.user
        if hasattr(user, 'username'):  # type: ignore
            if scopes is None:
                scopes = request.query_params.get('scopes', None)
            if isinstance(scopes, str):
                scopes = scopes.split(' ')  # type: ignore
            access_token = self.__get_access_token(user, scopes)
            if access_token:
                # We want to get the token for each provider that is authenticated
                return JSONResponse(access_token)   # type: ignore
            else:
                if any([u in request.headers['user-agent'] for u in ['Mozilla', 'Gecko', 'Trident', 'WebKit', 'Presto', 'Edge', 'Blink']]):
                    # If we have one provider, we can force the login, otherwise we need to request which login route
                    return self.__force_authenticate(request, ajax)
                else:
                    return JSONResponse('Unable to access token as user has not authenticated via session')
        redirect = '/me/token'
        if scopes:
            self.logger.debug(f'Getting Access Token with scopes {scopes}')
            redirect = urls.with_query_params(redirect, scopes=scopes)
        return RedirectResponse(urls.with_query_params(self.config.routing.landing_path, redirect=redirect))

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

            async def get_token(request: Request, auth_state: AuthenticationState = Depends(self._authenticator.auth_backend.requires_auth(allow_session=True)), scopes: Optional[List[str]] = None):
                ajax = request.query_params.get('ajax', False)
                return self._get_token(request, auth_state, scopes, ajax)

            routes += [Route(self.config.routing.user_path, endpoint=get_user, methods=['GET'], name='user'),
                       Route(f'{self.config.routing.user_path}/token', endpoint=get_token, methods=['GET'], name='get-token')]

        return routes

    def __force_authenticate(self, request: Request, ajax: bool = False) -> Union[JSONResponse, RedirectResponse]:
        # lets get the full redirect including any query parameters
        redirect = urls.with_query_params(request.url.path, **request.query_params)
        self.logger.debug(f'Request {request.url}')
        self.logger.info(f'Forcing authentication with redirect = {redirect}')
        providers = [u for u in self._authenticator._providers if u.authenticator]
        if len(providers) == 1:
            redirect_url = urls.with_query_params(providers[0].login_url, redirect=redirect, force=True)
        else:
            redirect_url = urls.with_query_params(self.config.routing.login_path, redirect=redirect, force=True)
        if ajax:
            self.logger.debug(f'AJAX is true - handling {redirect_url}')
            url = urls.parse_url(redirect_url)
            query_params = urls.query_params(redirect_url)
            query_params.pop('redirect', None)
            self.logger.debug(f'url {url.path}, query_params {query_params}')
            response = JSONResponse({'redirect': url.path, 'query_params': query_params})  # type: ignore
        else:
            response = RedirectResponse(redirect_url)  # type: ignore
        return response

    def __get_access_token(self, user, scopes=None):
        access_token = None
        for provider in self._authenticator._providers:
            if provider.authenticator:
                try:
                    access_token = provider.authenticator.get_access_token(user, scopes)
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
