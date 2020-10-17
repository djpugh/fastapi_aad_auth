"""Base AAD Authentication Handler."""
from functools import wraps
import logging
from pathlib import Path
from typing import Any, Dict, List

import fastapi.app
from starlette.authentication import requires
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, request_response, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from fastapi_aad_auth.config import Config
from fastapi_aad_auth.errors import ConfigurationError
from fastapi_aad_auth.oauth import AADOAuthBackend


logger = logging.getLogger(__name__)

_BASE_ROUTES = ['openapi', 'swagger_ui_html', 'swagger_ui_redirect', 'redoc_html']


class AADAuth:
    """AAD Authenticator Class.

    Generates and handles adding AAD authentication, routing and middleware

    Includes a decorator for signifying authentication required on fastapi routes, and a basic Login UI with AAD link
    """

    def __init__(self, config: Config = None, add_to_base_routes: bool = True):
        """Initialise the AAD config based on the provided configuration.

        Keyword Args:
            config (fastapi_aad_auth.config.Config): Authentication configuration (includes ui and routing, as well as AAD Application and Tenant IDs)
            add_to_base_routes (bool): Add the authentication to the router
        """
        if config is None:
            config = Config()
        self.config = config
        self.oauth_backend = AADOAuthBackend.from_config(self.config)
        if add_to_base_routes:
            self._add_to_base_routes = True

    def app_routes_add_auth(self, app: fastapi.app.App, route_list: List[str], invert: bool = False):
        """Add authentication to specified routes in application router.

        Used for default routes (e.g. api/docs and api/redocs, openapi.json etc)

        Args:
            app: fastapi application
            route_list: list of routes to add authentication to (e.g. api docs, redocs etc)

        Keyword Args:
            invert: Switch between using the route list as a block list or an allow list

        """
        if self.oauth_backend.enabled:
            routes = app.router.routes
            for i, route in enumerate(routes):
                # Can use allow list or block list (i.e. invert = True sets all except the route list to have auth
                if (route.name in route_list and not invert) or (route.name not in route_list and invert):
                    route.endpoint = self.auth_required()(route.endpoint)
                    route.app = request_response(route.endpoint)
                app.router.routes[i] = route
        return app

    def configure_app(self, app: fastapi.app.App):
        """Configure the fastapi application to use these authentication handlers.

        Adds authentication middleware, error handler and adds authnetication
        to the default routes as well as adding the authentication specific routes

        Args:
            app: fastapi application
        """

        def on_auth_error(request: Request, exc: Exception):
            logger.exception(f'Error {exc} for request {request}')
            self.oauth_backend.authenticator.set_post_auth_redirect(request, request.url.path)
            return RedirectResponse(self.config.routing.landing_path)

        app.add_middleware(AuthenticationMiddleware, backend=self.oauth_backend, on_error=on_auth_error)

        template_path = Path(self.config.login_ui.error_template_file)
        templates = Jinja2Templates(directory=template_path.parent)

        @app.exception_handler(ConfigurationError)
        async def configuration_error_handler(request: Request, exc: ConfigurationError):
            if any([u in request.headers['user-agent'] for u in ['Mozilla', 'Gecko', 'Trident', 'WebKit', 'Presto', 'Edge', 'Blink']]):
                return templates.TemplateResponse(template_path.name,
                                                  {exc: exc},
                                                  status_code=500)
            else:
                return JSONResponse(
                    status_code=500,
                    content={"message": "Oops! It seems like the application has not been configured correctly, please contact an admin"}
                )

        # Check if session middleware is there
        if not any([SessionMiddleware in u.cls.__mro__ for u in app.user_middleware]):
            app.add_middleware(SessionMiddleware, **self.config.session.dict())
        if self._add_to_base_routes:
            self.app_routes_add_auth(app, _BASE_ROUTES)
        app.routes.extend(self.auth_routes)
        if self.config.login_ui.context:
            context = self.config.login_ui.context
        else:
            context = {}
        if self.config.login_ui.app_name:
            context['appname'] = self.config.login_ui.app_name
        else:
            context['appname'] = app.title
        app.routes.extend(self.build_auth_ui(context))

    def auth_required(self, scopes: str = 'authenticated', redirect: str = 'login'):
        """Decorator to require specific scopes (and redirect to the login ui) for an endpoint.

        This can be used for toggling authentication (e.g. between an internal/external server)
        as well as handling the redirection based on the session information

        Keyword Args:
            scopes: scopes for the fastapi requires decorator
            redirect: name of the redirection url
        """

        def wrapper(endpoint):
            if self.config.enabled:

                @wraps(endpoint)
                async def require_endpoint(request: Request, *args, **kwargs):
                    self.oauth_backend.authenticator.set_post_auth_redirect(request, request.url.path)

                    @requires(scopes, redirect=redirect)
                    async def req_wrapper(request: Request, *args, **kwargs):
                        return await endpoint(request, *args, **kwargs)

                    return await req_wrapper(request, *args, **kwargs)

                return require_endpoint
            else:
                return endpoint

        return wrapper

    @property
    def auth_routes(self):
        """Get the default authentication routes and methods.

        Includes login, logout and the login callback
        """

        async def logout(request: Request):
            logger.debug(f'Logging out - request url {request.url}')
            if self.oauth_backend.enabled:
                logger.debug(f'Auth {request.auth}')
                self.oauth_backend.authenticator.logout(request)
            return RedirectResponse(self.config.routing.post_logout_path)

        async def login(request: Request):
            logger.debug(f'Logging in - request url {request.url}')
            if self.oauth_backend.enabled:
                logger.debug(f'Auth {request.auth}')
                return self.oauth_backend.authenticator.process_login_request(request)
            else:
                logger.debug('Auth not enabled')
                return RedirectResponse(self.config.home_path)

        async def login_callback(request: Request):
            logger.info('Processing login callback')
            logger.debug(f'request url {request.url}')
            if self.oauth_backend.enabled:
                return self.oauth_backend.authenticator.process_login_callback(request)
            else:
                logger.debug('Auth not enabled')
                return RedirectResponse(self.config.landing_path)

        routes = [Route(self.config.routing.logout_path, endpoint=logout, methods=['GET'], name='logout'),
                  Route(self.config.routing.login_path, endpoint=login, methods=['GET'], name='login_oauth'),
                  Route(self.config.routing.login_redirect_path, endpoint=login_callback, methods=['GET'], name='login_callback')]

        return routes

    def build_auth_ui(self, context: Dict[str, Any] = None):
        """Build the ui route and static data for the login UI.

        The context kwargs can include ``login`` - button HTML (different to the default Microsoft UI button),
        ``appname`` - the application name (for the login page title)

        Keyword Args:
            contex: a dicitionary of predefined parameters to pass to the Jinja2 Login UI template
        """
        if context is None:
            context = {}
        template_path = Path(self.config.login_ui.template_file)
        templates = Jinja2Templates(directory=template_path.parent)

        async def login(request: Request, *args, **kwargs):
            if not self.oauth_backend.enabled or request.user.is_authenticated:
                # This is authenticated so go straight to the homepage
                return RedirectResponse(self.config.routing.home_path)
            context['request'] = request
            if 'login' not in context or context['login'] is None:
                post_redirect = self.oauth_backend.authenticator.pop_post_auth_redirect(request)
                context['login'] = self.oauth_backend.authenticator.get_login_button(self.config.routing.login_path, post_redirect)
            return templates.TemplateResponse(template_path.name, context)

        routes = [Route(self.config.routing.landing_path, endpoint=login, methods=['GET'], name='login'),
                  Mount(self.config.login_ui.static_path, StaticFiles(directory=self.config.login_ui.static_directory), name='static-login')]

        return routes

    @property
    def api_auth_scheme(self):
        """Get the authentication scheme for the api page."""
        return self.oauth_backend.api_auth_scheme
