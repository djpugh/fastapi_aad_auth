from functools import wraps
import logging
from pathlib import Path

from starlette.authentication import requires
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.routing import request_response, Route, Mount
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from fastapi_aad_auth.config import Config
from fastapi_aad_auth.oauth import AADOAuthBackend


logger = logging.getLogger(__name__)

_BASE_ROUTES = ['openapi', 'swagger_ui_html', 'swagger_ui_redirect', 'redoc_html']


class AADAuth:

    def __init__(self, config: Config = None, add_to_base_routes=True):
        if config is None:
            config = Config()
        self.config = config
        self.oauth_backend = AADOAuthBackend.from_config(self.config)
        if add_to_base_routes:
            self._add_to_base_routes = True

    def app_routes_add_auth(self, app, route_list, ignore=False):
        if self.oauth_backend.enabled:
            routes = app.router.routes
            for i, route in enumerate(routes):
                # Can use allow list or block list (i.e. ignore = True sets all except the route list to have auth
                if (route.name in route_list and not ignore) or (route.name not in route_list and ignore):
                    route.endpoint = self.auth_required()(route.endpoint)
                    route.app = request_response(route.endpoint)
                app.router.routes[i] = route
        return app

    def configure_app(self, app):

        def on_auth_error(request: Request, exc: Exception):
            logger.exception(f'Error {exc} for request {request}')
            self.oauth_backend.authenticator.set_post_auth_redirect(request, request.url.path)
            return RedirectResponse(self.config.routing.landing_path)

        app.add_middleware(AuthenticationMiddleware, backend=self.oauth_backend, on_error=on_auth_error)
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

    def auth_required(self, scopes='authenticated', redirect='login'):

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

        async def logout(request: Request):
            if self.oauth_backend.enabled:
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

    def build_auth_ui(self, context=None):
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
        return self.oauth_backend.api_auth_scheme
