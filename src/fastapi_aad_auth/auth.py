"""Authenticator Class."""
from functools import wraps
import inspect
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI
from starlette.authentication import requires
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import request_response, Route

from fastapi_aad_auth._base.backend import BaseOAuthBackend
from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth._base.validators import SessionValidator
from fastapi_aad_auth.config import Config
from fastapi_aad_auth.errors import AuthenticationError, AuthorisationError, base_error_handler, ConfigurationError, json_error_handler, redirect_error_handler
from fastapi_aad_auth.mixins import LoggingMixin
from fastapi_aad_auth.ui.jinja import Jinja2Templates
from fastapi_aad_auth.utilities import deprecate, is_interactive


_BASE_ROUTES = ['openapi', 'swagger_ui_html', 'swagger_ui_redirect', 'redoc_html']


class Authenticator(LoggingMixin):
    """Authenticator class.

    Creates the key components based on the provided configurations.
    """

    def __init__(self, config: Config = None, add_to_base_routes: bool = True, base_context: Optional[Dict[str, Any]] = None, user_klass: Optional[type] = None):
        """Initialise the Authenticator based on the provided configuration.

        Keyword Args:
            * config (fastapi_aad_auth.config.Config): Authentication configuration (includes ui and routing, as well as AAD Application and Tenant IDs)
            * add_to_base_routes (bool): Add the authentication to the router
            * base_context (Dict[str, Any]): a base context to provide
            * user_klass (type): The user class to use as part of the auth state
        """
        super().__init__()
        if config is None:
            config = Config()
        if user_klass is not None:
            config.user_klass = user_klass
        self.config = config
        if base_context is None:
            base_context = {}
        if self.config.login_ui.context:
            context = self.config.login_ui.context.copy()
            context.update(base_context)
            base_context = context
        if 'app_name' not in base_context:
            base_context['app_name'] = self.config.login_ui.app_name
        if 'static_path' not in base_context:
            base_context['static_path'] = self.config.login_ui.static_path
        self._base_context = base_context
        self._add_to_base_routes = add_to_base_routes
        self._session_validator = self._init_session_validator()
        self._providers = self._init_providers()
        self.auth_backend = self._init_auth_backend()
        self._ui = None
        self._ui_routes = self._init_ui()
        self._auth_routes = self._init_auth_routes()

    def _init_session_validator(self):
        auth_serializer = SessionValidator.get_session_serializer(self.config.auth_session.secret.get_secret_value(),
                                                                  self.config.auth_session.salt.get_secret_value())
        return SessionValidator(auth_serializer, ignore_redirect_routes=self.config.routing.no_redirect_routes)
        # Lets setup the oauth backend

    def _init_providers(self):
        return [u._provider_klass.from_config(session_validator=self._session_validator, config=self.config, provider_config=u) for u in self.config.providers]

    def _init_auth_backend(self):
        validators = [self._session_validator]
        for provider in self._providers:
            validators += provider.validators
        return BaseOAuthBackend(validators, enabled=self.config.enabled)

    def _init_ui(self):
        self._ui = self.config.login_ui.ui_klass(self.config, self, self._base_context)
        return self._ui.routes

    def _init_auth_routes(self):

        async def logout(request: Request):
            self.logger.debug(f'Logging out - request url {request.url}')
            if self.config.enabled:
                self.logger.debug(f'Auth {request.auth}')
                for provider in self._providers:
                    provider.logout(request)
                self._session_validator.logout(request)
            return RedirectResponse(self.config.routing.post_logout_path)
        routes = [Route(self.config.routing.logout_path, endpoint=logout, methods=['GET'], name='logout')]
        for provider in self._providers:
            routes += provider.get_routes(noauth_redirect=self.config.routing.home_path)
        # We have a deprecated behaviour here
        return routes

    def _set_error_handlers(self, app):
        error_template_path = Path(self.config.login_ui.error_template_file)
        error_templates = Jinja2Templates(directory=str(error_template_path.parent))
        if self.config.login_ui.app_name:
            self._base_context['appname'] = self.config.login_ui.app_name
        else:
            self._base_context['appname'] = app.title
        self._base_context['static_path'] = self.config.login_ui.static_path

        @app.exception_handler(ConfigurationError)
        async def configuration_error_handler(request: Request, exc: ConfigurationError) -> Response:
            error_message = "Oops! It seems like the application has not been configured correctly, please contact an admin"
            error_type = 'Authentication Configuration Error'
            status_code = 500
            return base_error_handler(request, exc, error_type, error_message, error_templates, error_template_path, context=self._base_context.copy(), status_code=status_code)

        @app.exception_handler(AuthorisationError)
        async def authorisation_error_handler(request: Request, exc: AuthorisationError) -> Response:
            error_message = "Oops! It seems like you cannot access this information. If this is an error, please contact an admin"
            error_type = 'Authorisation Error'
            status_code = 403
            return base_error_handler(request, exc, error_type, error_message, error_templates, error_template_path, context=self._base_context.copy(), status_code=status_code)

        @app.exception_handler(AuthenticationError)
        async def authentication_error_handler(request: Request, exc: AuthenticationError) -> Response:
            return self._authentication_error_handler(request, exc)

    def _authentication_error_handler(self, request: Request, exc: AuthenticationError) -> Response:
        error_message = "Oops! It seems like you are not correctly authenticated"
        status_code = 401
        self.logger.exception(f'Error {exc} for request {request}')
        if is_interactive(request):
            self._session_validator.set_post_auth_redirect(request, request.url.path)
            kwargs = {}
            if self._session_validator.is_valid_redirect(request.url.path):
                kwargs['redirect'] = request.url.path
            return redirect_error_handler(self.config.routing.landing_path, exc, **kwargs)
        else:
            return json_error_handler(error_message, status_code=status_code)

    def auth_required(self, scopes: str = 'authenticated', redirect: str = 'login'):
        """Decorator to require specific scopes (and redirect to the login ui) for an endpoint.

        This can be used for toggling authentication (e.g. between an internal/external server)
        as well as handling the redirection based on the session information

        Keyword Args:
            scopes: scopes for the starlette requires decorator
            redirect: name of the redirection url
        """

        def wrapper(endpoint):
            if self.config.enabled:

                @wraps(endpoint)
                async def require_endpoint(request: Request, *args, **kwargs):
                    self._session_validator.set_post_auth_redirect(request, request.url.path)

                    @requires(scopes, redirect=redirect)
                    async def req_wrapper(request: Request, *args, **kwargs):
                        return await endpoint(request, *args, **kwargs)

                    return await req_wrapper(request, *args, **kwargs)

                return require_endpoint
            else:
                return endpoint

        return wrapper

    def api_auth_required(self,
                          scopes: str = 'authenticated',
                          allow_session: bool = True,
                          roles: Optional[Union[List['str'], 'str']] = None,
                          groups: Optional[Union[List['str'], 'str']] = None):
        """Decorator to require specific scopes (and redirect to the login ui) for an endpoint.

        This can be used for enabling authentication on an API endpoint, using the fastapi
        dependency injection logic.

        This adds the authentication state to the endpoint arguments as ``auth_state``.

        Keyword Args:
            scopes: scopes for the starlette requires decorator
            allow_session: whether to allow session authentication or not
        """
        def wrapper(endpoint):
            if self.config.enabled:

                # Create the oauth endpoint
                oauth = self.auth_backend.requires_auth(scopes=scopes, allow_session=allow_session, roles=roles, groups=groups)

                # We need to do some signature hackery for fastapi
                endpoint_signature = inspect.signature(endpoint)
                endpoint_args = [v for v in endpoint_signature.parameters.values() if v.default is inspect._empty and v.name != 'auth_state']
                endpoint_kwarg_params = [v for v in endpoint_signature.parameters.values() if v.default is not inspect._empty and v.name != 'auth_state']
                new_params = [inspect.Parameter('auth_state',
                                                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                                default=Depends(oauth),
                                                annotation=AuthenticationState)]

                # This is the actual dectorator

                @wraps(endpoint)
                async def require_endpoint(auth_state: AuthenticationState = Depends(oauth), *args, **kwargs):
                    if ('auth_state' in endpoint_signature.parameters):
                        kwargs['auth_state'] = auth_state
                    return await endpoint(*args, **kwargs)

                # We need to set the signature to have the endpoints signature with the additional auth_state params
                require_endpoint.__signature__ = endpoint_signature.replace(parameters=endpoint_args+new_params+endpoint_kwarg_params)
                # We also want to set the annotation correctly
                require_endpoint.__annotations__['auth_state'] = AuthenticationState
                return require_endpoint
            else:
                return endpoint

        return wrapper

    def app_routes_add_auth(self, app: FastAPI, route_list: List[str], invert: bool = False):
        """Add authentication to specified routes in application router.

        Used for default routes (e.g. api/docs and api/redocs, openapi.json etc)

        Args:
            app: fastapi application
            route_list: list of routes to add authentication to (e.g. api docs, redocs etc)

        Keyword Args:
            invert: Switch between using the route list as a block list or an allow list

        """
        if self.config.enabled:
            routes = app.router.routes
            for i, route in enumerate(routes):
                # Can use allow list or block list (i.e. invert = True sets all except the route list to have auth
                if (route.name in route_list and not invert) or (route.name not in route_list and invert):  # type: ignore
                    route.endpoint = self.auth_required()(route.endpoint)  # type: ignore
                    route.app = request_response(route.endpoint)  # type: ignore
                app.router.routes[i] = route
        return app

    def configure_app(self, app: FastAPI, add_error_handlers=True):
        """Configure the fastapi application to use these authentication handlers.

        Adds authentication middleware, error handler and adds authentication
        to the default routes as well as adding the authentication specific routes

        Args:
            app: fastapi application

        Keyword Args:
            add_error_handlers (bool) : add the error handlers to the app (default is true, but can be set to False to configure specific handling)
        """
        def on_auth_error(request: Request, exc: AuthenticationError):
            return self._authentication_error_handler(request, exc)

        app.add_middleware(AuthenticationMiddleware, backend=self.auth_backend, on_error=on_auth_error)
        if add_error_handlers:
            self._set_error_handlers(app)
        # Check if session middleware is there
        if not any([SessionMiddleware in u.cls.__mro__ for u in app.user_middleware]):
            app.add_middleware(SessionMiddleware, **self.config.session.dict())
        if self._add_to_base_routes:
            self.app_routes_add_auth(app, _BASE_ROUTES)
        app.routes.extend(self._ui_routes)
        app.routes.extend(self._auth_routes)
        # TODO: select a specific provider to use here
        if self.config.enabled:
            app.swagger_ui_init_oauth = self._providers[0].validators[0].init_oauth


_DEPRECATED_VERSION = '0.2.0'


@deprecate(_DEPRECATED_VERSION, replaced_by=f'{Authenticator.__module__}:{Authenticator.__name__}')
class AADAuth(Authenticator):   # noqa: D101
    __doc__ = Authenticator.__doc__

    @property  # type: ignore
    @deprecate(_DEPRECATED_VERSION, replaced_by=f'{Authenticator.__module__}:{Authenticator.__name__}.auth_backend.requires_auth')
    def api_auth_scheme(self):
        """Get the API Authentication Schema."""
        return self.auth_backend.requires_auth()
