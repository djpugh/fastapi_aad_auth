"""fastapi_aad_auth configuration options."""
from typing import Dict, List, Optional, Union
import uuid

from pkg_resources import resource_filename
from pydantic import BaseSettings as _BaseSettings, DirectoryPath, Field, FilePath, SecretStr, validator

from fastapi_aad_auth.providers.aad import AADConfig
from fastapi_aad_auth.utilities import bool_from_env, DeprecatableFieldsMixin, DeprecatedField, expand_doc, klass_from_str


class BaseSettings(DeprecatableFieldsMixin, _BaseSettings):
    """Allow deprecations in the BaseSettings object."""


_DEPRECATION_VERSION = '0.2.0'


@expand_doc
class RoutingConfig(BaseSettings):
    """Configuration for authentication related routing.

    Includes ``logout_path``, ``login_path``, and ``login_redirect_path`` (defaults should
    be fine for most use-cases).

    There are also the ``landing_path`` for the login page, as well as the ``home_path`` for the home
    page (defaults to the application root), and the ``post_logout_path`` for any specific routing
    once a logout has completed.
    """

    login_path: str = DeprecatedField('/login/oauth', description="Path for initiating the AAD oauth call", env='FASTAPI_AUTH_LOGIN_ROUTE', deprecated_in=_DEPRECATION_VERSION, replaced_by='Routing.oauth_base_route', additional_info=' - To access the new behaviour, set this value to None or an empty string')
    login_redirect_path: str = DeprecatedField('/login/oauth/redirect', description="Path for handling the AAD redirect call", env='FASTAPI_AUTH_LOGIN_REDIRECT_ROUTE', deprecated_in=_DEPRECATION_VERSION, replaced_by='Routing.oauth_base_route', additional_info=' - To access the new behaviour, set this value to None or an empty string')
    oauth_base_route: str = Field('/oauth', description="Base Path for initiating the oauth calls", env='FASTAPI_OAUTH_BASE_ROUTE')
    logout_path: str = Field('/logout', description="Path for processing a logout request", env='FASTAPI_AUTH_LOGOUT_ROUTE')
    landing_path: str = Field('/login', description="Path for the login UI page", env='FASTAPI_AUTH_LOGIN_UI_ROUTE')
    user_path: Optional[str] = Field('/me', description="Path for getting the user view", env='FASTAPI_AUTH_USER_ROUTE')
    home_path: str = Field('/', description="Path for the application home page (default redirect if none provided)",
                           env='APP_HOME_ROUTE')
    post_logout_path: str = Field(None, description="Path for the redirect post logout - defaults to the landing path if not provided",
                                  env='FASTAPI_AUTH_POST_LOGOUT_ROUTE')

    class Config:  # noqa D106
        env_file = '.env'

    @validator('post_logout_path', always=True, pre=True)
    def _validate_post_logout_path(cls, value, values):
        if value is None:
            value = values.get('landing_path')
        return value


@expand_doc
class LoginUIConfig(BaseSettings):
    """Configuration for the application Login UI.

    Includes the application name, template file, error template file,
    static directory, path to mount the login static information to, and the context.
    """
    app_name: str = Field(None, description="Application name to show on the Login UI page", env='APP_NAME')
    template_file: FilePath = Field(resource_filename('fastapi_aad_auth.ui', 'login.html'),
                                    description="The jinja2 template to use for the login screen",
                                    env='FASTAPI_AUTH_LOGIN_TEMPLATE_FILE')
    error_template_file: FilePath = Field(resource_filename('fastapi_aad_auth.ui', 'error.html'),
                                          description="The jinja2 template to use for error information",
                                          env='FASTAPI_AUTH_LOGIN_ERROR_TEMPLATE_FILE')
    user_template_file: FilePath = Field(resource_filename('fastapi_aad_auth.ui', 'user.html'),
                                         description="The jinja2 template to use for the user view",
                                         env='FASTAPI_AUTH_USER_TEMPLATE_FILE')
    static_directory: DirectoryPath = Field(resource_filename('fastapi_aad_auth.ui', 'static'),
                                            description="Static path for the UI components",
                                            env='FASTAPI_AUTH_LOGIN_STATIC_DIR')
    static_path: str = Field('/static-login',
                             description="Path to mount the login static dir in",
                             env='FASTAPI_AUTH_LOGIN_STATIC_PATH')
    context: Optional[Dict[str, str]] = Field(None, description="Any additional context variables required for the template")
    ui_klass: type = Field('fastapi_aad_auth.ui:UI',
                           description="UI class to use to handle creating and returning the routes for the login, error and user screens, this will be treated as an import path "
                           "if provided as a string, with the last part the class to load", env='FASTAPI_AUTH_UI_KLASS')

    class Config:  # noqa D106
        env_file = '.env'

    _validate_klass = validator('ui_klass', pre=True, always=True, allow_reuse=True)(klass_from_str)


@expand_doc
class AuthSessionConfig(BaseSettings):
    """Authentication Session configuration.

    Contains secret and salt information (should be set as environment
    variables in a multi-worker/multi-processing environment to enable
    authentication across workers)
    """
    secret: SecretStr = Field(str(uuid.uuid4()), description="Secret used for encoding authentication information",
                              env='SESSION_AUTH_SECRET')
    salt: SecretStr = Field(str(uuid.uuid4()), description="Salt used for encoding authentication information",
                            env='SESSION_AUTH_SALT')

    class Config:  # noqa D106
        env_file = '.env'


@expand_doc
class SessionConfig(BaseSettings):
    """Configuration for session middleware.

    Contains the session secret (should be set as environment variables in
    a multi-worker/multi-processing environment to enable authentication
    across workers)

    Provides configuration for the fastapi session middleware
    """
    secret_key: SecretStr = Field(str(uuid.uuid4()), description="Secret used for the session middleware",
                                  env='SESSION_SECRET')
    session_cookie: str = Field('session', description="Cookie name for the session information",
                                env='SESSION_COOKIE')
    same_site: str = Field('lax', description="Cookie validation mode for the session", env='SESSION_SAME_SITE')
    https_only: bool = Field(False, description="Allow the sessions only with https connections", env='SESSION_HTTPS_ONLY')
    max_age: int = Field(24*60*60, description="Maximum age for a session", env='SESSION_MAX_AGE')

    class Config:  # noqa D106
        env_file = '.env'

    _validate_https_only = validator('https_only', allow_reuse=True)(bool_from_env)


@expand_doc
class Config(BaseSettings):
    """The overall configuration for the AAD authentication.

    Provides the overall configuration and parameters.
    """

    enabled: bool = Field(True, description="Enable authentication", env='FASTAPI_AUTH_ENABLED')
    providers: List[Union[AADConfig]] = Field(None, description="The provider configurations to use")
    aad: Optional[AADConfig] = DeprecatedField(None, description='AAD Configuration information', deprecated_in='0.2.0', replaced_by='Config.providers')
    auth_session: AuthSessionConfig = Field(None, description="The configuration for encoding the authentication information in the session")
    routing: RoutingConfig = Field(None, description="Configuration for routing")
    session: SessionConfig = Field(None, description="Configuration for the session middleware")
    login_ui: LoginUIConfig = Field(None, description="Login UI Configuration")
    user_klass: type = Field('fastapi_aad_auth._base.state:User',
                             description="User class to use within the AADOAuthBackend, this will be treated as an import path "
                             "if provided as a string, with the last part the class to load", env='FASTAPI_AUTH_USER_KLASS')

    class Config:  # noqa D106
        env_file = '.env'

    @validator('providers', always=True, pre=True)
    def _validate_providers(cls, value, values):
        enabled = values.get('enabled', cls.__fields__['enabled'].default)
        if value is None:
            value = []
            if enabled:
                value.append(AADConfig(_env_file=cls.Config.env_file))
        return value

    @validator('aad', always=True, pre=True)
    def _validate_aad(cls, value, values):
        enabled = values.get('enabled', cls.__fields__['enabled'].default)
        if value is None and enabled:
            providers = values.get('providers', [AADConfig(_env_file=cls.Config.env_file)])
            value = [u for u in providers if isinstance(u, AADConfig)][0]
        return value

    @validator('auth_session', always=True, pre=True)
    def _validate_auth_session(cls, value):
        if value is None:
            value = AuthSessionConfig(_env_file=cls.Config.env_file)
        return value

    @validator('routing', always=True, pre=True)
    def _validate_routing(cls, value):
        if value is None:
            value = RoutingConfig(_env_file=cls.Config.env_file)
        return value

    @validator('session', always=True, pre=True)
    def _validate_session(cls, value):
        if value is None:
            value = SessionConfig(_env_file=cls.Config.env_file)
        return value

    @validator('login_ui', always=True, pre=True)
    def _validate_login_ui(cls, value):
        if value is None:
            value = LoginUIConfig(_env_file=cls.Config.env_file)
        return value

    _validate_klass = validator('user_klass', pre=True, always=True, allow_reuse=True)(klass_from_str)
    _validate_enabled = validator('enabled', allow_reuse=True)(bool_from_env)
