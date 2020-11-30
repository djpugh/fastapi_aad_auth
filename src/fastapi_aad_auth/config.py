"""fastapi_aad_auth configuration options."""
from typing import Dict, List, Optional
import uuid

from pkg_resources import resource_filename
from pydantic import BaseSettings, DirectoryPath, Field, FilePath, HttpUrl, SecretStr, validator


def bool_from_env(env_value):
    """Convert environment variable to boolean."""
    if isinstance(env_value, str):
        env_value = env_value.lower() in ['true', '1']
    return env_value


def list_from_env(env_value):
    """Convert environment variable to list."""
    if isinstance(env_value, str):
        env_value = [u for u in env_value.split(',') if u]
    return env_value


def expand_doc(klass):
    """Expand pydantic model documentation to enable autodoc."""
    docs = ['', '', 'Keyword Args:']
    for name, field in klass.__fields__.items():
        default_str = ''
        if field.default:
            default_str = f' [default: ``{field.default}``]'
        module = field.outer_type_.__module__
        if module != 'builtins':
            if hasattr(field.outer_type_, '__origin__'):
                type_ = f' ({field.outer_type_.__origin__.__name__}) '
            elif not hasattr(field.outer_type_, '__name__'):
                type_ = ''
            else:
                type_ = f' ({module}.{field.outer_type_.__name__}) '
        else:
            type_ = f' ({field.outer_type_.__name__}) '
        env_var = ''
        if 'env' in field.field_info.extra:
            env_var = f' (Can be set by ``{field.field_info.extra["env"]}`` environment variable)'
        docs.append(f'    {name}{type_}: {field.field_info.description}{default_str}{env_var}')
    if klass.__doc__ is None:
        klass.__doc__ = ''
    klass.__doc__ += '\n'.join(docs)
    return klass


@expand_doc
class RoutingConfig(BaseSettings):
    """Configuration for authentication related routing.

    Includes ``logout_path``, ``login_path``, and ``login_redirect_path`` (defaults should
    be fine for most use-cases).

    There are also the ``landing_path`` for the login page, as well as the ``home_path`` for the home
    page (defaults to the application root), and the ``post_logout_path`` for any specific routing
    once a logout has completed.
    """
    login_path: str = Field('/login/oauth', description="Path for initiating the AAD oauth call", env='FASTAPI_AUTH_LOGIN_ROUTE')
    login_redirect_path: str = Field('/login/oauth/redirect', description="Path for handling the AAD redirect call", env='FASTAPI_AUTH_LOGIN_REDIRECT_ROUTE')
    logout_path: str = Field('/logout', description="Path for processing a logout request", env='FASTAPI_AUTH_LOGOUT_ROUTE')
    landing_path: str = Field('/login', description="Path for the login UI page", env='FASTAPI_AUTH_LOGIN_UI_ROUTE')
    user_path: str = Field('/me', description="Path for getting the user view", env='FASTAPI_AUTH_USER_ROUTE')
    home_path: str = Field('/', description="Path for the application home page (default redirect if none provided)",
                           env='APP_HOME_ROUTE')
    post_logout_path: str = Field(None, description="Path for the redirect post logout - defaults to the landing path if not provided",
                                  env='FASTAPI_AUTH_POST_LOGOUT_ROUTE')
    # TODO: Add an API Token Route to get a bearer token interactively.

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
                                    description="The jinja2 template to use",
                                    env='FASTAPI_AUTH_LOGIN_TEMPLATE_FILE')
    error_template_file: FilePath = Field(resource_filename('fastapi_aad_auth.ui', 'error.html'),
                                          description="The jinja2 template to use",
                                          env='FASTAPI_AUTH_LOGIN_ERROR_TEMPLATE_FILE')
    user_template_file: FilePath = Field(resource_filename('fastapi_aad_auth.ui', 'user.html'),
                                          description="The jinja2 template to use",
                                          env='FASTAPI_AUTH_USER_TEMPLATE_FILE')
    static_directory: DirectoryPath = Field(resource_filename('fastapi_aad_auth.ui', 'static'),
                                            description="Static path for the Login UI",
                                            env='FASTAPI_AUTH_LOGIN_STATIC_DIR')
    static_path: str = Field('/static-login',
                             description="Path to mount the login static dir in",
                             env='FASTAPI_AUTH_LOGIN_STATIC_PATH')
    context: Optional[Dict[str, str]] = Field(None, description="Any additional context variables required for the template")

    class Config:  # noqa D106
        env_file = '.env'


@expand_doc
class AADConfig(BaseSettings):
    """Configuration for the AAD application.

    Includes expected claims, application registration, etc.

    Can also provide additional client application ids to accept.

    A list of roles can be provided to accept (requires configuring the
    roles in the AAD application registration manifest)
    """
    client_id: SecretStr = Field(..., description="Application Registration Client ID", env='AAD_CLIENT_ID')
    tenant_id: SecretStr = Field(..., description="Application Registration Tenant ID", env='AAD_TENANT_ID')
    client_secret: Optional[SecretStr] = Field(None, description="Application Registration Client Secret (if required)", env='AAD_CLIENT_SECRET')
    scopes: List[str] = Field(["Read"], description="Additional scopes requested")
    client_app_ids: Optional[List[str]] = Field(None, description="Additional Client App IDs to accept tokens from (when running as a backend service)",
                                                env='AAD_CLIENT_APP_IDS')
    strict: bool = Field(True, description="Check that all claims are provided", env='AAD_STRICT_CLAIM_CHECK')
    api_audience: Optional[str] = Field(None, description="Corresponds to the Application ID URI - used for token validation, defaults to api://{client_id}",
                                        env='AAD_API_AUDIENCE')
    redirect_uri: Optional[HttpUrl] = Field(None, description="The redirect URI to use - overwrites the default path handling etc",
                                            env='AAD_REDIRECT_URI')
    prompt: Optional[str] = Field(None, description="AAD prompt to request", env='AAD_PROMPT')
    domain_hint: Optional[str] = Field(None, description="AAD domain hint", env='AAD_DOMAIN_HINT')
    roles: Optional[List[str]] = Field(None, description="AAD roles required in claims", env='AAD_ROLES')

    class Config:  # noqa D106
        env_file = '.env'

    _validate_strict = validator('strict', allow_reuse=True)(bool_from_env)
    _validate_client_app_ids = validator('client_app_ids', allow_reuse=True)(list_from_env)
    _validate_roles = validator('roles', allow_reuse=True)(list_from_env)


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
    """The overall configuraton for the AAD authentication."""
    enabled: bool = Field(True, description="Enable authentication", env='FASTAPI_AUTH_ENABLED')
    aad: AADConfig = Field(None, description="The AAD configuration to use")
    auth_session: AuthSessionConfig = Field(None, description="The configuration for encoding the authentication information in the session")
    routing: RoutingConfig = Field(None, description="Configuration for routing")
    session: SessionConfig = Field(None, description="Configuration for the session middleware")
    login_ui: LoginUIConfig = Field(None, description="Login UI Configuration")

    class Config:  # noqa D106
        env_file = '.env'

    @validator('aad')
    def _validate_aad(cls, value):
        if value is None:
            value = AADConfig(_env_file=cls.Config.env_file)
        return value

    @validator('auth_session')
    def _validate_auth_session(cls, value):
        if value is None:
            value = AuthSessionConfig(_env_file=cls.Config.env_file)
        return value

    @validator('routing')
    def _validate_routing(cls, value):
        if value is None:
            value = RoutingConfig(_env_file=cls.Config.env_file)
        return value

    @validator('session')
    def _validate_session(cls, value):
        if value is None:
            value = SessionConfig(_env_file=cls.Config.env_file)
        return value

    @validator('login_ui')
    def _validate_login_ui(cls, value):
        if value is None:
            value = LoginUIConfig(_env_file=cls.Config.env_file)
        return value

    _validate_enabled = validator('enabled', allow_reuse=True)(bool_from_env)
