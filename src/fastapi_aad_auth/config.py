from typing import Dict, List, Optional
import uuid

from pkg_resources import resource_filename
from pydantic import BaseSettings, DirectoryPath, Field, FilePath, HttpUrl, SecretStr, validator


def bool_from_env(env_value):
    if isinstance(env_value, str):
        env_value = env_value.lower() in ['true', '1']
    return env_value


def list_from_env(env_value):
    if isinstance(env_value, str):
        env_value = [u for u in env_value.split(',') if u]
    return env_value


class RoutingConfig(BaseSettings):

    login_path: str = Field('/login/oauth', env='FASTAPI_AUTH_LOGIN_ROUTE')
    login_redirect_path: str = Field('/login/oauth/redirect', env='FASTAPI_AUTH_LOGIN_REDIRECT_ROUTE')
    logout_path: str = Field('/logout', env='FASTAPI_AUTH_LOGOUT_ROUTE')
    landing_path: str = Field('/login', env='FASTAPI_AUTH_LOGIN_UI_ROUTE')
    home_path: str = Field('/', env='APP_HOME_ROUTE')
    post_logout_path: str = Field(None, env='FASTAPI_AUTH_POST_LOGOUT_ROUTE')

    @validator('post_logout_path', always=True, pre=True)
    def _validate_post_logout_path(cls, value, values):
        if value is None:
            value = values.get('landing_path')
        return value


class LoginUIConfig(BaseSettings):
    app_name: str = Field(None, env='APP_NAME')
    template_file: FilePath = Field(resource_filename('fastapi_aad_auth.ui', 'login.html'), env='FASTAPI_AUTH_LOGIN_TEMPLATE_FILE')
    static_directory: DirectoryPath = Field(resource_filename('fastapi_aad_auth.ui', 'static'), env='FASTAPI_AUTH_LOGIN_STATIC_DIR')
    static_path: str = Field('/static-login', env='FASTAPI_AUTH_LOGIN_STATIC_PATH')
    context: Optional[Dict[str, str]] = Field(None)


class AADConfig(BaseSettings):
    client_id: SecretStr = Field(..., env='AAD_CLIENT_ID')
    tenant_id: SecretStr = Field(..., env='AAD_TENANT_ID')
    client_secret: Optional[SecretStr] = Field(None, env='AAD_CLIENT_SECRET')
    scopes: List[str] = ["Read"]
    client_app_ids: Optional[List[str]] = Field(None, env='AAD_CLIENT_APP_IDS')
    strict: bool = Field(True, env='AAD_STRICT_CLAIM_CHECK')
    api_audience: Optional[str] = Field(None, env='AAD_API_AUDIENCE')
    redirect_uri: Optional[HttpUrl] = Field(None, env='AAD_REDIRECT_URI')
    prompt: Optional[str] = Field(None, env='AAD_PROMPT')
    domain_hint: Optional[str] = Field(None, env='AAD_DOMAIN_HINT')

    _validate_strict = validator('strict', allow_reuse=True)(bool_from_env)
    _validate_client_app_ids = validator('client_app_ids', allow_reuse=True)(list_from_env)


class AuthSessionConfig(BaseSettings):
    secret: SecretStr = Field(str(uuid.uuid4()), env='SESSION_AUTH_SECRET')
    salt: SecretStr = Field(str(uuid.uuid4()), env='SESSION_AUTH_SALT')


class SessionConfig(BaseSettings):
    secret_key: SecretStr = Field(str(uuid.uuid4()), env='SESSION_SECRET')
    session_cookie: str = Field('session', env='SESSION_COOKIE')
    same_site: str = Field('lax', env='SESSION_SAME_SITE')
    https_only: bool = Field(False, env='SESSION_HTTPS_ONLY')
    max_age: int = Field(24*60*60, env='SESSION_MAX_AGE')

    _validate_https_only = validator('https_only', allow_reuse=True)(bool_from_env)


class Config(BaseSettings):

    enabled: bool = Field(True, env='FASTAPI_AUTH_ENABLED')
    aad: AADConfig = None
    auth_session: AuthSessionConfig = None
    routing: RoutingConfig = None
    session: SessionConfig = None
    login_ui: LoginUIConfig = None

    class Config:
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
