from fastapi_aad_auth.auth import Authenticator  # noqa F401
from fastapi_aad_auth.config import Config  # noqa F401
from fastapi_aad_auth._base.state import AuthenticationState  # noqa F401
from fastapi_aad_auth._version import get_versions

__version__ = get_versions()['version']
del get_versions
