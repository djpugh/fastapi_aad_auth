from fastapi_aad_auth.auth import AADAuth  # noqa F401
from fastapi_aad_auth.config import Config  # noqa F401
from fastapi_aad_auth.oauth import AuthenticationState  # noqa F401
from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
