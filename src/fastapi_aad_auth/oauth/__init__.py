"""OAuth handlers."""
from fastapi_aad_auth.utilities import deprecate_module  # noqa: F401

_DEPRECATED_VERSION = '0.2.0'


deprecate_module(locals(), _DEPRECATED_VERSION, warn_from='0.1.22')
