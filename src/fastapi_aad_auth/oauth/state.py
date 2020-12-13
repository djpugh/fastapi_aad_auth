"""Authentication State."""
from fastapi_aad_auth._base.state import AuthenticationState as _AuthenticationState, User as _User
from fastapi_aad_auth.utilities import deprecate, deprecate_module

_DEPRECATED_VERSION = '0.2.0'


deprecate_module(locals(), _DEPRECATED_VERSION, replaced_by=_AuthenticationState.__module__)


@deprecate(_DEPRECATED_VERSION, replaced_by=f'{_AuthenticationState.__module__}:{_AuthenticationState.__name__}')
class AuthenticationState(_AuthenticationState):  # noqa: D101
    __doc__ = _AuthenticationState.__doc__


@deprecate(_DEPRECATED_VERSION, replaced_by=f'{_User.__module__}:{_User.__name__}')
class User(_User):  # noqa: D101
    __doc__ = _User.__doc__
