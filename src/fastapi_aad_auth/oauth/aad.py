"""AAD handlers."""
from fastapi_aad_auth._base.validators import SessionValidator as _SessionValidator
from fastapi_aad_auth.auth import Authenticator as _Authenticator
from fastapi_aad_auth.config import AADConfig, Config  # noqa: F401
from fastapi_aad_auth.providers.aad import AADProvider as _AADProvider
from fastapi_aad_auth.utilities import deprecate, deprecate_module

_DEPRECATED_VERSION = '0.2.0'


deprecate_module(locals(), _DEPRECATED_VERSION, replaced_by=f'{_AADProvider.__module__} and {_Authenticator.__module__}')


@deprecate(_DEPRECATED_VERSION, replaced_by=f'{_AADProvider.__module__}:{_AADProvider.__name__}')
class AADOAuthBackend(_AADProvider):  # noqa: D101
    __doc__ = _AADProvider.__doc__

    @classmethod
    @deprecate(_DEPRECATED_VERSION, replaced_by=f'{_AADProvider.__module__}:{_AADProvider.__name__}.from_config and {_Authenticator.__module__}:{_Authenticator.__name__}')
    def from_config(cls, config: Config):
        """Load the auth backend from a config.

        Args:
            config: Loaded configuration

        Keyword Args:
            user_klass: The class to use as a user
        """
        session_validator = _SessionValidator.get_session_serializer(config.auth_session.secret.get_secret_value(),
                                                                     config.auth_session.salt.get_secret_value())
        provider = super().from_config(session_validator, config, config.aad)
        return provider.auth_backend
