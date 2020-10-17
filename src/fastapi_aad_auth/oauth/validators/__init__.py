"""Validators for different authentication methods."""
from fastapi_aad_auth.oauth.validators.session import SessionValidator as AADSessionValidator, get_session_serializer  # noqa F401
from fastapi_aad_auth.oauth.validators.token import AADTokenValidator  # noqa F401
