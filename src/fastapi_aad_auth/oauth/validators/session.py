"""Validator for interactive (UI) sessions."""

import logging

from itsdangerous import URLSafeSerializer

from fastapi_aad_auth.oauth.state import AuthenticationState

logger = logging.getLogger(__name__)

REDIRECT_KEY = 'requested'


def get_session_serializer(secret, salt):
    """Get or Initialise the session serializer."""
    return URLSafeSerializer(secret, salt=salt)


class SessionValidator:
    """Validator for session based authentication."""

    def __init__(self, session_serializer: URLSafeSerializer, *args, **kwargs):
        """Initialise validator for session based authentication."""
        self._session_serializer = session_serializer
        super().__init__(*args, **kwargs)

    def get_state_from_session(self, request):
        """Get the session from the request."""
        auth_state = AuthenticationState.load_from_session(self._session_serializer, request.session)
        return auth_state

    def check(self, request):
        """Check the authentication from the request."""
        try:
            state = AuthenticationState.load_from_session(self._session_serializer, request.session)
        except Exception:
            state = AuthenticationState.as_unauthenticated(self._session_serializer, request.session)
            logger.exception('Error authenticating via session')
        return state

    def pop_post_auth_redirect(self, request):
        """Clear post-authentication redirects."""
        return request.session.pop(REDIRECT_KEY, '/')

    def set_post_auth_redirect(self, request, redirect='/'):
        """Set post-authentication redirects."""
        request.session[REDIRECT_KEY] = redirect
