"""Session based validator for interactive (UI) sessions."""
import fnmatch
from functools import partial
from typing import List, Optional

from itsdangerous import URLSafeSerializer

from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth._base.validators import Validator


REDIRECT_KEY = 'requested'


class SessionValidator(Validator):
    """Validator for session based authentication."""

    def __init__(self, session_serializer: URLSafeSerializer, ignore_redirect_routes: Optional[List[str]] = None, *args, **kwargs):
        """Initialise validator for session based authentication."""
        self._session_serializer = session_serializer
        if ignore_redirect_routes is None:
            ignore_redirect_routes = []
        self._ignore_redirect_routes = [u for u in ignore_redirect_routes if u]
        super().__init__(*args, **kwargs)  # type: ignore

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
            self.logger.exception('Error authenticating via session')
        return state

    def pop_post_auth_redirect(self, request):
        """Clear post-authentication redirects."""
        return request.session.pop(REDIRECT_KEY, request.query_params.get('redirect', '/'))

    def set_post_auth_redirect(self, request, redirect='/'):
        """Set post-authentication redirects."""
        if not self.is_valid_redirect(redirect):
            redirect = '/'

        request.session[REDIRECT_KEY] = redirect

    def is_valid_redirect(self, redirect):
        """Check if the redirect is not to endpoints that we don't want to redirect to."""
        if redirect is None:
            return False
        return not any(map(partial(fnmatch.fnmatch, redirect), self._ignore_redirect_routes))

    @staticmethod
    def get_session_serializer(secret, salt):
        """Get or Initialise the session serializer."""
        return URLSafeSerializer(secret, salt=salt)

    def logout(self, request):
        """Process a logout request."""
        AuthenticationState.logout(self._session_serializer, request.session)
