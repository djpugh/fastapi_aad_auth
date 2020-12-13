"""Base Session Authenticator for interactive (UI) sessions."""
import base64
import logging

import msal
from pkg_resources import resource_string
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth.errors import ConfigurationError
from fastapi_aad_auth.mixins import LoggingMixin


class SessionAuthenticator(LoggingMixin):
    """Authenticator for interactive (UI) sessions."""

    def __init__(self, session_validator, token_validator):
        """Initialise the session authenticator."""
        self._session_validator = session_validator
        self._token_validator = token_validator
        super().__init__()

    def redirect_if_authenticated(self, auth_state, redirect='/'):
        """Redirect to a target if authenticated."""
        if auth_state.is_authenticated():
            self.logger.info(f'Logged in, redirecting to {redirect}')
        else:
            redirect = '/login'
        return RedirectResponse(redirect)

    def redirect_to_provider_login(self, auth_state, request):
        """Redirect to the provider login."""
        self.logger.debug(f'state {auth_state}')
        auth_state.save_to_session(self._session_validator._session_serializer, request.session)
        authorization_url = self._get_authorization_url(request, auth_state.session_state)
        return RedirectResponse(authorization_url)

    def _get_authorization_url(self, request, session_state):
        raise NotImplementedError('Implement in specific subclass')

    def process_login_request(self, request, force=False, redirect='/'):
        """Process the provider login request."""
        self.logger.debug(f'Logging in - request url {request.url}')
        auth_state = self._session_validator.get_state_from_session(request)
        if auth_state.is_authenticated() and not force:
            self.logger.debug(f'Authenticated - redirecting {auth_state}')
            response = self.redirect_if_authenticated(auth_state)
        else:
            # Set the redirect parameter here
            self._session_validator.set_post_auth_redirect(request, request.query_params.get('redirect', redirect))
            self.logger.debug(f'No Auth state - redirecting to provider login {auth_state}')
            response = self.redirect_to_provider_login(auth_state, request)
        return response

    def process_login_callback(self, request):
        """Process the provider login callback."""
        code = request.query_params.get('code', None)
        state = request.query_params.get('state', None)
        if state is None or code is None:
            return  # not authenticated
        auth_state = self._session_validator.get_state_from_session(request)
        auth_state.check_session_state(state)
        token = self._process_code(request, auth_state, code)
        user = self._get_user_from_token(token)
        authenticated_state = AuthenticationState.authenticate_as(user, self._session_validator._session_serializer, request.session)
        redirect = self._session_validator.pop_post_auth_redirect(request)
        return self.redirect_if_authenticated(authenticated_state, redirect=redirect)

    def _process_code(self, request, auth_state, code):
        raise NotImplementedError('Implement in subclass')

    def get_access_token(self, user):
        """Get the access token for the user."""
        raise NotImplementedError('Implement in subclass')

    def get_access_token_from_request(self, request: Request):
        """Get the access token from a request object."""
        auth_state = self._session_validator.get_state_from_session(request)
        if auth_state.is_authenticated():
            return self.get_access_token(auth_state.user)['access_token']
        return None

    def get_user_from_request(self, request: Request):
        """Get the user from a request object."""
        auth_state = self._session_validator.get_state_from_session(request)
        return auth_state.user

    def _get_user_from_token(self, token, options=None):
        validated_claims = self._token_validator.validate_token(token, options=options)
        return self._token_validator._get_user_from_claims(validated_claims)

    def get_login_button(self, url, post_redirect='/'):
        """Get a UI login button."""
        url = self._add_redirect_to_url(url, post_redirect)
        return f'<a class="btn btn-lg btn-primary btn-block col-8 offset-md-2" href="{url}">Sign in</a>'

    def logout(self, request):
        """Process a logout request if any special behaviour required."""
        pass

    def pop_post_auth_redirect(self, *args, **kwargs):
        """Clear post-authentication redirects."""
        return self._session_validator.pop_post_auth_redirect(*args, **kwargs)

    def set_post_auth_redirect(self, *args, **kwargs):
        """Set post-authentication redirects."""
        self._session_validator.set_post_auth_redirect(*args, **kwargs)

