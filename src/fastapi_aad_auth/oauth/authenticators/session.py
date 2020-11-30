"""Authenticator for interactive (UI) sessions."""
import base64
import logging

import msal
from pkg_resources import resource_string
from starlette.responses import RedirectResponse

from fastapi_aad_auth.errors import ConfigurationError
from fastapi_aad_auth.oauth.state import AuthenticationState

logger = logging.getLogger(__name__)


class SessionAuthenticator:
    """Authenticator for interactive (UI) sessions."""

    def __init__(self, session_validator, token_validator):
        """Initialise the session authenticator."""
        self._session_validator = session_validator
        self._token_validator = token_validator

    def redirect_if_authenticated(self, auth_state, redirect='/'):
        """Redirect to a target if authenticated."""
        if auth_state.is_authenticated():
            logger.info(f'Logged in, redirecting to {redirect}')
        else:
            redirect = '/login'
        return RedirectResponse(redirect)

    def redirect_to_provider_login(self, auth_state, request):
        """Redirect to the provider login."""
        logger.debug(f'state {auth_state}')
        auth_state.save_to_session(self._session_validator._session_serializer, request.session)
        authorization_url = self._get_authorization_url(request, auth_state.session_state)
        return RedirectResponse(authorization_url)

    def _get_authorization_url(self, request, session_state):
        raise NotImplementedError('Implement in specific subclass')

    def process_login_request(self, request, force=False, redirect='/'):
        """Process the provider login request."""
        logger.debug(f'Logging in - request url {request.url}')
        auth_state = self._session_validator.get_state_from_session(request)
        if auth_state.is_authenticated() and not force:
            logger.debug(f'Authenticated - redirecting {auth_state}')
            response = self.redirect_if_authenticated(auth_state)
        else:
            # Set the redirect parameter here
            self._session_validator.set_post_auth_redirect(request, request.query_params.get('redirect', redirect))
            logger.debug(f'No Auth state - redirecting to provider login {auth_state}')
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
        raise NotImplementedError('Implement in subclass')

    def get_access_token_from_request(self, request):
        auth_state = self._session_validator.get_state_from_session(request)
        if auth_state.is_authenticated():
            return self.get_access_token(auth_state.user)['access_token']
        return None

    def get_user_from_request(self, request):
        auth_state = self._session_validator.get_state_from_session(request)
        return auth_state.user

    def _get_user_from_token(self, token, options=None):
        validated_claims = self._token_validator.validate_token(token, options=options)
        return self._token_validator._get_user_from_claims(validated_claims)

    def _add_redirect_to_url(self, url, post_redirect=None):
        if post_redirect is not None:
            url = f'{url}?redirect={post_redirect}'
        return url

    def get_login_button(self, url, post_redirect='/'):
        """Get a UI login button."""
        url = self._add_redirect_to_url(url, post_redirect)
        return f'<a class="btn btn-lg btn-primary btn-block col-8 offset-md-2" href="{url}">Sign in</a>'

    def logout(self, request):
        """Process a logout request."""
        AuthenticationState.logout(self._session_validator._session_serializer, request.session)

    def pop_post_auth_redirect(self, *args, **kwargs):
        """Clear post-authentication redirects."""
        return self._session_validator.pop_post_auth_redirect(*args, **kwargs)

    def set_post_auth_redirect(self, *args, **kwargs):
        """Set post-authentication redirects."""
        self._session_validator.set_post_auth_redirect(*args, **kwargs)


class AADSessionAuthenticator(SessionAuthenticator):
    """AAD Authenticator for interactive (UI) sessions."""

    def __init__(
            self,
            session_validator,
            token_validator,
            client_id,
            tenant_id,
            redirect_path='/login/oauth/redirect',
            prompt=None,
            client_secret=None,
            scopes=None,
            redirect_uri=None,
            domain_hint=None):
        """Initialise AAD Authenticator for interactive (UI) sessions."""
        super().__init__(session_validator, token_validator)
        self._redirect_path = redirect_path
        self._redirect_uri = redirect_uri
        self._domain_hint = domain_hint
        self._prompt = prompt
        self.client_id = client_id
        if scopes is None:
            scopes = [f'api://{self.client_id}']
        elif isinstance(scopes, str):
            scopes = [scopes]
        self._scopes = scopes
        self._authority = f'https://login.microsoftonline.com/{tenant_id}'

        if client_secret is not None:
            logger.info('Client secret provided, using Confidential Client')
            self.msal_application = msal.ConfidentialClientApplication(
                client_id,
                authority=self._authority,
                client_credential=client_secret)
        else:
            logger.info('Client secret not provided, using Public Client')
            self.msal_application = msal.PublicClientApplication(
                client_id,
                authority=self._authority)

    def _build_redirect_uri(self, request):
        if self._redirect_uri:
            redirect_uri = self._redirect_uri
        else:
            if request.url.port is None or (request.url.port == 80 and request.url.scheme == 'http') or (request.url.port == 443 and request.url.scheme == 'https'):
                port = ''
            else:
                port = f':{request.url.port}'
            redirect_uri = f'{request.url.scheme}://{request.url.hostname}{port}{self._redirect_path}'
        return redirect_uri

    def _process_code(self, request, auth_state, code):
        # Let's build up the redirect_uri
        result = self.msal_application.acquire_token_by_authorization_code(code, scopes=[],
                                                                           redirect_uri=self._build_redirect_uri(request))
        logger.debug(f'Result {result}')
        if 'error' in result and result['error']:
            raise ConfigurationError(result)
        return result['id_token']

    def _get_user_from_token(self, token, options=None):
        if options is None:
            options = self._token_validator._claims_options
        options.pop('azp', None)
        options.pop('appid', None)
        return super()._get_user_from_token(token, options=options)

    def _get_authorization_url(self, request, session_state):
        return self.msal_application.get_authorization_request_url([],
                                                                   state=session_state,
                                                                   claims_challenge='{"id_token": {"roles": {"essential": true} } }',
                                                                   redirect_uri=self._build_redirect_uri(request),
                                                                   prompt=self._prompt,
                                                                   domain_hint=self._domain_hint)

    def get_login_button(self, url, post_redirect='/'):
        """Get the AAD Login Button."""
        url = self._add_redirect_to_url(url, post_redirect)
        logo = base64.b64encode(resource_string('fastapi_aad_auth.oauth', 'ms-logo.png')).decode()
        return f'<a class="btn btn-lg btn-light btn-ms" href="{url}"><div class="row align-items-center justify-center login-ms"><img alt="Microsoft Logo" class="rounded splash-ms" src="data:image/png;base64,{logo}" />Sign in with Microsoft Work Account</div></a>'

    def get_access_token(self, user):
        result = None
        account = None
        if user.username:
            account = self.msal_application.get_accounts(user.username)
        if account:
            account = account[0]
            logger.info(account)
            # This needs you to register the openid api
            result = self.msal_application.acquire_token_silent_with_error(scopes=[f'api://{self.client_id}/openid'], account=account)
            logger.info(result)
        if result is None:
            raise ValueError('Token not found')
        else:
            return {'token_type': result['token_type'],
                    'expires_in': result['expires_in'],
                    'access_token': result['access_token']}