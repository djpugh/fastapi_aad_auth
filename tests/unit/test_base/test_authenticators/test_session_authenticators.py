import unittest
from unittest.mock import MagicMock

from fastapi_aad_auth._base.authenticators.session import RedirectResponse, SessionAuthenticator
from fastapi_aad_auth._base.state import User
from fastapi_aad_auth._base.validators import SessionValidator


class SessionAuthentiatorTestCase(unittest.TestCase):

    def setUp(self):
        self.authenticator = SessionAuthenticator(MagicMock(), MagicMock())
        self.authenticated_state = MagicMock()
        self.authenticated_state.is_authenticated = MagicMock(return_value=True)
        self.unauthenticated_state = MagicMock()
        self.unauthenticated_state.is_authenticated = MagicMock(return_value=False)

    def test_redirect_if_authenticated_true(self):
        response = self.authenticator.redirect_if_authenticated(self.authenticated_state)
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], '/')

    def test_redirect_if_authenticated_alternate_path(self):
        response = self.authenticator.redirect_if_authenticated(self.authenticated_state, redirect='/123')
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], '/123')

    def test_redirect_if_authenticated_false(self):
        response = self.authenticator.redirect_if_authenticated(self.unauthenticated_state)
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], '/login')

    def test_redirect_to_provider_login_mocked(self):
        request = MagicMock()
        self.authenticator._get_authorization_url = MagicMock(return_value="https://www.google.com")
        response = self.authenticator.redirect_to_provider_login(self.unauthenticated_state, request)
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], 'https://www.google.com')
        self.authenticator._get_authorization_url.assert_called_with(request, self.unauthenticated_state.session_state)

    def test__get_authorization_url(self):
        with self.assertRaises(NotImplementedError):
            self.authenticator._get_authorization_url(None, None)

    def test_process_login_request_authenticated(self):
        self.authenticator._session_validator.get_state_from_session = MagicMock(return_value=self.authenticated_state)
        request = MagicMock()
        request.query_params = {}
        response = self.authenticator.process_login_request(request, force=False)
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], '/')
        request.query_params = {'redirect': '/456'}
        response = self.authenticator.process_login_request(request, force=False)
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], '/456')

    def test_process_login_request_authenticated_redirect(self):
        self.authenticator._session_validator.get_state_from_session = MagicMock(return_value=self.authenticated_state)
        request = MagicMock()
        request.query_params = {}
        response = self.authenticator.process_login_request(request, force=False, redirect='/123')
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], '/123')
        request.query_params = {'redirect': '/456'}
        response = self.authenticator.process_login_request(request, force=False, redirect='/123')
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], '/456')

    def test_process_login_request_authenticated_force(self):
        self.authenticator._session_validator.get_state_from_session = MagicMock(return_value=self.authenticated_state)
        request = MagicMock()
        request.query_params = {}
        self.authenticator._get_authorization_url = MagicMock(return_value="https://www.google.com")
        response = self.authenticator.process_login_request(request, force=True, redirect='/123')
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], 'https://www.google.com')
        self.authenticator._get_authorization_url.assert_called_with(request, self.authenticated_state.session_state)
        self.authenticator._session_validator.set_post_auth_redirect.assert_called_with(request, '/123')

    def test_process_login_request_unauthenticated(self):
        self.authenticator._session_validator.get_state_from_session = MagicMock(return_value=self.unauthenticated_state)
        request = MagicMock()
        request.query_params = {}
        self.authenticator._get_authorization_url = MagicMock(return_value="https://www.google.com")
        response = self.authenticator.process_login_request(request, force=False, redirect='/123')
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], 'https://www.google.com')
        self.authenticator._get_authorization_url.assert_called_with(request, self.unauthenticated_state.session_state)
        self.authenticator._session_validator.set_post_auth_redirect.assert_called_with(request, '/123')

    def test_process_login_callback_unauthenticated(self):
        request = MagicMock()
        request.query_params = {}
        response = self.authenticator.process_login_callback(request)
        self.assertIsNone(response)

    def test_process_login_callback_mocked(self):
        auth_state = MagicMock()
        self.authenticator._session_validator.get_state_from_session = MagicMock(return_value=auth_state)
        token = MagicMock()
        self.authenticator._process_code = MagicMock(return_value=token)
        user = User(email='jb@jb.com', name='JB', username='jb@jb.com')
        self.authenticator._get_user_from_token = MagicMock(return_value=user)
        self.authenticator._session_validator.pop_post_auth_redirect = MagicMock(return_value='/123')
        request = MagicMock()
        request.query_params = {'code': 'abc', 'state': 'def'}
        response = self.authenticator.process_login_callback(request)
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers['location'], '/123')
        self.authenticator._session_validator.get_state_from_session.assert_called_with(request)
        auth_state.check_session_state.assert_called_with('def')
        self.authenticator._process_code.assert_called_with(request, auth_state, 'abc')
        self.authenticator._get_user_from_token.assert_called_with(token)

    def test__process_code(self):
        with self.assertRaises(NotImplementedError):
            self.authenticator._process_code(None, None, None)

    def test_get_access_token(self):
        with self.assertRaises(NotImplementedError):
            self.authenticator._process_code(None, None, None)

    def test_get_access_token_from_request_mocked(self):
        self.authenticator._session_validator.get_state_from_session = MagicMock(return_value=self.authenticated_state)
        self.authenticator.get_access_token = MagicMock(return_value={'access_token': '123'})
        request = MagicMock()
        result = self.authenticator.get_access_token_from_request(request)
        self.assertEqual(result, '123')
        self.authenticator.get_access_token.assert_called_with(self.authenticated_state.user)
        self.authenticator._session_validator.get_state_from_session.assert_called_with(request)

    def test_get_access_token_from_request_unauth(self):
        self.authenticator._session_validator.get_state_from_session = MagicMock(return_value=self.unauthenticated_state)
        self.authenticator.get_access_token = MagicMock(return_value={'access_token': '123'})
        request = MagicMock()
        result = self.authenticator.get_access_token_from_request(request)
        self.assertIsNone(result)
        self.authenticator.get_access_token.assert_not_called()

    def test_get_user_from_request(self):
        request = MagicMock()
        self.authenticator._session_validator.get_state_from_session = MagicMock(return_value=self.authenticated_state)
        self.assertEqual(self.authenticator.get_user_from_request(request), self.authenticated_state.user)
        self.authenticator._session_validator.get_state_from_session.assert_called_with(request)

    def test__get_user_from_token(self):
        self.authenticator._token_validator.validate_token = MagicMock(return_value='a')
        self.authenticator._token_validator._get_user_from_claims = MagicMock(return_value='b')
        self.assertEqual(self.authenticator._get_user_from_token('x'), 'b')
        self.authenticator._token_validator.validate_token.assert_called_with('x', options=None)
        self.authenticator._token_validator._get_user_from_claims.assert_called_with('a')

    def test_get_login_button(self):
        button = self.authenticator.get_login_button('https://www.google.com',)
        self.assertIn('<a class="btn', button)
        self.assertIn('href="https://www.google.com?redirect=%2F"', button)
        self.assertIn('>Sign in</a>', button)

    def test_pop_post_auth_redirect(self):
        result = self.authenticator.pop_post_auth_redirect('a', 1)
        self.authenticator._session_validator.pop_post_auth_redirect.assert_called_with('a', 1)
        self.assertEqual(result, self.authenticator._session_validator.pop_post_auth_redirect('a', 1))

    def test_set_post_auth_redirect(self):
        self.authenticator.set_post_auth_redirect('a', 1)
        self.authenticator._session_validator.set_post_auth_redirect.assert_called_with('a', 1)
