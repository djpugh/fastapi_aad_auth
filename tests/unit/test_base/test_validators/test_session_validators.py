import asyncio
import unittest
from unittest.mock import MagicMock
import uuid

from fastapi_aad_auth._base.state import AuthenticationState, User, AuthenticationOptions
from fastapi_aad_auth._base.validators.session import REDIRECT_KEY, SessionValidator, URLSafeSerializer
from fastapi_aad_auth.mixins.not_authenticated import HTTPException


class SessionValidatorTestCase(unittest.TestCase):

    def setUp(self):
        self.serializer = SessionValidator.get_session_serializer(str(uuid.uuid4()), str(uuid.uuid4()))
        self.validator = SessionValidator(self.serializer)

    def test_get_state_from_session(self):
        user = User(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        state = AuthenticationState(user=user, state=AuthenticationOptions.authenticated)
        request = MagicMock()
        request.session = {}
        state.save_to_session(self.serializer, request.session)
        result = self.validator.get_state_from_session(request)
        self.assertEqual(result, state)
        state2 = AuthenticationState(user=None, state=AuthenticationOptions.unauthenticated)
        state2.save_to_session(self.serializer, request.session)
        result = self.validator.get_state_from_session(request)
        self.assertEqual(result, state2)

    def test_check_unauthenticated(self):
        request = MagicMock()
        request.session = {}
        result = self.validator.check(request)
        self.assertEqual(result.state, AuthenticationOptions.unauthenticated)
        self.assertIsNone(result.user)
        state = AuthenticationState(user=None, state=AuthenticationOptions.unauthenticated)
        state.save_to_session(self.serializer, request.session)
        result = self.validator.check(request)
        self.assertEqual(result.state, AuthenticationOptions.unauthenticated)
        self.assertIsNone(result.user)
        self.assertEqual(result, state)

    def test_check_authorised(self):
        user = User(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        state = AuthenticationState(user=user, state=AuthenticationOptions.authenticated)
        request = MagicMock()
        request.session = {}
        state.save_to_session(self.serializer, request.session)
        result = self.validator.check(request)
        self.assertEqual(state, result)

    def test_pop_post_auth_redirect(self):
        request = MagicMock()
        request.session = {REDIRECT_KEY: '/ghi'}
        redirect =self.validator.pop_post_auth_redirect(request)
        self.assertEqual(request.session,{})
        self.assertEqual(redirect, '/ghi')

    def test_set_post_auth_redirect_valid(self):
        request = MagicMock()
        request.session = {}
        self.validator.set_post_auth_redirect(request, '/')
        self.assertEqual(request.session[REDIRECT_KEY], '/')
        self.validator.set_post_auth_redirect(request, '/abc')
        self.assertEqual(request.session[REDIRECT_KEY], '/abc')

    def test_set_post_auth_redirect_invalid(self):
        request = MagicMock()
        request.session = {}
        self.validator._ignore_redirect_routes = ['/def']
        self.validator.set_post_auth_redirect(request, '/def')
        self.assertEqual(request.session[REDIRECT_KEY], '/')

    def test_is_valid_redirect_valid(self):
        self.assertTrue(self.validator.is_valid_redirect('/abc'))

    def test_is_valid_redirect_none(self):
        self.assertFalse(self.validator.is_valid_redirect(None))

    def test_is_valid_redirect_invalid(self):
        self.validator._ignore_redirect_routes = ['/def']
        self.assertTrue(self.validator.is_valid_redirect('/abc'))
        self.assertFalse(self.validator.is_valid_redirect('/def'))

    def test_get_session_serializer(self):
        result = SessionValidator.get_session_serializer('a', 'b')
        self.assertIsInstance(result, URLSafeSerializer)
        self.assertEqual(URLSafeSerializer('a', salt='b').loads(result.dumps('x')), 'x')

    def test_logout(self):
        user = User(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        state = AuthenticationState(user=user, state=AuthenticationOptions.authenticated)
        request = MagicMock()
        request.session = {}
        state.save_to_session(self.serializer, request.session)
        self.validator.logout(request)
        logged_out = AuthenticationState.load_from_session(self.serializer, request.session)
        self.assertNotEqual(logged_out, state)
        self.assertEqual(logged_out.state, AuthenticationOptions.unauthenticated)
        self.assertNotEqual(logged_out.user, state.user)
        self.assertIsNone(logged_out.user)
