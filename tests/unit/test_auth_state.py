from typing import List
import unittest
import uuid

from fastapi_aad_auth._base.state import AuthenticationState, User, AuthenticationOptions
from fastapi_aad_auth._base.validators import SessionValidator


class User2(User):
    b: int = 2


class User3(User2):

    @property
    def permissions(self):
        return [self.name, 'a']


class AuthenticationStateTestCase(unittest.TestCase):

    def setUp(self):
        self.serializer = SessionValidator.get_session_serializer(str(uuid.uuid4()), str(uuid.uuid4()))

    def test_create(self):
        user = User(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        state = AuthenticationState(user=user, state=AuthenticationOptions.authenticated)
        self.assertIsInstance(state.user, User)
        self.assertEqual(state.user.name, user.name)

    def test_create_custom_user(self):
        user = User2(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        state = AuthenticationState(user=user, state=AuthenticationOptions.authenticated)
        self.assertIsInstance(state.user, User2)
        self.assertEqual(state.user.name, user.name)
        self.assertEqual(state.user.b, user.b)
        self.assertEqual(state.user.b, 2)

    def test_load(self):
        user = User(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        state = AuthenticationState(user=user, state=AuthenticationOptions.authenticated)
        loaded_state = AuthenticationState.load(self.serializer, state.store(self.serializer))
        self.assertIsInstance(state.user, User)
        self.assertEqual(state.user.name, user.name)

    def test_load_custom_user(self):
        user = User2(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        state = AuthenticationState(user=user, state=AuthenticationOptions.authenticated)
        loaded_state = AuthenticationState.load(self.serializer, state.store(self.serializer))
        self.assertIsInstance(state.user, User2)
        self.assertEqual(state.user.name, user.name)
        self.assertEqual(state.user.b, user.b)
        self.assertEqual(state.user.b, 2)

    def test_load_custom_user_permissions(self):
        user = User3(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com', b=4)
        state = AuthenticationState(user=user, state=AuthenticationOptions.authenticated)
        loaded_state = AuthenticationState.load(self.serializer, state.store(self.serializer))
        self.assertIsInstance(state.user, User3)
        self.assertEqual(state.user.name, user.name)
        self.assertEqual(state.user.b, user.b)
        self.assertEqual(state.user.b, 4)
        self.assertEqual(state.user.permissions, ['Joe Bloggs', 'a'])



