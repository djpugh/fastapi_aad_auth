from enum import Enum
import json
import logging
from typing import List, Optional
import uuid

from itsdangerous.exc import BadSignature
from pydantic import BaseModel, root_validator
from starlette.authentication import AuthCredentials, AuthenticationError, SimpleUser, UnauthenticatedUser


logger = logging.getLogger(__name__)


SESSION_STORE_KEY = 'auth'


class AuthenticationOptions(Enum):
    unauthenticated = 0
    not_allowed = -1
    authenticated = 1


class User(BaseModel):

    name: str
    email: str
    username: str
    roles: List[str] = []
    groups: List[str] = []

    @property
    def permissions(self):
        return []


class AuthenticationState(BaseModel):
    session_state: str = str(uuid.uuid4())
    state: AuthenticationOptions = AuthenticationOptions.unauthenticated
    user: Optional[User] = None

    @root_validator(pre=True)
    def _validate_user(cls, values):
        if values.get('user', None) is None:
            values['state'] = AuthenticationOptions.unauthenticated
        return values

    def check_session_state(self, session_state):
        if session_state != self.session_state:
            raise AuthenticationError("Session states do not match")
        return True

    def store(self, serializer):
        return serializer.dumps(self.json())

    @classmethod
    def load(cls, serializer, encoded_state=None):
        if encoded_state:
            try:
                state = json.loads(serializer.loads(encoded_state))
                loaded_state = cls(**state)
            except BadSignature:
                loaded_state = cls()
        else:
            loaded_state = cls()
        return loaded_state

    @classmethod
    def logout(cls, serializer, session):
        state = cls.load_from_session(serializer, session)
        state.user = None
        state.state = AuthenticationOptions.unauthenticated
        session[SESSION_STORE_KEY] = state.store(serializer)

    @classmethod
    def load_from_session(cls, serializer, session):
        return cls.load(serializer, session.get(SESSION_STORE_KEY, None))

    def save_to_session(self, serializer, session):
        session[SESSION_STORE_KEY] = self.store(serializer)
        return session

    def is_authenticated(self):
        return self.user is not None and self.state == AuthenticationOptions.authenticated

    @property
    def authenticated_user(self):
        if self.is_authenticated() and self.user:
            if isinstance(self.user, User):
                return SimpleUser(self.user.email)
        return UnauthenticatedUser()

    @property
    def credentials(self):
        if self.user and self.is_authenticated():
            return AuthCredentials(['authenticated'] + self.user.permissions)
        else:
            return AuthCredentials()

    @classmethod
    def authenticate_as(cls, user, serializer, session):
        state = cls(user=user, state=AuthenticationOptions.authenticated)
        if serializer is not None and session is not None:
            state.save_to_session(serializer, session)
        return state

    @classmethod
    def as_unauthenticated(cls, serializer, session):
        return cls.authenticate_as(None, serializer, session)
