"""Authentication State Handler."""
from enum import Enum
import json
import logging
from typing import List, Optional
import uuid

from itsdangerous import URLSafeSerializer
from itsdangerous.exc import BadSignature
from pydantic import BaseModel, root_validator
from starlette.authentication import AuthCredentials, AuthenticationError, SimpleUser, UnauthenticatedUser


logger = logging.getLogger(__name__)


SESSION_STORE_KEY = 'auth'


class AuthenticationOptions(Enum):
    """Authentication Options."""
    unauthenticated = 0
    not_allowed = -1
    authenticated = 1


class User(BaseModel):
    """User Model."""
    name: str
    email: str
    username: str
    roles: Optional[List[str]] = None
    groups: Optional[List[str]] = None

    @property
    def permissions(self):
        """User Permissions."""
        return []


class AuthenticationState(BaseModel):
    """Authentication State."""
    session_state: str = str(uuid.uuid4())
    state: AuthenticationOptions = AuthenticationOptions.unauthenticated
    user: Optional[User] = None

    @root_validator(pre=True)
    def _validate_user(cls, values):
        if values.get('user', None) is None:
            values['state'] = AuthenticationOptions.unauthenticated
        return values

    def check_session_state(self, session_state):
        """Check state againste session state."""
        if session_state != self.session_state:
            raise AuthenticationError("Session states do not match")
        return True

    def store(self, serializer):
        """Store in serializer."""
        return serializer.dumps(self.json())

    @classmethod
    def load(cls, serializer: URLSafeSerializer, encoded_state: Optional[str] = None):
        """Load from encoded state.

        Args:
            serializer: Serializer object containing the en/decoding secrets
        Keyword Args:
            encoded_state: The encoded state to be decoded
        """
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
    def logout(cls, serializer: URLSafeSerializer, session):
        """Clear the sessions state."""
        state = cls.load_from_session(serializer, session)
        state.user = None
        state.state = AuthenticationOptions.unauthenticated
        session[SESSION_STORE_KEY] = state.store(serializer)

    @classmethod
    def load_from_session(cls, serializer: URLSafeSerializer, session):
        """Load from a session."""
        return cls.load(serializer, session.get(SESSION_STORE_KEY, None))

    def save_to_session(self, serializer: URLSafeSerializer, session):
        """Save to a session."""
        session[SESSION_STORE_KEY] = self.store(serializer)
        return session

    def is_authenticated(self):
        """Check if the state is authenticated."""
        return self.user is not None and self.state == AuthenticationOptions.authenticated

    @property
    def authenticated_user(self):
        """Get the authenticated user."""
        if self.is_authenticated() and self.user:
            if isinstance(self.user, User):
                return SimpleUser(self.user.email)
        return UnauthenticatedUser()

    @property
    def credentials(self):
        """Get the credentials object."""
        if self.user and self.is_authenticated():
            return AuthCredentials(['authenticated'] + self.user.permissions)
        else:
            return AuthCredentials()

    @classmethod
    def authenticate_as(cls, user, serializer, session):
        """Store the authenticated user."""
        state = cls(user=user, state=AuthenticationOptions.authenticated)
        if serializer is not None and session is not None:
            state.save_to_session(serializer, session)
        return state

    @classmethod
    def as_unauthenticated(cls, serializer, session):
        """Store as an un-authenticated user."""
        return cls.authenticate_as(None, serializer, session)
