"""Authentication State Handler."""
from enum import Enum
import importlib
import json
from typing import List, Optional, Union
import uuid

from itsdangerous import URLSafeSerializer
from itsdangerous.exc import BadSignature
from pydantic import Field, root_validator, validator
from starlette.authentication import AuthCredentials, SimpleUser, UnauthenticatedUser

from fastapi_aad_auth.errors import AuthenticationError
from fastapi_aad_auth.mixins import LoggingMixin
from fastapi_aad_auth.utilities import InheritableBaseModel, InheritablePropertyBaseModel


SESSION_STORE_KEY = 'auth'


class AuthenticationOptions(Enum):
    """Authentication Options."""
    unauthenticated = 0
    not_allowed = -1
    authenticated = 1


class User(InheritablePropertyBaseModel):
    """User Model."""
    name: str = Field(..., description='Full name')
    email: str = Field(..., description='User email')
    username: str = Field(..., description='Username')
    roles: Optional[List[str]] = Field(None, description='Any roles provided')
    groups: Optional[List[str]] = Field(None, description='Any groups provided')
    scopes: Optional[List[str]] = Field(None, description='Token scopes provided')

    @property
    def permissions(self):
        """User Permissions."""
        permissions = []
        if self.scopes:
            for scope in self.scopes:
                if not scope.startswith('.'):
                    permissions.append(scope)
        if self.groups:
            for group in self.groups:
                if not group.startswith('.'):
                    permissions.append(group)
        if self.roles:
            for role in self.roles:
                if not role.startswith('.'):
                    permissions.append(role)
        return permissions[:]

    @property
    def klass(self):
        """Return the user klass information for loading from a session."""
        return f'{self.__class__.__module__}:{self.__class__.__name__}'

    @validator('scopes', always=True, pre=True)
    def _validate_scopes(cls, value):
        if isinstance(value, str):
            value = value.split(' ')
        return value

    @validator('roles', always=True, pre=True)
    def _validate_roles(cls, value):
        if isinstance(value, str):
            value = value.split(' ')
        return value

    @validator('groups', always=True, pre=True)
    def _validate_groups(cls, value):
        if isinstance(value, str):
            value = json.loads(value)
        return value


class AuthenticationState(LoggingMixin, InheritableBaseModel):
    """Authentication State."""
    _logger = None
    session_state: str = str(uuid.uuid4())
    state: AuthenticationOptions = AuthenticationOptions.unauthenticated
    user: Optional[User] = None

    class Config:  # noqa: D106
        underscore_attrs_are_private = True

    @validator('user', always=True, pre=True)
    def _validate_user_klass(cls, value):
        if isinstance(value, dict):
            klass = value.get('klass', None)
            if klass:
                module, name = klass.split(':')
                mod = importlib.import_module(module)
                klass = getattr(mod, name)
            else:
                klass = User
            value = klass(**value)
        return value

    @root_validator(pre=True)
    def _validate_user(cls, values):
        if values.get('user', None) is None:
            values['state'] = AuthenticationOptions.unauthenticated
        return values

    def check_session_state(self, session_state):
        """Check state against session state."""
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

    def check_scopes(self, required_scopes: Optional[Union[List[str], str]] = None):
        """Check if the user has the required scopes."""
        if required_scopes is None:
            return True
        elif isinstance(required_scopes, str):
            required_scopes = required_scopes.split(' ')
        for scope in required_scopes:
            if scope in self.credentials.scopes:
                return True
        return False

    def check_roles(self, required_roles: Optional[Union[List[str], str]] = None):
        """Check if the user has the required roles."""
        if required_roles is None:
            return True
        elif isinstance(required_roles, str):
            required_roles = required_roles.split(' ')
        for role in required_roles:
            if self.user and self.user.roles and role in self.user.roles:
                return True
        return False

    def check_groups(self, required_groups: Optional[Union[List[str], str]] = None):
        """Check if the user has the required roles."""
        if required_groups is None:
            return True
        elif isinstance(required_groups, str):
            required_groups = required_groups.split(' ')
        for group in required_groups:
            if self.user and self.user.groups and group in self.user.groups:
                return True
        return False
