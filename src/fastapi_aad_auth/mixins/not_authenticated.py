"""Add not_authenticated error to a class."""
from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED


class NotAuthenticatedMixin:
    """Provide an error for not authenticated error."""

    @property
    def not_authenticated(self):
        """Create an error for unauthenticated requests."""
        return HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
