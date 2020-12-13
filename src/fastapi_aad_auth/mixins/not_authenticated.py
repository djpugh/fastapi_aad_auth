
from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED


class NotAuthenticatedMixin:
    
    @property
    def not_authenticated(self):
        return HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
