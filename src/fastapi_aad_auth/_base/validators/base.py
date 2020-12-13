from abc import abstractmethod

from fastapi import HTTPException
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth.mixins import LoggingMixin


class Validator(LoggingMixin):

    @abstractmethod
    def check(self, request: Request) -> AuthenticationState:
        raise NotImplementedError('Implement in subclass')

    async def __call__(self, request: Request) -> AuthenticationState:  # type: ignore
        """Validate the request authentication.

        Returns an AuthenticationState object or raises an Unauthorized error
        """
        result = self.check(request)
        self.logger.info(f'Identified state {result}')
        if not result.is_authenticated():
            raise self.not_authenticated
        return result
    
    @property
    def not_authenticated(self):
        return HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
