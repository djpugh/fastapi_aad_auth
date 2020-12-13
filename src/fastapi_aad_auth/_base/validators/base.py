from abc import abstractmethod

from starlette.requests import Request

from fastapi_aad_auth._base.state import AuthenticationState
from fastapi_aad_auth.mixins import LoggingMixin, NotAuthenticatedMixin


class Validator(NotAuthenticatedMixin, LoggingMixin):

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