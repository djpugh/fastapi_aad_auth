"""fastapi_aad_auth errors."""
from pathlib import Path
from typing import Dict, Optional

from starlette.authentication import AuthenticationError
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.templating import Jinja2Templates

from fastapi_aad_auth.utilities import is_interactive, urls
from fastapi_aad_auth.utilities.logging import getLogger

logger = getLogger(__name__)


def base_error_handler(request: Request, exception: Exception, error_type: str, error_message: str, templates: Jinja2Templates, template_path: Path, context: Optional[Dict] = None, status_code: int = 500) -> Response:
    """Handle Error as JSON or HTML response depending on request type."""
    logger.warning(f'Handling error {exception}')
    if is_interactive(request):
        response = ui_error_handler(request, exception, error_type, error_message, templates, template_path, context, status_code)
    else:
        response = json_error_handler(error_message, status_code)
    logger.debug(f'Response {response}')
    return response


def json_error_handler(error_message: str, status_code: int = 500) -> JSONResponse:
    """Handle error as a JSON."""
    logger.info('Non-Interactive environment so returning JSON message')

    return JSONResponse(   # type: ignore
        status_code=status_code,
        content={"message": error_message}
    )


def redirect_error_handler(redirect_path: str, exception: Exception, **kwargs) -> RedirectResponse:
    """Handle error as a redirect with error info in the query parameters."""
    return RedirectResponse(urls.with_query_params(redirect_path, error=exception, **kwargs))


def ui_error_handler(request: Request, exception: Exception, error_type: str, error_message: str, templates: Jinja2Templates, template_path: Path, context: Optional[Dict] = None, status_code: int = 500) -> Response:
    """Return a UI view of the error."""
    logger.info('Interactive environment so returning error template')
    logger.debug(f'Path: {template_path}')
    logger.debug(f'Exception: {exception}')
    if context is None:
        context = {}
    error_context = context.copy()
    error = exception
    detail = ''
    if exception.args:
        logger.info('Getting args')
        error = exception.args[0]
    if len(exception.args) > 1:
        detail = exception.args[1]
    error_context.update({'error': str(error),
                          'status_code': str(status_code),
                          'error_type': error_type,
                          'error_description': error_message,
                          'error_detail': str(detail),
                          'request': request})  # type: ignore
    logger.debug(f'Error context: {error_context}')
    return templates.TemplateResponse(template_path.name,
                                      error_context,
                                      status_code=status_code)


class ConfigurationError(Exception):
    """Misconfigured application."""


class AuthorisationError(AuthenticationError):
    """Not Authorised to access this resource."""
