"""fastapi_aad_auth errors."""
from starlette.responses import JSONResponse, Response

from fastapi_aad_auth.utilities import is_interactive
from fastapi_aad_auth.utilities.logging import getLogger

logger = getLogger(__name__)


def base_error_handler(request, exception, error_type, error_message, templates, template_path, context=None, status_code=500) -> Response:
    """Handle Error as JSON or HTML response depending on request type."""
    if context is None:
        context = {}
    logger.warning(f'Handling error {exception}')
    if is_interactive(request):
        logger.info('Interactive environment so returning error template')
        logger.debug(f'Path: {template_path}')
        error_context = context.copy()
        error_context.update({'error': str(exception),
                              'status_code': str(status_code),
                              'error_type': error_type,
                              'error_description': error_message,
                              'request': request})  # type: ignore
        response = templates.TemplateResponse(template_path.name,
                                              error_context,
                                              status_code=status_code)
    else:
        logger.info('Non-Interactive environment so returning JSON message')

        response = JSONResponse(   # type: ignore
            status_code=status_code,
            content={"message": error_message}
        )
    logger.debug(f'Response {response}')
    return response


class ConfigurationError(Exception):
    """Misconfigured application."""
