"""URL utilities."""
import logging

from starlette.datastructures import URL


logger = logging.getLogger(__name__)


def with_redirect(url, post_redirect=None):
    """Append a redirect query parameter."""
    if post_redirect is not None:
        url = with_query_params(url, redirect=post_redirect)
    return url


def append(base_url, *args):
    """Append paths together."""
    extension = '/'.join([u.strip('/') for u in args])
    if extension:
        url = base_url.rstrip('/')+'/'+extension
    else:
        url = base_url
    return url


def with_query_params(url, **query_params):
    """Add query parameters to a url."""
    logger.debug(f'Adding {query_params} to {url}')
    parsed_url = URL(url)
    logger.debug(f'Existing query params {parsed_url.query}')
    new_url = parsed_url.include_query_params(**query_params)
    logger.debug(f'Updated query params {new_url.query}')
    logger.debug(f'Updated url {new_url}')
    return str(new_url)
