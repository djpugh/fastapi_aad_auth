"""Add logger to a class."""

from fastapi_aad_auth.utilities import logging


class LoggingMixin:
    """Add logger to class based on name."""
    def __init__(self, *args, **kwargs):
        """Initialise the logger."""
        self._logger = None
        super().__init__(*args, **kwargs)

    @property
    def logger(self):
        """Get the logger object."""
        if self._logger is None:
            self._logger = logging.getLogger(self.__class__.__name__)
        return self._logger
