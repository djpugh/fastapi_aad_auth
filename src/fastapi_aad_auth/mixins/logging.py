from fastapi_aad_auth import logging 


class LoggingMixin:

    def __init__(self, *args, **kwargs):
        self._logger = None
        super().__init__(*args, **kwargs)

    @property
    def logger(self):
        if self._logger is None:
            self._logger = logging.getLogger(self.__class__.__name__)
        return self._logger
