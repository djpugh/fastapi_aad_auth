import unittest

from fastapi_aad_auth.utilities.deprecate import APIDeprecationWarning


class OAuthDeprecationTestCase(unittest.TestCase):

    def test_base_backend_api_auth_scheme(self):
        from fastapi_aad_auth._base.backend import BaseOAuthBackend
        backend = BaseOAuthBackend([])
        backend.enabled = False
        with self.assertWarns(APIDeprecationWarning):
            backend.api_auth_scheme
