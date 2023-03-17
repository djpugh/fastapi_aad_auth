import unittest

from fastapi_aad_auth.utilities.deprecate import APIDeprecationWarning


class AADAuthDeprecationTestCase(unittest.TestCase):

    def test_aad_auth(self):
        from fastapi_aad_auth.auth import _DEPRECATED_VERSION, AADAuth
        self.assertIn('DEPRECATED', AADAuth.__doc__)
        self.assertIn(f'in version {_DEPRECATED_VERSION}', AADAuth.__doc__)

    def test_aad_auth_api_auth_scheme(self):
        from fastapi_aad_auth.auth import _DEPRECATED_VERSION, AADAuth
        self.assertIn('DEPRECATED', AADAuth.api_auth_scheme.__doc__)
        self.assertIn(f'in version {_DEPRECATED_VERSION}', AADAuth.api_auth_scheme.__doc__)
