import unittest

from fastapi_aad_auth.utilities.deprecate import APIDeprecationWarning


class OAuthDeprecationTestCase(unittest.TestCase):

    def test_03_aad_module_deprecation(self):
        with self.assertWarns(APIDeprecationWarning):
            import fastapi_aad_auth.oauth.aad
        self.assertIn('DEPRECATED', fastapi_aad_auth.oauth.aad.__doc__)
        self.assertIn(f'in version {fastapi_aad_auth.oauth.aad._DEPRECATED_VERSION}', fastapi_aad_auth.oauth.aad.__doc__)

    def test_02_state_module_deprecation(self):
        with self.assertWarns(APIDeprecationWarning):
            import fastapi_aad_auth.oauth.state
        self.assertIn('DEPRECATED', fastapi_aad_auth.oauth.state.__doc__)
        self.assertIn(f'in version {fastapi_aad_auth.oauth.state._DEPRECATED_VERSION}', fastapi_aad_auth.oauth.state.__doc__)

    def test_01_oauth_module_deprecation(self):
        with self.assertWarns(APIDeprecationWarning):
            import fastapi_aad_auth.oauth
        self.assertIn('DEPRECATED', fastapi_aad_auth.oauth.__doc__)
        self.assertIn(f'in version {fastapi_aad_auth.oauth._DEPRECATED_VERSION}', fastapi_aad_auth.oauth.__doc__)

    def test_04_AuthenticationState_deprecated(self):
        from fastapi_aad_auth.oauth.state import _DEPRECATED_VERSION, AuthenticationState
        with self.assertWarns(APIDeprecationWarning):
            state = AuthenticationState()
        self.assertIn('DEPRECATED', state.__doc__)
        self.assertIn(f'in version {_DEPRECATED_VERSION}', state.__doc__)

    def test_05_User_deprecated(self):
        from fastapi_aad_auth.oauth.state import _DEPRECATED_VERSION, User
        with self.assertWarns(APIDeprecationWarning):
            user = User(name='a', email='a@b.com', username='a@b.com')
        self.assertIn('DEPRECATED', user.__doc__)
        self.assertIn(f'in version {_DEPRECATED_VERSION}', user.__doc__)

    def test_06_AADOAuthBackendDepreactated(self):
        from fastapi_aad_auth.oauth.aad import _DEPRECATED_VERSION, AADOAuthBackend
        self.assertIn('DEPRECATED', AADOAuthBackend.__doc__)
        self.assertIn(f'in version {_DEPRECATED_VERSION}', AADOAuthBackend.__doc__)
        self.assertIn('DEPRECATED', AADOAuthBackend.from_config.__doc__)
        self.assertIn(f'in version {_DEPRECATED_VERSION}', AADOAuthBackend.from_config.__doc__)
