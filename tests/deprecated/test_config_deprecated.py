import unittest

from fastapi_aad_auth.config import _DEPRECATION_VERSION, Config, RoutingConfig
from fastapi_aad_auth.utilities.deprecate import APIDeprecationWarning


class ConfigDeprecationTestCase(unittest.TestCase):

    def test_RoutingConfig_login_path_deprecation(self):
        # Deprecated in schema
        self.assertEqual(RoutingConfig.schema()['properties']['login_path']['warn_from'], '0.1.22')
        self.assertEqual(RoutingConfig.schema()['properties']['login_path']['deprecated_in'], _DEPRECATION_VERSION)
        self.assertTrue(RoutingConfig.schema()['properties']['login_path']['deprecated'])

    def test_RoutingConfig_login_redirect_path_deprecation(self):
        self.assertEqual(RoutingConfig.schema()['properties']['login_redirect_path']['warn_from'], '0.1.22')
        self.assertEqual(RoutingConfig.schema()['properties']['login_redirect_path']['deprecated_in'], _DEPRECATION_VERSION)
        self.assertTrue(RoutingConfig.schema()['properties']['login_redirect_path']['deprecated'])

    def test_Config_aad_deprecation(self):
        self.assertEqual(Config.__fields__['aad'].field_info.extra['warn_from'], '0.1.22')
        self.assertEqual(Config.__fields__['aad'].field_info.extra['deprecated_in'], _DEPRECATION_VERSION)
        self.assertTrue(Config.__fields__['aad'].field_info.extra['deprecated'])
