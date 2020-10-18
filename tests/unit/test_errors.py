import unittest

from fastapi_aad_auth.errors import ConfigurationError

# TODO: Add additional test cases

class ConfigurationErrorTestCase(unittest.TestCase):

    def test_configuration_error(self):
        with self.assertRaises(ConfigurationError):
            raise ConfigurationError()

        with self.assertRaises(Exception):
            raise ConfigurationError()

        with self.assertRaises(Exception):
            try:
                raise ConfigurationError()
            except (ValueError, TypeError, RuntimeError):
                pass
