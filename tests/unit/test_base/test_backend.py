import asyncio
import unittest
from unittest.mock import MagicMock


class BaseOAuthBackendTestCase(unittest.TestCase):

    def test_authenticate_authenticated(self):
        raise unittest.SkipTest()

    def test_authenticate_unauthenticated(self):
        raise unittest.SkipTest()

    def test_is_authenticated_authenticated(self):
        raise unittest.SkipTest()

    def test_is_authenticated_unauthenticated(self):
        raise unittest.SkipTest()

    def test_call(self):
        raise unittest.SkipTest()

    def test_check_authenticated(self):
        raise unittest.SkipTest()

    def test_check_unauthenticated(self):
        raise unittest.SkipTest()

    def test__iter_validators(self):
        raise unittest.SkipTest()

    def test_requires_auth(self):
        raise unittest.SkipTest()

    def test_api_auth_scheme(self):
        raise unittest.SkipTest()


