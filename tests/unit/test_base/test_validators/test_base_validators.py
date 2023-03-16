import asyncio

import unittest
from unittest.mock import MagicMock

from fastapi_aad_auth._base.validators.base import Validator
from fastapi_aad_auth.mixins.not_authenticated import HTTPException


class ValidatorTestCase(unittest.TestCase):
    def setUp(self):
        self.validator = Validator()

    def test_check(self):
        with self.assertRaises(NotImplementedError):
            self.validator.check(None)

    def test_call_authenticated(self):
        result = MagicMock()
        result.is_authenticated = MagicMock(return_value=True)
        self.validator.check = MagicMock(return_value=result)
        out = asyncio.run(self.validator('a'))
        self.validator.check.assert_called_with('a')
        self.assertEqual(out, result)

    def test_call_unauthenticated(self):
        result = MagicMock()
        result.is_authenticated = MagicMock(return_value=False)
        self.validator.check = MagicMock(return_value=result)
        with self.assertRaises(HTTPException):
            asyncio.run(self.validator('a'))
        self.validator.check.assert_called_with('a')
