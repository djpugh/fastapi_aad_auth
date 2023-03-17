import unittest
from unittest.mock import MagicMock


class DeprecatedFieldTestCase(unittest.TestCase):

    def test_field(self):
        raise unittest.SkipTest()


class DeprecatableFieldsMixinTestCase(unittest.TestCase):

    def test_deprecate_field(self):
        raise unittest.SkipTest()


class DeprecateTestCase(unittest.TestCase):

    def test_deprecate(self):
        raise unittest.SkipTest()


class DeprecateModuleTestCase(unittest.TestCase):

    def test_deprecate(self):
        raise unittest.SkipTest()


class IsDeprecatedTestCase(unittest.TestCase):

    def test_deprecated(self):
        raise unittest.SkipTest()

    def test_not_deprecated(self):
        raise unittest.SkipTest()
