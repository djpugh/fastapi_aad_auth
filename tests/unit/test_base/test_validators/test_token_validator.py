import asyncio
import unittest
from unittest.mock import MagicMock
import uuid

from authlib.jose import jwt, JWTClaims
from starlette.middleware.authentication import AuthenticationError

from fastapi_aad_auth._base.state import AuthenticationState, User, AuthenticationOptions
from fastapi_aad_auth._base.validators.token import TokenValidator
from fastapi_aad_auth.mixins.not_authenticated import HTTPException


class TokenValidatorTestCase(unittest.TestCase):

    def setUp(self):
        self.validator = TokenValidator(client_id='a', authorizationUrl='b', tokenUrl='c')

    def test_check_authenticated(self):
        user = User(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        header =  {'alg': 'HS256'}
        payload = {'iss': 'Authlib',
                   'sub': '123',
                   'aud': 'api://a',
                   'exp': 99999999999,
                   'nbf': 1,
                   'iat': 1}
        claims = JWTClaims(payload, header)
        self.validator._decode_token = MagicMock(return_value=claims)
        self.validator._get_user_from_claims = MagicMock(return_value=user)
        request = MagicMock()
        request.headers = {'Authorization': 'bearer abc123'}
        state = self.validator.check(request)
        self.assertIsInstance(state, AuthenticationState)
        self.assertEqual(state.state, AuthenticationOptions.authenticated)
        self.assertEqual(state.user, user)

    def test_check_unauthenticated(self):
        user = User(name='Joe Bloggs', email='joe.bloggs@gmail.com', username='joe.bloggs@gmail.com')
        header =  {'alg': 'HS256'}
        payload = {'iss': 'Authlib',
                   'sub': '123',
                   'aud': 'api://b',
                   'exp': 1,
                   'nbf': 1,
                   'iat': 1}
        claims = JWTClaims(payload, header)
        self.validator._decode_token = MagicMock(return_value=claims)
        self.validator._get_user_from_claims = MagicMock(return_value=user)
        request = MagicMock()
        request.headers = {'Authorization': 'bearer abc123'}
        state = self.validator.check(request)
        self.assertIsInstance(state, AuthenticationState)
        self.assertEqual(state.state, AuthenticationOptions.unauthenticated)

    def test_get_token_ok(self):
        request = MagicMock()
        request.headers = {'Authorization': 'bearer abc123'}
        self.assertEqual(self.validator.get_token(request), 'abc123')

    def test_get_token_none(self):
        request = MagicMock()
        request.headers = {}
        self.validator.auto_error = True
        with self.assertRaises(HTTPException):
            self.validator.get_token(request)
        self.validator.auto_error = False
        self.assertIsNone(self.validator.get_token(request))

    def test_get_token_not_bearer(self):
        request = MagicMock()
        request.headers = {'Authorization': 'basic abc123'}
        self.validator.auto_error = True
        with self.assertRaises(HTTPException):
            self.validator.get_token(request)
        self.validator.auto_error = False
        self.assertIsNone(self.validator.get_token(request))

    def test_init_oauth(self):
        result = self.validator.init_oauth
        self.assertIsInstance(result, dict)
        self.assertEqual(result['clientId'], self.validator.client_id)
        self.assertEqual(result['scopes'], f'{self.validator.api_audience}/openid')
        self.assertTrue(result['usePkceWithAuthorizationCodeGrant'])

    def test__validate_claims(self):
        header =  {'alg': 'HS256'}
        payload = {'iss': 'Authlib', 'sub': '123'}
        claims = JWTClaims(payload, header)
        self.assertEqual(claims, self.validator._validate_claims(claims, {'iss': {'essential': True}}))

    def test_validate_claims_missing(self):
        header =  {'alg': 'HS256'}
        payload = {'iss': 'Authlib', 'sub': '123'}
        claims = JWTClaims(payload, header)
        with self.assertRaises(AuthenticationError) as ctx:
            self.validator._validate_claims(claims, {'xyz': {'essential': True}})
        self.assertIn('Missing', ctx.exception.args[0])

    def test_validate_claims_invalid(self):
        header =  {'alg': 'HS256'}
        payload = {'iss': 'Authlib', 'sub': '123'}
        claims = JWTClaims(payload, header)
        self.assertEqual(claims, self.validator._validate_claims(claims, {'sub': {'values': ['123', '456']}}))
        with self.assertRaises(AuthenticationError) as ctx:
            self.validator._validate_claims(claims, {'sub': {'values': ['456']}})
        self.assertIn('Invalid', ctx.exception.args[0])

    def test_validate_claims_expired(self):
        header =  {'alg': 'HS256'}
        payload = {'iss': 'Authlib', 'sub': '123', 'exp': 1}
        claims = JWTClaims(payload, header)
        with self.assertRaises(AuthenticationError) as ctx:
            self.validator._validate_claims(claims, {})
        self.assertIn('expired', ctx.exception.args[0])

    def test__claims_options(self):
        options = self.validator._claims_options
        self.assertTrue(options['sub']['essential'])
        self.assertTrue(options['aud']['essential'])
        self.assertTrue(options['exp']['essential'])
        self.assertTrue(options['nbf']['essential'])
        self.assertTrue(options['iat']['essential'])
        self.assertEqual(options['aud']['values'], [f'{self.validator.api_audience}'])

    def test__decode_token(self):
        with self.assertRaises(NotImplementedError):
            self.validator._decode_token(None)

    def test_validate_token(self):
        header =  {'alg': 'HS256'}
        payload = {'iss': 'Authlib', 'sub': '123'}
        claims = JWTClaims(payload, header)
        self.validator._decode_token = MagicMock(return_value=claims)
        result = self.validator.validate_token('a', {})
        self.assertEqual(claims, result)
        self.validator._decode_token.assert_called_with('a')

    def test__compare_claims(self):
        header =  {'alg': 'HS256'}
        payload = {'iss': 'Authlib', 'sub': '123'}
        claims = JWTClaims(payload, header)
        result = self.validator._compare_claims(claims)
        self.assertIn('iss: Authlib', result)
        self.assertIn('sub: 123', result)

    def test__get_user_from_claims(self):
        with self.assertRaises(NotImplementedError):
            self.validator._get_user_from_claims(None)
