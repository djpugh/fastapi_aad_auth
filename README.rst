************************
fastapi_aad_auth
************************

.. image:: https://img.shields.io/github/license/djpugh/fastapi_aad_auth.svg
    :target: https://github.com/djpugh/fastapi_aad_auth/blob/master/LICENSE

.. image:: https://img.shields.io/pypi/v/fastapi_aad_auth?style=flat-square
    :target: https://pypi.org/project/fastapi_aad_auth

.. image:: https://img.shields.io/pypi/implementation/fastapi_aad_auth?style=flat-square
    :target: https://pypi.org/project/fastapi_aad_auth

.. image:: https://img.shields.io/pypi/pyversions/fastapi_aad_auth?style=flat-square
    :target: https://pypi.org/project/fastapi_aad_auth

.. image:: https://img.shields.io/pypi/dm/fastapi_aad_auth?style=flat-square
    :target: https://pypistats.org/packages/fastapi_aad_auth)

.. image:: https://img.shields.io/pypi/l/fastapi_aad_auth?style=flat-square
    :target: https://opensource.org/licenses/MIT)

.. image:: https://github.com/djpugh/fastapi_aad_auth/workflows/Pipeline/badge.svg?branch=master&event=push
    :target: https://github.com/djpugh/fastapi_aad_auth/actions?query=workflow%3APipeline

.. image:: https://codecov.io/gh/djpugh/fastapi_aad_auth/branch/master/graph/badge.svg?token=APZ8YDJ0UD
    :target: https://codecov.io/gh/djpugh/fastapi_aad_auth

.. image:: https://app.fossa.com/api/projects/custom%2B20832%2Fgithub.com%2Fdjpugh%2Ffastapi_aad_auth.svg?type=shield
    :target: https://app.fossa.com/projects/custom%2B20832%2Fgithub.com%2Fdjpugh%2Ffastapi_aad_auth?ref=badge_shield

.. image:: https://sonarcloud.io/api/project_badges/measure?project=djpugh_fastapi_aad_auth&metric=alert_status
    :target: https://sonarcloud.io/dashboard?id=djpugh_fastapi_aad_auth

.. image:: https://img.shields.io/github/issues/djpugh/fastapi_aad_auth
    :target: https://github.com/djpugh/fastapi_aad_auth/issues

.. image:: https://img.shields.io/github/issues-pr-raw/djpugh/fastapi_aad_auth
    :target: https://github.com/djpugh/fastapi_aad_auth/pulls


Adding Azure Active Directory Authentication for FastAPI


Links
-----

* `Full Documentation <https://djpugh.github.io/fastapi_aad_auth>`_
* `Installation <https://djpugh.github.io/fastapi_aad_auth/installation.html>`_
* `Changelog <https://djpugh.github.io/fastapi_aad_auth/changelog.html>`_
* `Issues <https://github.com/djpugh/fastapi_aad_auth/issues>`_
* `PyPI <https://pypi.org/project/fastapi_aad_auth>`_
* |github| `Github <https://github.com/djpugh/fastapi_aad_auth>`_

.. |github| image:: https://api.iconify.design/logos-github-icon.svg
    :target: https://github.com/djpugh/fastapi_aad_auth


Using it
--------

The configuration is defined in ``src/fastapi_aad_auth/config.py``, and includes options for configuring
the AAD config, the login UI and the routes.

You can initialise it with::

    from fastapi_aad_auth import AADAuth, AuthenticationState, Config
    auth_provider = AADAuth()

    # If you had a config that wasn't set in the environment, you could use 
    # auth_provider = AADAuth(Config(<my config kwargs>)


You can use it for fastapi routes::

    from fastapi import APIRouter, Depends


    # Use the auth_provider.api_auth_scheme for fastapi authentication

    router = APIRouter()

    @router.get('/hello')
    async def hello_world(auth_state: AuthenticationState =D epends(auth_provider.api_auth_scheme)):
        print(auth_state)
        return {'hello': 'world'}

For starlette routes (i.e. interactive/HTML pages), use the auth_provider.auth_required for authentication::

    from starlette.responses import PlainTextResponse

    @auth_provider.auth_required()
    async def test(request):
        if request.user.is_authenticated:
            return PlainTextResponse('Hello, ' + request.user.display_name)

This middleware will set the request.user object and request.credentials object::

    async def homepage(request):
        if request.user.is_authenticated:
            return PlainTextResponse('Hello, ' + request.user.display_name)
        return PlainTextResponse(f'Hello, you')


You can set the swagger_ui_init_oauth using auth_provider.api_auth_scheme.init_oauth::

    from fastapi import FastAPI
    app = FastAPI(title='fastapi_aad_auth test app',
                  description='Adding Azure Active Directory Authentication for FastAPI',
                  version='0.1.0',
                  openapi_url=f"/api/v0/openapi.json",
                  docs_url='/api/docs',
                  swagger_ui_init_oauth=auth_provider.api_auth_scheme.init_oauth,
                  redoc_url='/api/redoc',
                  routes=routes)


To add the required middleware to the fastapi app use::

    auth_provider.configure_app(app)



Coverage
~~~~~~~~

.. image:: https://codecov.io/gh/djpugh/fastapi_aad_auth/branch/master/graphs/sunburst.svg?token=APZ8YDJ0UD
    :target: https://codecov.io/gh/djpugh/fastapi_aad_auth

License Analysis
~~~~~~~~~~~~~~~~

.. image:: https://app.fossa.com/api/projects/custom%2B20832%2Fgithub.com%2Fdjpugh%2Ffastapi_aad_auth.svg?type=large
    :target: https://app.fossa.com/projects/custom%2B20832%2Fgithub.com%2Fdjpugh%2Ffastapi_aad_auth?ref=badge_shield

---------------------------

(Built from `package-template <https://github.com/djpugh/package-template>`_ version 1.0.0)