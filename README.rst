************************
fastapi_aad_auth
************************

Adding Azure Active Directory Authentication for FastAPI

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



(Built from `package-template <https://github.com/djpugh/package-template>`_ version 1.0.0)