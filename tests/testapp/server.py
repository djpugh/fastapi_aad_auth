import logging

logging.basicConfig(level='DEBUG')

from fastapi import APIRouter, Depends
from fastapi import FastAPI
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from starlette.requests import Request
from starlette.routing import request_response, Route
import uvicorn


from fastapi_aad_auth import __version__, Authenticator, AuthenticationState

auth_provider = Authenticator()

router = APIRouter()

@router.get('/hello')
async def hello_world(auth_state: AuthenticationState = Depends(auth_provider.auth_backend.requires_auth(allow_session=True))):
    print(auth_state)
    return {'hello': 'world'}

@router.get('/test_auth_decorator')
@auth_provider.api_auth_required('authenticated', allow_session=False)
async def hello_world2(auth_state: AuthenticationState, a: str = 'b'):
    print(auth_state)
    return {'hello': 'world', 'a': a}


if 'untagged' in __version__ or 'unknown':
    API_VERSION = 0
else:
    API_VERSION = __version__.split('.')[0]


async def homepage(request):
    if request.user.is_authenticated:
        return PlainTextResponse('Hello, ' + request.user.display_name)
    return HTMLResponse(f'<html><body><h1>Hello, you</h1><br></body></html>')


@auth_provider.auth_required()
async def test(request):
    if request.user.is_authenticated:
        return PlainTextResponse('Hello, ' + request.user.display_name)

routes = [
    Route("/", endpoint=homepage),
    Route("/test", endpoint=test)
]

app = FastAPI(title='fastapi_aad_auth test app',
              description='Testapp for Adding Azure Active Directory Authentication for FastAPI',
              version=__version__,
              openapi_url=f"/api/v{API_VERSION}/openapi.json",
              docs_url='/api/docs',
              redoc_url='/api/redoc',
              routes=routes)

app.include_router(router)

auth_provider.configure_app(app)


if __name__ == "__main__":
    uvicorn.run('server:app', host='0.0.0.0', debug=True, port=8000, log_level='debug', reload=True)
