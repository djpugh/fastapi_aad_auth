Using fastapi_aad_auth
**********************
Please see `Basic Usage <usage>`_ for information on how to configure and setup ``fastapi_aad_auth``.

Accessing User Tokens/View
~~~~~~~~~~~~~~~~~~~~~~~~~~

There are two routes that are automatically added to this, the ``/me`` and ``/me/getToken`` routes. The ``/me`` route provides a summary of the current user, and enables them to get a bearer token from Azure AD.
The ``/me/token`` endpoint provides that same token (for the logged in user) in a JSON object

.. warning::

    To get the token, this is primarily an interactive method, as it requires caching the token through the UI session based login approach, so it can fail intermittently depending on if the user has logged in recently.

This can be disabled by setting the ``config.routing.user_path`` to ``None`` or ``''``. #

Customising the User Model
~~~~~~~~~~~~~~~~~~~~~~~~~~

The authentication state user can be processed within the application methods - the ``Depends`` part of the api route returns an
:class:`~fastapi_aad_auth._base.state.AuthenticationState` object - ``auth_state`` in the ``testapp`` (see :ref:`testing`).

.. literalinclude:: ../../tests/testapp/server.py
    :language: python
    :linenos:
    :start-at: @router.get('/hello')
    :end-at: return

The associated user is then available at ``auth_state.user``

The :class:`~fastapi_aad_auth.auth.Authenticator` object takes a ``user_klass`` argument:

.. literalinclude:: ../../src/fastapi_aad_auth/auth.py
    :language: python
    :linenos:
    :start-at: class Authenticator
    :end-before: """Initialise

which defaults to the really basic :class:`~fastapi_aad_auth.oauth.state.User` class, but any object with the same
interface should work, so you can add e.g. database calls etc. to validate/persist/check the user and any other
desired behaviours.

You can customise this when initialising the :class:`~fastapi_aad_auth.auth.Authenticator` object by setting
the :class:`~fastapi_aad_auth.config.Config` ``user_klass`` variable (this can also be done by the
associated environment variable, or in the argument, which overrides all other settings)::

    from fastapi_aad_auth import Authenticator, Config

    config = Config()

    auth = Authenticator(config, user_klass=MyUserClass)

Customising the UI
~~~~~~~~~~~~~~~~~~

The UI templates are rendered using Jinja2 Templates, with a customisation from :py:class:`~fastapi_aad_auth.ui.jinja.Jinja2Templates`
that uses a loader that allows a package resource to be used in place of a file (using ``{% extends <package>:<resource> %}``).

Additionally, the :py:class:`~fastapi_aad_auth.config.LoginUIConfig` has an attribute ``ui_klass`` that can be used to customise how
the context is built (note that this class should inherit from (or duck-type the public API of) :class:`~fastapi_aad_auth.ui.UI`)

These jinja templates also are structured (see :doc:`module/fastapi_aad_auth.ui` docs for the other templates) from a base template that is relatively generic:

.. literalinclude:: ../../src/fastapi_aad_auth/ui/base.html
    :language: html

And can easily be extended or customised.


Token Scopes
~~~~~~~~~~~~

:mod:`fastapi_aad_auth` is used for providing authentication and authorisation on an API using Azure Active Directory as an authorisation provider.

This means that scopes are requested against the ``client_id`` of the application rather than e.g. MS Graph or similar, if your backend API needs to
access Microsoft (or other APIs) you will need to use e.g. an additional msal instance (or provide specific additional ``scopes`` through the
:py:meth:`fastapi_aad_auth.providers.aad.AADSessionAuthenticator.get_access_token`, with ``app_scopes=False``), if those permissions are added on the App Registration.

Alternatively, you can use an on-behalf-of flow (see `Azure Docs <https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow>`_).
