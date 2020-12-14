API Deprecations
****************

``0.2.0``:

    Refactoring towards a more extensible structure for the Authentication Backend
     * :class:`fastapi_aad_auth.oauth.state.AuthenticationState` - replaced by :class:`fastapi_aad_auth._base.state.AuthenticationState`
     * :class:`fastapi_aad_auth.oauth.aad.AADOAuthBackend` - replaced by :class:`fastapi_aad_auth.providers.aad.AADProvider`
     * :py:attr:`fastapi_aad_auth.config.RoutingConfig.login_path` - replaced by provider based usage of :py:attr:`fastapi_aad_auth.config.RoutingConfig.oauth_base_route`, see :ref:`config-aad-appreg` for how to configure the app registration
     * :py:attr:`fastapi_aad_auth.config.RoutingConfig.login_redirect_path` - replaced by provider based usage of :py:attr:`fastapi_aad_auth.config.RoutingConfig.oauth_base_route`, see :ref:`config-aad-appreg` for how to configure the app registration
     * :py:attr:`fastapi_aad_auth.config.Config.aad` - replaced by providers in :py:attr:`fastapi_aad_auth.config.Config.providers`
     * :class:`fastapi_aad_auth.auth.AADAuth` - replaced by :class:`fastapi_aad_auth.auth.Authenticator`
     * :py:meth:`fastapi_aad_auth.auth.AADAuth.api_auth_scheme` - replaced by :py:meth:`fastapi_aad_auth._base.backend.BaseOAuthBackend.requires_auth` (includes ``allow_session`` boolean flag)
