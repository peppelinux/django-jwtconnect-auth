DEFAULT_JWTAUTH_CLAIMS_MAP = dict(
                                    username = 'username',
                                    first_name = 'given_name',
                                    last_name = 'family_name',
                                    email = 'email'
                                 )

DEFAULT_JWTAUTH_ACCESS_TOKEN_LIFETIME = 1800
DEFAULT_JWTAUTH_REFRESH_TOKEN_LIFETIME = 3600
DEFAULT_JWTAUTH_ALGORITHM = 'RS256'
DEFAULT_JWTAUTH_KEYJAR_HANDLER = 'jwtconnect_auth.jwks.JWTConnectAuthKeyHandler'
