# django-jwtconnect-auth
A Django JWT Authentication Backend built on top of JWTConnect.io, [CryptoJWT](https://cryptojwt.readthedocs.io/) and [OidcMsg](https://oidcmsg.readthedocs.io/).

This application made simple building a JWT based authentication system, with less as possibile endpoints involved.
Its birth is due to a desire for simplification in cases where a customized system is required for the granting of authorizations to access resources. It comes with the bare minimum, it could be useful as a basis also for the production of *OAuth2 AS* and *OIDC Providers*, it would just need to add specific endpoints and further attributes in the construction of the JWT.

The main goal for this application is to __provide a secure standard for JWT management and not to offer a OAuth2 or OIDC compliant server__. These can be implemented on top of this app as well. This application also show us how to deal with [OidcMsg](https://oidcmsg.readthedocs.io/) and [CryptoJWT](https://cryptojwt.readthedocs.io/) in a totally free way.

At this time and as it is, jwtconnect-auth can be adopted for the following scopes:

- Third-party applications can have Access tokens and renew these, via Rest API (Django Rest framework)
- Creation of token after a user have been logged in, in cases where third-party Single SignOn systems were involved. There wouldn't be any direct submission of credentials from Application to jwtconnect-auth to obtain a token.

# Specifications and common endpoints

- Tokens could be also relased with an authentication web resource where to submit username and password, mind that this would be disabled in the field of SSO infrastructures as SAML2, you can decide how and why you should do this.
- Token creation is triggered once, independently by what kind of External Authentication happens, a django signal creates the token for authenticated users if this doesn't exist yet (signal should be enabled in your setup).
  The release mechanism can be completely customized, you can decide how and where the release of token to the Apps would happen, implementing it in your own.
- Tokens can be refreshed via POST method: `/token/refresh` by default, but it's customizable in the `urls.py` of your project folder.
- A user can have multiple active tokens or one at time (configurable in general `settings`).
- TokenIntrospection endpoint would let third-party applications to get additional informations about a token.

  
# Token Introspection

The requestor must be authenticated, a valid access token must bresent in its http request headers.
Params supported: token, jti.

Example:
  ````
  curl -H 'Content-type: application/json; indent=4' -H "Accept: application/json" -d '{"jti":"cd9db7ca7560149c543b08a8b8f03393eeb979e9c26d877f66c1fbca23a8554d"}' -X POST http://127.0.0.1:8000/token/introspection -H "Authorization: Bearer $ACCESS_TOKEN"
  ````

![Alt text](gallery/introspection.png) 


# Token Refresh
  
Params supported: token -> must be a valid refresh token.

Example:
  ````
  curl -H 'Content-type: application/json; indent=4' -H "Accept: application/json" -d '{"token":"$REFRESH_TOKEN}' -X POST http://127.0.0.1:8000/token/refresh
  ````
 
![Alt text](gallery/refresh.png) 


# Demo project

In `example/` folder we have an example project usable as a demo.

````
pip install -r requirements.txt
cd example
./manage.py migrate
./manage.py createsuperuser
./manage.py runserver
````

# Setup

Install this application and all its dependency
````
pip install git+https://github.com/peppelinux/django-jwtconnect-auth.git
````

Add it in `settings.INSTALLED_APPS`:
````
INSTALLED_APPS = [
    ...

    'rest_framework',
    'jwtconnect_auth',

    ...
]
````

Minimum parameters involved to get it to work, see a list of these in `jwtconnect_auth/settings.py`
````
# JWTCONNECT SETTINGS
JWTAUTH_KEY  = import_private_rsa_key_from_file('certs/private.key')
JWTAUTH_CERT = import_public_key_from_cert_file('certs/public.cert')
JWTAUTH_ISSUER = 'http://localhost:8000'
````

## Settings

In `settings.REST_FRAMEWORK` add Authentication class:

````
REST_FRAMEWORK = {

    'DEFAULT_AUTHENTICATION_CLASSES': [
        # jwtconnect auth
        'jwtconnect_auth.authentication.JWTConnectAuthBearer'
    ]
}
````

Create RSA certificates in your desidered folders:
````
openssl req -nodes -new -x509 -days 3650 -keyout certs/private.key -out certs/public.cert -subj '/CN=your.own.fqdn.com'
````

#### Settings Parameters
Complete list.

````
from cryptojwt.jwk.x509 import import_public_key_from_cert_file
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file

# in seconds
JWTAUTH_ACCESS_TOKEN_LIFETIME = 1800
JWTAUTH_REFRESH_TOKEN_LIFETIME = 3600

JWTAUTH_ALLOW_REFRESH = True
JWTAUTH_UPDATE_LAST_LOGIN = True

# Signature features (see cryptojwt documentation)

# if symmetric: discouraged, please mind the security!
JWTAUTH_ALGORITHM: 'HS256'
JWTAUTH_KEY = 'thatsecret'

# if asymmetric
JWTAUTH_ALGORITHM: 'RS256'
JWTAUTH_KEY  = import_private_rsa_key_from_file('certs/private.key')
JWTAUTH_CERT = import_public_key_from_cert_file('certs/public.cert')

JWTAUTH_ISSUER = 'ISSUER - service or provider name'
JWTAUTH_AUTH_HEADER_TYPES = ('Bearer',)

# include which one you want to pass in the token, the missing will be omitted
JWTAUTH_CLAIMS_MAP = dict(username = 'username',
                          first_name = 'given_name',
                          last_name = 'family_name',
                          email = 'email')

# indicates if a user can have multiple and concurrent active tokens or only one per time (the last overwrite the older)
JWTAUTH_MULTIPLE_TOKENS = True
````

# Tests

````
cd example
./manage.py test jwtconnect_auth -v 2
````

Coverage

````
cd example
pip install coverage
coverage erase
coverage run ./manage.py test jwtconnect_auth
coverage report -m
````

# API

Playing with internals

````
from jwtconnect_auth.jwks import *
from django.contrib.auth import get_user_model
user = get_user_model().objects.first()
data = JWTConnectAuthTokenBuilder.build(user)
data

jwts = JWTConnectAuthTokenBuilder.create(data)
````

data would be something like:
````
({'iat': 1600125663,
  'iss': 'http://localhost:8000',
  'sub': '80327042b96b9f1c00d9d04db816e84af4e3616db1d0694b13ab86f49fd251bf',
  'jti': '5069631f237a6711b950ab965666ae465aca4e7b5daa0ae783fac2e11e148fce',
  'ttype': 'T',
  'exp': 1600127463,
  'username': 'wert',
  'given_name': '',
  'family_name': '',
  'email': ''},
 {'iat': 1600125663,
  'iss': 'http://localhost:8000',
  'sub': '80327042b96b9f1c00d9d04db816e84af4e3616db1d0694b13ab86f49fd251bf',
  'ttype': 'R',
  'jti': '064dd076bcafa7fba9a2055452d8b7d48eb5327f1aa4dffc8d1be5ffd8bb3b12',
  'exp': 1600129263})
````

JWTs would be something like:
````
  "access_token": "eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOiAxNjAwMzMwNzk1LCAiaXNzIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsICJzdWIiOiAiYmIzNjI1NDgzYmQ0M2NjZGZhODk0ZWI3YTg4MTg3ZDNlZTI2MWQ0ZmRkMmIwMDFhNzMyMGY0YTRmMzk2YmM1YyIsICJqdGkiOiAiYmJhNWI3YmM2YzMzMjhlNmFjMGM2MDYxMTdjNGFkMTIxNzdiMzljMjc4ZDM0OTE3NTQ5NzljYWRhMGRkMmRhNSIsICJ0dHlwZSI6ICJUIiwgImV4cCI6IDE2MDAzMzI1OTUsICJ1c2VybmFtZSI6ICJjaXJvIiwgImVtYWlsIjogInRoYXRtYWlsQGluZ29hbGxhLm9yZyJ9.d_ZPZdBasemDuDEMZTkU_eCpCsrhrAvVobLdxkLZBI5E0-FLA4MJC66HxoXStUI2TXBwvqpKrcD_Je_5TNlqg7YuA-B9nUqkDPTIvUl1IwY4v4Ijyu-Trq6HNDkfnr4tYRKJqFIPzQGYnrcR_ox3-IdZQk1mveZzwwXWTnAyyA5G872jeTT0XOb8s2GBwUyS8ppT_ZstrxjpcGRcQ8YYIB7g4NAY33_BmeEFxsEbLmNrYYKR8PjskkCgiqOqtuhTaCBfBJJJ4BU07jBfUI0CjuJaLsKdAYA_HKlrH0B_hxbhF-LNvv88MtcuKD-FA76Ua3Ye8JQQqWXtCI6jYWbjPQ",
  "refresh_token": "eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOiAxNjAwMzMwNzk1LCAiaXNzIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsICJzdWIiOiAiYmIzNjI1NDgzYmQ0M2NjZGZhODk0ZWI3YTg4MTg3ZDNlZTI2MWQ0ZmRkMmIwMDFhNzMyMGY0YTRmMzk2YmM1YyIsICJ0dHlwZSI6ICJSIiwgImp0aSI6ICI0ZWY3ZTM5MDIxN2I4NDE3MzUyYjA1MTM3NGQ1MGQwN2U1ZTEyYWI4OWE2ZTkzZmJhN2NlNTFhMDE3ODZlMjZjIiwgImV4cCI6IDE2MDAzMzQzOTV9.PLfPFCSqxtoVyufYNTJuD60ElW-2YG7cyKXJX6WMzgHeaYA96zCelscnfiK_RCuLkr6woZ_mbcZtI24ZIaR4pG_JE7onxCP8wg3oZE0yMGKcv5GXnWeAjx5mE3eBiIhvrZMH6Vn19prNyAuQ8Y5JCJUUeJ4QZiuYYk3TZAKAXAPoNaU1e__f7qHDmkfdBEZ7LliX5bQxkviAdfXS5VbX5CAgB1gOlgbaO4FTbtOpKoVn4YV0gfD_eV_E004JnmpGiOc5-yapE1w3-tTKTkxnfggD6TZOCm8oIZv2k3vkc1pTBIrts1inNg7EEukPdYvX6GFba3fe4FIY-p_6HBmG4A",
  "token_type": "bearer",
  "expires_in": 1800

````

#### JWT implementation

[OidcMsg](https://oidcmsg.readthedocs.io/) is the underlying library for doing this.

````
from oidcmsg.message import Message

data = dict(
            # many attributes
            given_name='peppe',
            family_name='tarantino',

            exp=None, # timestamp representing the datetime of expiration
            iat=None, # timestamp representing the datetime of creation
            aud=None, # JWT is intended for, to which service have been released
            iss=None, # issuer, the django backend service identifier
            sid=None, # session id
            sub=None, # subject, no longher than 256bytes. Opaque string that univocally identifies the user
            jti=None  # unique identifier for this token
            )

msg = Message(**data)

# JWT representation (without signature)
msg.to_dict()
msg.to_jwt()

````

### JWS implementation

[CryptoJWT](https://cryptojwt.readthedocs.io/) is the underlying library for doing this.

*Symmetric*
````
from cryptojwt.jwk.hmac import SYMKey

keys = [SYMKey(key="A1B2C3D4HAHAHAHAHAHAHAHA")]
jws = msg.to_jwt(keys, "HS256")

# signed JWT
jws
````

*Asymmetric*

Build JWKs
````
from cryptojwt.jwk.rsa import new_rsa_key
rsa_key = new_rsa_key()
jwk = rsa_key.serialize(private=True)

# public
rsa_key.serialize()
````

Import JWKs
````
from cryptojwt.jwk.jwk import key_from_jwk_dict
_key = key_from_jwk_dict(jwk_dict)
````

Import PEM
````
from cryptojwt.jwk.x509 import import_public_key_from_cert_file
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file

public = import_public_key_from_cert_file('certs/public.cert')
private = import_private_rsa_key_from_file('certs/private.key')

# and then ...
from cryptojwt.jwk.rsa import RSAKey
rsa_key = RSAKey(priv_key=private)
````

Export JWKs to PEM
````
from cryptojwt.tools import keyconv

# public
keyconv.export_jwk(rsa_key)

# private
keyconv.export_jwk(rsa_key, private=True)

````

Sign a JWT
````
from cryptojwt.jwk.rsa import RSAKey

keys = [RSAKey(**jwk)]
jws = msg.to_jwt(keys, "RS256")

# signed jws
jws
````

*Message to Signed JWT*

````
# with symmetric keys
jwt = msg.to_jwt(keys, "HS256")

# with asymmetric keys
jwt = msg.to_jwt(keys, "RS256")
````

*JWT signature verification*
````
from cryptojwt.key_jar import KeyJar

key_jar = KeyJar()

# "" means default, you can always point to a issuer identifier
key_jar.import_jwks(jwk, issuer_id="")

recv = Message().from_jwt(jws, keyjar=key_jar, key=keys)
recv.verify() # must return True

recv.to_dict()
````
