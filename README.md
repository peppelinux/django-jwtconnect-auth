# django-jwtconnect-auth
A Django JWT Authentication Backend built on top of JWTConnect.io, [CryptoJWT](https://cryptojwt.readthedocs.io/) and [OidcMsg](https://oidcmsg.readthedocs.io/).

This application allows us to issue tokens in JWT format. This means that:

- Third-party applications can have Access tokens and renew these, via Rest API (Django Rest framework involved)
- Creation of token after a user have been logged in, in cases where third-party SingleSignOn systems were involved. There wouldn't be any submission of credentials from Application to jwtconnect-auth to obtain a token.

# Specifications and common endpoints

- Tokens could be relased with an authentication web resource where to submit username and password, mind that this would be disabled in the field of SSO infrastructures as SAML2.
- Token creation is triggered once, independently by what kind of External Authentication happens, a django signal creates the token for authenticated users if this doesn't exist yet (signal should be enabled in your setup).
  The release mechanism can be completely customized, you can decide how and where the release of token to the Apps would happen, implementing it in your own.
- Tokens can be refreshed via POST method: `/token/refresh`
- A user can have multiple active tokens or one at time (configurable in general `settings`). The last overwrite the older.
- TokenIntrospection endpoint would let third-party applications to get additional informations about a token.

  
# Token Introspection

The requestor must be authenticated (token involvedi n its http request headers).
Params supported: token, jti.

Example:
  ````
  curl -H 'Content-type: application/json; indent=4' -H "Accept: application/json" -d '{"jti":"cd9db7ca7560149c543b08a8b8f03393eeb979e9c26d877f66c1fbca23a8554d"}' -X POST http://127.0.0.1:8000/token/introspection -H "Authorization: Bearer $ACCESS_TOKEN"
  ````

![Alt text](gallery/introspection.png) 



# Token Refresh
  
The requestor must be authenticated.
Params supported: token -> must be a valid refresh token.

Example:
  ````
  curl -H 'Content-type: application/json; indent=4' -H "Accept: application/json" -d '{"token":"eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOiAxNjAwMjU5ODIxLCAiaXNzIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsICJzdWIiOiAiODAzMjcwNDJiOTZiOWYxYzAwZDlkMDRkYjgxNmU4NGFmNGUzNjE2ZGIxZDA2OTRiMTNhYjg2ZjQ5ZmQyNTFiZiIsICJ0dHlwZSI6ICJSIiwgImp0aSI6ICI4ZjM5NzJlZDFlYTQ4YmU1ZjE5MDI1N2JmNWQ0NDlmZTk1MDViNzk5NDFlM2Q4ZjVmNDc3NTM0ZmNiMzc4Y2QwIiwgImV4cCI6IDE2MDAyNjM0MjF9.HHv5W4TWUlf3O_jZ5q2i9aPYQhl3NwnDbtorRGMCKBEY8jnITbdrF2GHVch-irXTf6hW1Vcs9lwDWyn8LKSwhc612NDAatar6BiD1YOPzg8JjKuu_C1TUeyfXoDU2FSCNIodSCmgiSd1DY8hMlzHEs_wBY5O39rlk2f9iX4LDk9HNb1ZWdZ_RMXgydgsmKjalPc9dK_Ckylf0kC-GU1d3gXWkiejYYkN67xn_eU4r1aNWfhUAOMq_tV2XKKelxqYQTMNYht5EdgKaQ5BLMq8TVM5JH_zopI6QYl_NVqqzn9eydLD48sy7lLcFnCh0tgnNjEqSLGui9u6192P2kXmXw"}' -X POST http://127.0.0.1:8000/token/refresh -H "Authorization: Bearer $ACCESS_TOKEN"
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

Add minimum parameters are involved to get it to work, see the complete list in `jwtconnect_auth/settings.py`
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

JWTAUTH_UPDATE_LAST_LOGIN = True

# Signature features (see cryptojwt documentation)

# if symmetric: discourage, please forget it!
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
'access': 'eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOiAxNjAwMTI1NjYzLCAiaXNzIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsICJzdWIiOiAiODAzMjcwNDJiOTZiOWYxYzAwZDlkMDRkYjgxNmU4NGFmNGUzNjE2ZGIxZDA2OTRiMTNhYjg2ZjQ5ZmQyNTFiZiIsICJqdGkiOiAiNTA2OTYzMWYyMzdhNjcxMWI5NTBhYjk2NTY2NmFlNDY1YWNhNGU3YjVkYWEwYWU3ODNmYWMyZTExZTE0OGZjZSIsICJ0dHlwZSI6ICJUIiwgImV4cCI6IDE2MDAxMjc0NjMsICJ1c2VybmFtZSI6ICJ3ZXJ0In0.LYMlyaOS4LNTSCJN2xEnroMXbxe_FwNPVBS6Cl6oU6I9ALd3_phRZKb4syS8TJdgZJchxzjV20wPDtVZkHu2U7DD0kuk7-0mdDmunoT96nM4iix2BboRpIqm6NnnJL2bRQKEkTxRp8un5GUUfNSN-cQo8tGMTjUyCASTMx2XIaonfziycF7cMxmShceTNrdTaCASLLWMxpu0LrV8led6dsg1kkGPg8UyCSlpUZRfvmZoCnbvAk84kuAwhj6AqB777v_eqx0VPFa-aK09eJOOsVK1zakLk-Ld6lBFtwFdQjVxEQ15zydI_2WzcdYDmElTTGZ-aOBLmF7irQWCfX034A'
'refresh': 'eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOiAxNjAwMTI1NjYzLCAiaXNzIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsICJzdWIiOiAiODAzMjcwNDJiOTZiOWYxYzAwZDlkMDRkYjgxNmU4NGFmNGUzNjE2ZGIxZDA2OTRiMTNhYjg2ZjQ5ZmQyNTFiZiIsICJ0dHlwZSI6ICJSIiwgImp0aSI6ICIwNjRkZDA3NmJjYWZhN2ZiYTlhMjA1NTQ1MmQ4YjdkNDhlYjUzMjdmMWFhNGRmZmM4ZDFiZTVmZmQ4YmIzYjEyIiwgImV4cCI6IDE2MDAxMjkyNjN9.iZOXi0qRUzKKXE6R8zR3XFtrXkpNmF570LF4X8QpMl--3zysRZmshojRz97W_tjjb2lt9sm1nkcSPZ40GgCw7mxY9WcXxAxc7bGptBKsuqFIWtg6BhHTyva3TQOhiiYcJRhtI6gmWhUTScMnQ2ks5Tpjf5cXThp79BS9cGoxeGq3FPnpp_iFsQMnw96FL7jKalznFqHt1bfY63yuqCAsUW1JkK61pTm1Tn0H8H3xrm84h8LlWVWMHvrpzt1y-aHawHY0N2OT1h9wcuDhKygns4JQMkRtc6kgwbgwedr_5PMaBaE49t57P4Ezwvi8y41wEFJwFmSxPVr09EOZ6jqF9A'
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
