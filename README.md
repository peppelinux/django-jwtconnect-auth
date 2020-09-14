# django-jwtconnect-auth
A Django JWT Authentication Backend on top of JWTConnect's CryptoJWT and OidcMsg

### Setup

Django project here.

Create your own RSA certificates
````
openssl req -nodes -new -x509 -days 3650 -keyout private.key -out public.cert -subj '/CN=your.own.fqdn.com'
````


#### JWT implementation

[OidcMsg](https://oidcmsg.readthedocs.io/) is the underlying library for doing this.

````
from oidcmsg.message import Message

data = dict(
            # many attributes
            given_name='peppe',
            family_name='tarantino',
            
            exp=None,     # timestamp representing the datetime of expiration
            iat=None, # timestamp representing the datetime of creation
            aud=None, # JWT is intended for, to which service have been released
            iss=None, # issuer, the django backend service identifier
            sid=None, # session id, backed side
            sub=None, # subject, no longher than 256bytes. Opaque string that univocally identifies the user
            )

msg = Message(**data)

# JWT representation (without signature)
msg.to_dict()
msg.to_jwt()

````

#### JWS implementation

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
rsa_key = RSAKey(pub_key=private)
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
The same as before, but with a different method.

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

recv = Message().from_jwt(jws, key=keys)
recv.verify() # must return True

recv.to_dict()
````
