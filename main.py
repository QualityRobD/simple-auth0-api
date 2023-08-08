from flask import Flask, request, jsonify
from jose import jwt
import json
from urllib.request import urlopen

app = Flask(__name__)

AUTH0_DOMAIN = 'dev-qkw5s4olr7o8trqk.us.auth0.com'
API_AUDIENCE = 'https://dev-qkw5s4olr7o8trqk.us.auth0.com/api/v2/'
ALGORITHMS = ['RS256']


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header():
    """Obtains the access token from the Authorization Header"""
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != 'bearer':
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)

    token = parts[1]
    return token


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


@app.route('/api/private', methods=['GET'])
def private():
    token = get_token_auth_header()
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e'],
                'alg': key['alg']
            }
    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer='https://' + AUTH0_DOMAIN + '/'
        )
    except jwt.ExpiredSignatureError:
        raise AuthError({"code": "token_expired",
                        "description": "token is expired"}, 401)
    except jwt.JWTClaimsError:
        raise AuthError({"code": "invalid_claims",
                        "description":
                            "incorrect claims,"
                            "please check the audience and issuer"}, 401)
    except Exception:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Unable to parse authentication"
                            " token."}, 400)

    response = {
        "name": "Keras Selyrian",
        "age": "32",
        "addresses": [
            {
                "description": "home",
                "info": {
                    "street_number": "123",
                    "street_name": "Home Lane",
                    "city": "Adventure Bay",
                    "zip_code": "234vc"
                }
            },
            {
                "description": "work",
                "info": {
                    "street_number": "756",
                    "street_name": "Work Ave",
                    "city": "Detroit",
                    "zip_code": "48226"
                }
            }
        ]
    }

    return jsonify(response)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
