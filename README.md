# AUTHORIZATION SERVICE
## Introduction
The service provider OAuth token JWT Generation, The token are encrypted using RSA public Key.
The resource service should always have the private key to validate the token.

### Endpoints
1. /api/v1/oauth/token  
    Response {
      "accessToken": "e"
      "refreshToken": "",
      "tokenType": "Bearer",
      "expire_in": 3600,
      "scope": "read,write"
      }
2. 