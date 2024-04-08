# Kong plugin | `x-custom-jwt`: craft a custom JWT and sign it for building a JWS
1) Craft a custom JWT called `x-custom-jwt`
2) Load the private JWK from the plugin's configuration and convert it into a PEM format
3) Sign the JWT with the PEM string for building a JWS (RS256 algorithm)
4) Add the 'x-custom-jwt' to an HTTP Request Header backend API

The plugin `x-custom-jwt` doesn't check the validity of the input itself (neither checking of JWT signature & JWT expiration, nor user/password checking, nor checking Client TLS checking, nor api key checking). So it's **mandatory to use this plugin in conjunction with Kong security plugins**:
- [OIDC](https://docs.konghq.com/hub/kong-inc/openid-connect/)
- [JWT validation](https://docs.konghq.com/hub/kong-inc/jwt/)
- [Basic authorization](https://docs.konghq.com/hub/kong-inc/basic-auth/)
- [mTLS](https://docs.konghq.com/hub/kong-inc/mtls-auth/)
- [Key Authentication - Encrypted](https://docs.konghq.com/hub/kong-inc/key-auth/)

## High level algorithm to craft `x-custom-jwt`
```lua
-- Try to find one by one an Authentication given by the Consumer
find "Authorization: Bearer" header
if not "Authorization: Bearer" then
    find "Authorization: Basic" header
end
if not "Authorization: Bearer" and not "Authorization: Basic" then
    find "mTLS Client Certificate"
end
if not "Authorization: Bearer" and not "Authorization: Basic" and not "mTLS Client Certificate" then
    find "apikey" header
end

if not "Authorization: Bearer" and not "Authorization: Basic" and not "mTLS Client Certificate" and not "apikey" then
    -- The Consumer's request is blocked
    return "HTTP 401", "You are not authorized to consume this service"
end

-- If the Consumer sends a correct Authentication, we craft the 'x-custom-jwt' JWT
-- The 'client_id' claim has a value depending of the Consumer's Authentication
if "Authorization: Bearer" then
    -- Copy all the content of the AT (given by 'Authorization: Bearer')
    x-custom-jwt.payload = AT.payload
else if "Authorization: Basic" then
    -- Copy the username of the Basic Auth
    x-custom-jwt.payload.client_id = AT.payload.username
else if "mTLS Client Certificate" then
    -- Copy the entire subjectDN (all distinguished names) of the Client Certificate
    x-custom-jwt.payload.client_id = subjectDN
else if "apikey" then
    -- Copy the 'apikey' value
    x-custom-jwt.payload.client_id = apiKeyValue
end

-- If the 'x-custom-jwt.client_id' is not set
if not x-custom-jwt.payload.client_id then
    -- The Consumer's request is blocked
    return "HTTP 401", "You are not authorized to consume this service. Internal Error"
end

-- Header values for all Authentication methods
x-custom-jwt.header.typ = "JWT",
x-custom-jwt.header.alg = "HS256",
x-custom-jwt.header.kid = "<JWK.kid>", -- Got from the kid of private JWK
x-custom-jwt.header.jku = "<jku>" -- Got from the plugin Configuration

-- Common claims for all Authentication methods
x-custom-jwt.payload.iss = "<iss>" -- Got from the plugin Configuration
x-custom-jwt.payload.iat = "<current time>"
x-custom-jwt.payload.exp = x-custom-jwt.payload.iat + "<expires_in>"  -- Got from the plugin Configuration
x-custom-jwt.payload.aud = "<url>" -- the Backend_Api URL
x-custom-jwt.payload.jti = "<uuid>" -- Generation of a 'Universally unique identifier'

-- 'act.sub' claim
find "X-Consumer-Custom-Id" header
if "X-Consumer-Custom-Id" then
    x-custom-jwt.payload.act.client_id = "<X-Consumer-Custom-Id>" -- Got from 'X-Consumer-Custom-Id' header which is set by security plugins (OIDC, Basic Auth, Key Authentication, Mutual TLS Auth, etc.)
end

-- Sign the JWT with a private JWK (set in the plugin configuration) for building a JWS 
jws_x_custom_jwt = jwt:sign (x-custom-jwt, private_jwk)

-- Add the 'x-custom-jwt' header to the request's headers before sending the request to the Backend API
kong.service.request.set_header("x-custom-jwt", jws_x_custom_jwt)
```
## How to test the `x-custom-jwt` plugin with Kong Gateway
### Prerequisites 

1) install the [Kong Gateway](https://docs.konghq.com/gateway/latest/install/)
2) Install [http.ie](https://httpie.io/)
3) Prepare the JWK for getting the Public and Private Keypair
- You can use the JWK keypair provided in this repo:
  - JWKS (JSON Web Key Set) Public Key: `./test-keys/jwks-public.json`
  - JWK Private Key: `./test-keys/jwk-private.json`
- **Or** create your own JWK keypair: go for instance to the site https://mkjwk.org/ and configure the online tool with following values:
  - key Size: `2048`
  - Key Use: `Signature`
  - Algorithm: `RS256`
  - Key-ID: `SHA-256`
- Click on Generate, copy to clipboard the `Public and Private Keypair` (i.e. Private Key) and the `Public Key`
4) Create a Route to deliver the public JWKS
- The Route has the following properties:
  - name=`x-custom-jwt-jwks`
  - path=`/x-custom-jwt/jwks`
  - Click on `Save`
- Add the `Request Termination` plugin to the Route with:
  - `config.status_code`=`200`
  - `config.content_type`=`application/json`
  - `config.body`=copy/paste the content of `./test-keys/jwks-public.json` **Or**
  - `Config.Body`=**The `Public JWK Key` must be pasted from https://mkjwk.org/ and add `"keys": [` property for having a JWKS** If needed, adapt the `kid` to a custom value. JWKS Structure:
  ```json
  {
    "keys": [
      {
        *****  CHANGE ME WITH THE PUBLIC JWKS *****
      }
    ]
  }
  ```
  - Click on `Save`
- Add the `CORS` plugin to the Route with:
  - config.origins=`*`
  - Click on `Save`
5) Create a Gateway Service
- For `httpbin` service, add a Gateway Service with:
  - name=`httpbin`
  - URL=`http://httpbin.apim.eu/anything` 
  - Click on `Save`
- Add a Route to the Service with:
  - name=`httpbin` 
  - path=`/httpbin`
  - Click on `Save`
- Add `x-custom-jwt` plugin to the Service with:
  - config.iss=`<adapt the URL to your environment>` (example: https://kong-gateway:8443/x-custom-jwt)
  - config.jku=`<adapt the URL to your environment>` (example: https://kong-gateway:8443/x-custom-jwt/jwks)
  - config.private_jwk=copy/paste the content of `./test-keys/jwk-private.json` **Or**
  - config.private_jwk=paste the `Public and Private Keypair` from https://mkjwk.org/. If needed, adapt the `kid` to a custom value; the `kid` value must be the same as defined in `Prerequisites` heading (see the configuration of `Request Termination` plugin)

### "Authorization: Bearer"
0) Let's use the `httpbin` route 
1) Test `Sample #1`
- `Request #1`:
```shell
AT1=`cat ./sample-x-custom-jwt/1_input-access-token.txt` && http :8000/httpbin Authorization:' Bearer '$AT1
```
- `Response #1`: expected value of `x-custom-jwt` plugin:
```json
{
  "header": {
    "kid":"kong",
    "jku": "http://localhost:8000/x-custom-jwt/jwks",
    "typ": "JWT",
    "alg": "RS256"
  },
  "payload": {
    "client_id": "ma9oycqlep",
    "act": {
      "client_id": "oauth-custom_id"
    },
    "aud": "http://httpbin.apim.eu/anything",
    "part_nr_ansp_person": "39444822",
    "iat": 1689239122,
    "pi.sri": "reaIoODhdakJoNacp3N0yQQU3Gw..rOmI",
    "sub": "L000001",
    "part_nr_org": "28021937",
    "exp": 1689240922,
    "scope": "openid profile email",
    "iss": "https://kong-gateway:8443/x-custom-jwt/v2",
    "jti": "ca2a1f74-1041-437d-b908-29743e3381f0"
  },
  "signature": "xxxxx"
}
```
2) Test `Sample #2`
- `Request #2`:
```shell
AT2=`cat ./sample-x-custom-jwt/2_input-access-token.txt` && http :8000/httpbin Authorization:' Bearer '$AT2
```
- `Response #2`: expected value of `x-custom-jwt` plugin:
```json
{
  "header": {
    "kid":"kong",
    "jku": "http://localhost:8000/x-custom-jwt/jwks",
    "typ": "JWT",
    "alg": "RS256"
  },
  "payload": {
    "iat": 1689441329,
    "sub": "c0e6ab4b",
    "exp": 1689443129,
    "client_id": "c0e6ab4b",
    "rlm": "client",
    "scope": "axa-ch_openapi_travel-insurance_read axa-ch_openapi_travel-insurance_write",
    "iss": "http://localhost:8000/x-custom-jwt/v2",
    "jti": "095174c2-e08b-43cf-b0c2-15febfb0128c",
    "aud": "http://httpbin.apim.eu/anything"
  },
  "signature": "xxxxx"
}
```
3) Test `Sample #3`
- `Request #3`:
```shell
AT3=`cat ./sample-x-custom-jwt/3_input-access-token.txt` && http :8000/httpbin Authorization:' Bearer '$AT3
```
- `Response #3`: expected value of `x-custom-jwt` plugin:
```json
{
  "header": {
    "kid":"kong",
    "jku": "http://localhost:8000/x-custom-jwt/jwks",
    "typ": "JWT",
    "alg": "RS256"
  },
  "payload": {
    "iat": 1689441517,
    "sub": "L000001",
    "exp": 1689443317,
    "client_id": "ma9oycqlep",
    "part_nr_ansp_person": "39444822",
    "pi.sri": "reaIoODhdakJoNacp3N0yQQU3Gw..rOmI",
    "part_nr_org": "28021937",
    "aud": "http://httpbin.apim.eu/anything",
    "iss": "http://localhost:8000/x-custom-jwt/v2",
    "jti": "13073b87-9dfe-478e-9d36-e6145808e533",
    "scope": "openid profile email axa-ch_openapi_car-insurance_read axa-ch_openapi_vehicle-information_read"
  },
  "signature": "xxxxx"
}
```
### Example for "Authorization: Basic"
1) Open the Service (created above)
2) Create a new Route:
- name=`basicAuth`
- path=`/basicAuth`
3) Add `Basic Authentication` plugin to the Route (Leave default parameters)
4) Create a consumer with:
- username=`my-auth-username`
- Custom ID=`my-auth-username-ID`
5) Open the consumer, go on credentials, click on a `+ New Basic Auth Credential` and put:
- username=`my-auth`
- password=`My p@ssword!`
6) Click on save
7) Test
- `Request`:
```shell
http -a 'my-auth:My p@ssword!' :8000/basicAuth
```
- `Response`: expected value of `x-custom-jwt` plugin:
```json
{
  "header": {
    "typ": "JWT",
    "alg": "RS256",
    "kid": "kong",
    "jku": "https://kong-gateway:8443/x-custom-jwt/jwks"
  },
  "payload": {
    "act": {
      "client_id": "my-auth-username-ID"
    },
    "jti": "08e1f9e0-7cb7-4fb3-9d9a-1de487af3a03",
    "iss": "https://kong-gateway:8443/x-custom-jwt",
    "aud": "http://httpbin.apim.eu/anything",
    "iat": 1712585199,
    "exp": 1712586999,
    "client_id": "012345AZERTY!"
  },
  "signature": "xxxxx"
}
```
### Example for "mTLS Client Certificate"
1) Create a CA Certificate: open Certificates page and click `New CA Certficate`
- Copy/paste the content of `./mTLS/ca.cert.pem` in the CA field
- Click on Create
2) Open the CA Certificate just created and copy/paste its `ID`
3) Open the Service (created above)
4) Create a new a Route:
- name=`mtls-auth`
- path=`/mtls-auth`
5) Add `Mutual TLS Authentication` plugin to the Route and add to config.ca_certificates the `ÌD` of the CA cert
6) Click on Install
7) Create a consumer (linked with the client certificate) with:
- Username = `demo@apim.eu`
- Custom ID = `demo@apim.eu`
8) Click on create
9) Test
- `Request`:
```shell
http --verify=no --cert=./mTLS/1337.pem --cert-key=./mTLS/client.key https://localhost:8443/mtls-auth
```
- `Response`: expected value of `x-custom-jwt` plugin:
```json
{
  "header": {
    "typ": "JWT",
    "alg": "RS256",
    "kid": "kong",
    "jku": "https://kong-gateway:8443/x-custom-jwt/jwks"
  },
  "payload": {
    "act": {
      "client_id": "demo@apim.eu"
    },
    "jti": "ded4a84c-5f5e-48a5-b7b3-42613df0e236",
    "exp": 1689445843,
    "iss": "http://localhost:8000/x-custom-jwt/v2",
    "aud": "http://httpbin.apim.eu/anything",
    "client_id": "C=WD, ST=Earth, O=Kong Inc., OU=Solution Engineering, CN=apim.eu, emailAddress=demo@apim.eu",
    "iat": 1689444043
    },
  "signature": "xxxxx"
}
```
### Example for "Key Authentication"
1) Open the Service (created above)
2) Create a new a Route:
- name=`apiKey`
- path=`/apiKey`
3) Add `Key Auth` plugin to the Route with:
- config.key_names=`apikey`
4) Open the consumer `my-auth-username`, click on Credentials / Key Authentication and click on `+ New Key Auth Credential`, put:
- Key=`012345AZERTY!`
5) Click on `Create`
6) Test
- `Request`:
```shell
http :8000/apiKey apikey:'012345AZERTY!'
```
- `Response`: expected value of `x-custom-jwt` plugin:
  - Base64 encoded:
```
eyJraWQiOiJrb25nIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJqa3UiOiJodHRwczovL2tvbmctZ2F0ZXdheTo4NDQzL3gtY3VzdG9tLWp3dC9qd2tzIn0.eyJhY3QiOnsiY2xpZW50X2lkIjoibXktYXV0aC11c2VybmFtZS1JRCJ9LCJqdGkiOiI4MTg1ZjEyYi0wOTZlLTQzOWYtYWVlZC00ZGQxNjlkZDNlYWQiLCJpc3MiOiJodHRwczovL2tvbmctZ2F0ZXdheTo4NDQzL3gtY3VzdG9tLWp3dCIsImF1ZCI6Imh0dHA6Ly9odHRwYmluLmFwaW0uZXUvYW55dGhpbmciLCJpYXQiOjE3MTI1ODU2MTUsImV4cCI6MTcxMjU4NzQxNSwiY2xpZW50X2lkIjoiMDEyMzQ1QVpFUlRZISJ9.VZpSWJGQwPadGR-U_fXKbIvLHo6j6KuvTBG6UONpeq-c4sJpDZtELVfD27arD8iMaz7ncGpkdAnhBsl-e4i_N_lEyu0srYp0kOVHKFcCf8qIJYWFQSk0NQ5YLc59-AZ51RooZlCLcBv5LGeABHLKg49geolOVSwWTg0dN6tqVn1W1SpiDt63KCrZsdTV-YhYtHBjAnBYywRcFIsZoKaOt67JI0VO6o9hFzrPE8Tsr1kx6cePQFL44CEnbkRG1bny46PJQ4a_kMrT-i1v3UIum0EYtyfrFygrpdqA6AlNbjd7wfmc-p7zYKX-Mg84PCNYw34EoMrWk-jEt7cLUyPo3w
```
    - JSON decoded:
```json
{
  "header": {
    "typ": "JWT",
    "alg": "RS256",
    "kid": "kong",
    "jku": "https://kong-gateway:8443/x-custom-jwt/jwks"
  },
  "payload": {
  {
    "act": {
      "client_id": "my-auth-username-ID"
    },
    "jti": "8185f12b-096e-439f-aeed-4dd169dd3ead",
    "iss": "https://kong-gateway:8443/x-custom-jwt",
    "aud": "http://httpbin.apim.eu/anything",
    "iat": 1712585615,
    "exp": 1712587415,
    "client_id": "012345AZERTY!"
  },
  "signature": "xxxxx"
}
```

## Check the JWS with https://jwt.io
1) Open https://jwt.io
2) Copy/paste the `x-custom-jwt` header value
- If everything works correctly the jwt.io sends a `Signature Verified` message
- The public key is downloaded automatically through the route `x-custom-jwt-jwks` and the `Request Termination` plugin. If it's not the case, open the Browser Developer Tools and see the network tab and console tab. The classic issue is getting the JWKS by using the self-signed Kong certificate (on 8443); it's easy to fix the issue by opening a tab, going on the `jku` request (i.e. https://kong-gateway:8443/x-custom-jwt/jwks), clicking on Advanced and by clicking on 'Proceed to'
- There is a known limitation on jwt.io with `"use": "enc"` the match isn't done correctly and the JWK is not loaded automatically: we simply have to copy/paste the public JWK directly in the `VERIFY SIGNATURE` of the web page. With `"use": "sig"` there is no restriction
![Alt text](/images/1-JWT.io.jpg "jwt.io")