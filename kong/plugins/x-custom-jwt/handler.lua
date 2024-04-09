local xCustomJWT = {
    PRIORITY = 1025,
    VERSION = '1.0.0',
  }

local genericErrMsg = "You are not authorized to access to this service"

---------------------------------------------------------------------------------------------------
-- Craft the JWT 'x-custom-jwt' and Sign it having a JWS
---------------------------------------------------------------------------------------------------
local function jwtCrafterSigner(data, plugin_conf)
  
  local jwt   = require "resty.jwt"
  local pkey  = require("resty.openssl.pkey")
  local json  = require('cjson')
  local errFunc = {}
  local verboseMsg
  local signingKey
  
  -- Convert the private JWK key to a PEM format
  local pk, err = pkey.new(plugin_conf.private_jwk, {formats = "JWK", type = "*"})
  if err then
    verboseMsg = "Unable to load the JWK, error: '" .. err .. "'"
  else
    signingKey, err = pk:tostring("PrivateKey", "PEM", false)
    if err then
      verboseMsg = "Unable to output the JWK key to PEM format, error: '" .. err .. "'"
    else
      kong.log.notice("JWK converted to PEM: " .. signingKey)
    end
  end
  -- If there is an error on JWK to PEM conversion
  if verboseMsg then
    kong.log.err (verboseMsg)
    errFunc.ErrorMessage = genericErrMsg
    if plugin_conf.verbose then
      errFunc.VerboseMessage = verboseMsg
    end
    return nil, errFunc
  end
  
  -- Convert Private Key to JSON to get the 'kid'
  local privateJwkJson = json.decode(plugin_conf.private_jwk)

  -- Sign the JWT and build a JWS
  local jwt_token = jwt:sign(
    signingKey,
    {
      header = {
        typ = "JWT",
        alg = "RS256",
        kid = privateJwkJson.kid,
        jku = plugin_conf.jku
      },
      payload = data
    }
  )

  return jwt_token, errFunc

end

-----------------------------------------------------------------------------------------------
-- Get Payload from an Authorization Token (JWT)
-- The JWT has 3 parts, separated by a dot: Header.Payload.Signature
-----------------------------------------------------------------------------------------------
  local function get_payload_JWT (jwt_auth_token)
  local jwt_payload
  local utils = require "kong.tools.utils"
  local entries = utils.split(jwt_auth_token, ".")

  if #entries == 3 then
    jwt_payload = entries[2]
  else
    local err = "Inconsistent JWT: unable to get the typical structure Header.Payload.Signature"
    return nil, err
  end

  -- bas64 decoding of JWT payload
  local decode_base64 = ngx.decode_base64
  local decoded = decode_base64(jwt_payload)
  local cjson = require("cjson.safe").new()
  local jwt_auth_token_json, err = cjson.decode(decoded)
  -- If we failed to base64 decode
  if err then
    err = "Unable to decode JSON from JWT: '" .. err .. "'"
    return nil, err
  end

  return jwt_auth_token_json, nil
end

---------------------------------------------------------------------------------------------------
-- GURN / certificate
---------------------------------------------------------------------------------------------------
local function extract_gurn(cert)
  local err = nil
  local gurn = nil
  local openssl = require("resty.openssl.x509")

  local crt, err = openssl.new(cert,"PEM")
  if err then
    return gurn, err
  end

  -- Code processing the 'Subject'
  -- Subject example: C=WD, ST=Earth, O=Kong Inc., OU=Solution Engineering, CN=apim.eu/emailAddress=demo@apim.eu
  local subj, err = crt:get_subject_name()
  if err then
    return gurn, err
  end
  
  -- Get all values from Subject
  local subjectDN = ""
  for key,value in pairs(subj) do
    if subjectDN ~= "" then
      subjectDN = subjectDN .. ", "
    end
    subjectDN = subjectDN .. key.. "=" .. value.blob
  end
  gurn = subjectDN
  -- local obj, pos, err = subj:find("C")
  -- gurn = obj.blob

  -- Code processing the 'Issuer'
  -- Example:  
  --   Issuer: C=WD, ST=Earth, L=Global, O=Kong Inc., CN=Kong CA
  -- local issuer_name, err = crt:get_issuer_name()
  
  kong.log.notice("GURN: '" .. gurn .. "'")
  
  return gurn, err
end

---------------------------------------------------------------------------------------------------
-- Prepare the JWT payload
---------------------------------------------------------------------------------------------------
local function prepareJwtPayload(plugin_conf)
  local utils = require "kong.tools.utils"
  local data = {}
  local decode_base64 = ngx.decode_base64
  local entries
  local bearer_token
  local basic_authorization
  local subjectDN
  local api_key
  local errFunc = {}
  local verboseMsg
  
  -- First try to retrieve an Authorization Header from the Request
  local authorization_header = kong.request.get_header ("Authorization")
  
  -- If we found an Authorization Header
  if authorization_header ~= nil then
    kong.log.notice("'Authorization' header found='" .. authorization_header .. "'")
    -- Try to find an 'Authorization: Bearer'
    entries = utils.split(authorization_header, "Bearer ")
    if #entries == 2 then
      bearer_token = entries[2]
      kong.log.notice("Authenticated Token retrieved successfully: " .. bearer_token)
    else
      kong.log.notice("There is no 'Authorization: Bearer' header")
    end
    -- if 'Bearer' auth is not found, Try to find a 'Basic' auth
    if bearer_token == nil then
      entries = utils.split(authorization_header, "Basic ")
      if #entries == 2 then
        basic_authorization = entries[2]
        kong.log.notice("Basic Authorization retrieved successfully: " .. basic_authorization)
      else
        kong.log.notice("There is no 'Authorization: Basic' header")
      end
    end
  else
    kong.log.notice("There is no 'Authorization' header")
  end

  -- If there is no Authorization header (nor Bearer nor Basic), try to extract subjectDN from mutual TLS
  if not bearer_token and not basic_authorization then
    local cert, err = kong.client.tls.get_full_client_certificate_chain()
    if not err then
      if cert then
        kong.log.notice("Mutual TLS found | cert: " .. cert)
      else
        kong.log.notice("No mutual TLS")
      end
    else
      kong.log.notice("get_full_client_certificate_chain, err: " .. err)
    end

    if cert then
      local err
      subjectDN, err = extract_gurn(cert)
      if not err then
        kong.log.notice("subjectDN: '" .. subjectDN .. "'")
      else
        verboseMsg = "subjectDN extraction: " .. err
      end
    else
      kong.log.notice("There is no 'Client Certificate'")
    end
  end

  -- If there is no Authorization header / no subjectDN, try to extract an Api Key header
  if not bearer_token and not basic_authorization and not subjectDN and not verboseMsg then
    api_key = kong.request.get_header (plugin_conf.apikey_header)
    if not api_key then
      kong.log.notice("There is no '" .. plugin_conf.apikey_header .. "' header")
    end
  end
  
  -- If there is no Authorization header (nor Bearer nor Basic) / no subjectDN / no x-apikey
  if not bearer_token and not basic_authorization and not subjectDN and not api_key then
    errFunc.ErrorMessage = genericErrMsg
    local VerboseMessage = "No suitable Authentication method is found: no Bearer token, no Basic Auth, no mTLS, no Key Auth"
    if verboseMsg then
      VerboseMessage = VerboseMessage .. ". " .. verboseMsg
    end
    kong.log.err(VerboseMessage)
    if plugin_conf.verbose then
      errFunc.VerboseMessage = VerboseMessage
    end
    return nil, errFunc
  end
  
  -- Set the client_id value depending of the initial Authorization
  -- Authorization Token (JWT)
  if bearer_token then
    local bearer_token_payload, err = get_payload_JWT (bearer_token)
    if not err then
      -- Copy the entire content of AT
      data = utils.deep_copy(bearer_token_payload, true)
      data = bearer_token_payload
      -- Get the clientId claim (from the plugin configuration) and copy it
      if data[plugin_conf.bearer_clientid_claim] then
        data.client_id = data[plugin_conf.bearer_clientid_claim]
      else
        verboseMsg = "Unable to get '" .. plugin_conf.bearer_clientid_claim .. "' claim from the Bearer token"
      end
    else
      -- Error: Unable to get the 'Auth token' payload
      verboseMsg = "Unable to get the 'Auth token' payload: " .. err
    end
  -- Basic Authorization
  elseif basic_authorization then
    local basic_authorization_decoded = decode_base64(basic_authorization)
    if basic_authorization_decoded then
      local entries = utils.split(basic_authorization_decoded, ":")
      if #entries == 2 then
        data.client_id = entries[1]
      end
    else
      -- Error: Unable to decode correctly in base64 the 'Basic Auth'
      verboseMsg = "Unable to decode correctly in base64 the 'Basic Auth'"
    end
  -- Mutual TLS
  elseif subjectDN then 
    data.client_id = subjectDN
  -- API Key
  elseif api_key then
    data.client_id = api_key
  end

  -- If there is a pending error or If we failed to get 'client_id' we reject the request
  if verboseMsg or not data.client_id then
    errFunc.ErrorMessage = genericErrMsg
    local VerboseMessage = "The 'client_id' is not set"
    if verboseMsg then
      VerboseMessage = VerboseMessage .. ". " .. verboseMsg
    end
    kong.log.err(VerboseMessage)
    if plugin_conf.verbose then
        errFunc.VerboseMessage = VerboseMessage
    end
    return nil, errFunc
  end

  -- Set Issuer
  data.iss = plugin_conf.iss
  -- Set 'Issued at' + 'Expires In'
  data.iat = ngx.time()
  data.exp = data.iat + plugin_conf.expires_in

  -- Get API backend URL
  local service = kong.router.get_service()
  local service_port = ""
  -- If the API backend URL doesn't use the default ports (80 or 443) we explicitly add it
  if tostring(service.port) ~= '80'  and tostring(service.port) ~= '443' then
    service_port = ":" .. service.port
  end
  
  local path = ""
  if service.path then
    path = service.path
  end
  data.aud = service.protocol .. "://" .. service.host .. service_port .. path
  data.jti = utils.uuid()

  -- Get the entity of the currently authenticated Consumer (set by the Kong securiy plugins)
  local consumer = kong.client.get_consumer()
  if consumer then
    local act_client_id = consumer.custom_id or consumer.id
    kong.log.notice("Kong consumer retrieved successfully: '" .. act_client_id .. "'")
    if not data.act then
      -- Initialize the 'act' table
      data.act = {}
    end
    data.act.client_id = act_client_id
  else
    kong.log.notice("There is no Kong consumer credential")
  end

  return data, errFunc
end

---------------------------------------------------------------------------------------------------
-- Executed for every request from a client and before it is being proxied to the upstream service
---------------------------------------------------------------------------------------------------
function xCustomJWT:access(plugin_conf)
  
  local crafted_x_custom_jwt

  -- Get the Authentication and Prepare the JWT payload
  local data, errFunc = prepareJwtPayload(plugin_conf)
  if not errFunc.ErrorMessage then
    -- Craft the JWT and Sign it having a JWS
    crafted_x_custom_jwt, errFunc = jwtCrafterSigner(data, plugin_conf)
  end

  -- If there is an error
  if errFunc.ErrorMessage then
    return kong.response.exit(401, errFunc,  {["Content-Type"] = "application/json"})
  end
  
  -- Add the JWT to a 'x-custom-jwt' HTTP Header
  kong.service.request.set_header("x-custom-jwt", crafted_x_custom_jwt)
  
  kong.log.notice("JWT has been crafted: x-custom-jwt: " .. crafted_x_custom_jwt)

end

return xCustomJWT