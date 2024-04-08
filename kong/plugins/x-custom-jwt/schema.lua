local typedefs = require "kong.db.schema.typedefs"

return {
	name = "x-custom-jwt",
	fields = {
		{ protocols = typedefs.protocols },
		{ config = {
				type = "record",
				fields = {
					{ apikey_header = {type = "string", default = "apikey" }},
					{ expires_in = { type = "number", required = true, default = 1800 }},
					{ iss = typedefs.url({ required = true, default = "https://kong-gateway:8443/x-custom-jwt"}) },
					{ jku = typedefs.url({ required = true, default = "https://kong-gateway:8443/x-custom-jwt/jwks"}) },
					{ private_jwk = {type = "string", required = true, default = "{\"kty\": \"RSA\",\"kid\": \"kong\",...<***CHANGE_ME***>}"}},
					{ verbose = { type = "boolean", default = false }},
				},
			},
		}
	}
}