local jwt = require "resty.jwt"
local cjson = require "cjson"

local jwt_secret = os.getenv("JWT_SECRET") or "secret"
local auth_header = ngx.var.http_Authorization
local token

if auth_header then
    local _, _, t = string.find(auth_header, "Bearer%s+(.+)")
    token = t
end

if not token then
    token = ngx.var.arg_token or ngx.var.cookie_token
end

if not token then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Missing JWT token.")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local jwt_obj = jwt:verify(jwt_secret, token)

if not jwt_obj.verified then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say(cjson.encode(jwt_obj.reason))
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end
