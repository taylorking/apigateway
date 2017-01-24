local _M = {}

local redis = require "lib/redis"
local utils = require "lib/utils"
local REDIS_HOST = os.getenv("REDIS_HOST")
local REDIS_PORT = os.getenv("REDIS_PORT")
local REDIS_PASS = os.getenv("REDIS_PASS")

function process(securityObj)
  local ok, result = pcall(require, utils.concatStrings({'policies/security/', securityObj.type}))
  if not ok then
    ngx.err(500, 'An unexpected error ocurred while processing the security policy') 
  end 
  
  local red = redis.init(REDIS_HOST, REDIS_PORT, REDIS_PASS, 1000)
  local tenant = ngx.var.tenant
  local gatewayPath = ngx.var.gatewayPath
  local apiId = ngx.var.apiId
  local scope = securityObj.scope

  local header = (securityObj.header == nil) and 'x-api-key' or securityObj.header
  
  local apiKey = ngx.var[utils.concatStrings({'http_', header}):gsub("-", "_")]
  local accessToken = ngx.var[utils.concatStrings({'http_', 'Authorization'}):gsub("-", "_")]

  result.process(red, tenant, gatewayPath, apiId, scope, apiKey, accessToken, securityObj)
end

_M.process = process

return _M 
