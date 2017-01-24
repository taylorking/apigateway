
local utils = require "lib/utils"
local request = require "lib/request"
local cjson = require "cjson" 
-- Process the security object
-- @param securityObj security object from nginx conf file 
-- @return oauthId oauth identification
local _M = {}
function process(red, tenant, gatewayPath, apiId, scope, apiKey, accessToken, securityObj) 
  if accessToken == nil then
    request.err(401, "No Authorization header provided")
  end
  local token = {}
  local key = utils.concatStrings({"oauth:providers:", securityObj.provider, ":tokens:", accessToken})
  if not (red:exists(key) == 1) then
    token = exchange(red, accessToken, securityObj.provider)
  else 
    token = cjson.decode(red:get(key))
  end

  if token == nil or token.email == nil then
    request.err(401, "Token didn't work or provider doesn't support OpenID connect.") 
    return
  end
 
  red:set(key, cjson.encode(token))
  
  if not token.expires == nil then
    red:expire(key, token.expires)
  end
  
  if not skipValidation and not validate(red, tenant, gatewayPath, apiId, scope, token) then
    request.err(401, "You are not subscribed to this API") 
  end
  return token
-- only check with the provider if we haven't cached the token. 
end

function exchange(red, token, provider) 
    local loaded, provider = pcall(require, utils.concatStrings({'oauth/', provider}))
    
    if not loaded then 
      request.err(500, 'Error loading OAuth provider authentication module')
      return 
    end

    local token = provider(token)
    -- cache the token
    return token
end

function validate (red, tenant, gatewayPath, apiId, scope, token) 
  if scope == 'tenant' then
    k = utils.concatStrings({'subscriptions:tenant:', tenant})
  elseif scope == 'resource' then
    k = utils.concatStrings({'subscriptions:tenant:', tenant, ':resource:', gatewayPath})
  elseif scope == 'api' then
    k = utils.concatStrings({'subscriptions:tenant:', tenant, ':api:', apiId})
  end
  k = utils.concatStrings({k, ':oauth:', token.email})
  ngx.log(ngx.DEBUG, k)
  if red:exists(k) == 1 then
    return true
  else 
    return false
  end
end 

_M.exchange = exchange
_M.process = process
return _M
