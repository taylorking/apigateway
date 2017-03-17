-- Copyright (c) 2016 IBM. All rights reserved.
--
--   Permission is hereby granted, free of charge, to any person obtaining a
--   copy of this software and associated documentation files (the "Software"),
--   to deal in the Software without restriction, including without limitation
--   the rights to use, copy, modify, merge, publish, distribute, sublicense,
--   and/or sell copies of the Software, and to permit persons to whom the
--   Software is furnished to do so, subject to the following conditions:
--
--   The above copyright notice and this permission notice shall be included in
--   all copies or substantial portions of the Software.
--
--   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
--   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
--   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
--   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
--   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
--   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
--   DEALINGS IN THE SOFTWARE.

--- @module redis
-- Module that the gateway uses to interact with redis

local cjson = require "cjson"
local utils = require "lib/utils"
local logger = require "lib/logger"
local request = require "lib/request"
local lrucache = require "resty.lrucache" 
local CACHE_SIZE = 200 -- os.getenv('CACHE_SIZE') 
local cachingEnabled = false

if cachingEnabled then 
  local c, err = lrucache.new(CACHE_SIZE)
  if not c then 
    return error("Failed to initialize LRU cache" .. (err or "unknown"))
  end 
end 


local REDIS_FIELD = "resources"

local _M = {}

----------------------------
-- Initialization/Cleanup --
----------------------------

--- Initialize and connect to Redis
-- @param host redis host
-- @param port redis port
-- @param password redis password (nil if no password)
-- @param timeout redis timeout in milliseconds
function _M.init(host, port, password, timeout)
  local redis = require "resty.redis"
  local red = redis:new()
  red:set_timeout(timeout)
  -- Connect to Redis server
  local retryCount = 4
  local connect, err = red:connect(host, port)
  while not connect and retryCount > 0 do
    local msg = utils.concatStrings({"Failed to conect to redis at ", host, ":", port, ". Retrying ", retryCount, " more times."})
    if retryCount == 1 then
      msg = utils.concatStrings({msg:sub(1, -3), "."})
    end
    logger.info(msg)
    retryCount = retryCount - 1
    os.execute("sleep 1")
    connect, err = red:connect(host, port)
  end
  if not connect then
    request.err(500, utils.concatStrings({"Failed to connect to redis: ", err}))
  end
  -- Authenticate with Redis
  if password ~= nil and password ~= "" then
    local res, err = red:auth(password)
    if not res then
      request.err(500, utils.concatStrings({"Failed to authenticate: ", err}))
    end
  end
  return red
end

--- Add current redis connection in the ngx_lua cosocket connection pool
-- @param red Redis client instance
function _M.close(red)
  -- put it into the connection pool of size 100, with 10 seconds max idle time
  local ok, err = red:set_keepalive(10000, 100)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to set keepalive: ", err}))
  end
end

---------------------------
----------- APIs ----------
---------------------------

--- Add API to redis
-- @param red Redis client instance
-- @param id id of API
-- @param apiObj the api to add
-- @param existingAPI existing api to update
function _M.addAPI(red, id, apiObj, existingAPI)
  if existingAPI == nil then
    local apis = _M.getAllAPIs(red)
    -- Return error if api with basepath already exists
    for apiId, obj in pairs(apis) do
      if apiId%2 == 0 then
        obj = cjson.decode(obj)
        if obj.tenantId == apiObj.tenantId and obj.basePath == apiObj.basePath then
          request.err(500, "basePath not unique for given tenant.")
        end
      end
    end
  else
    -- Delete all resources for the existingAPI
    local basePath = existingAPI.basePath:sub(2)
    for path, v in pairs(existingAPI.resources) do
      local gatewayPath = ngx.unescape_uri(utils.concatStrings({basePath, ngx.escape_uri(path)}))
      gatewayPath = gatewayPath:sub(1,1) == "/" and gatewayPath:sub(2) or gatewayPath
      local redisKey = utils.concatStrings({"resources:", existingAPI.tenantId, ":", gatewayPath})
      _M.deleteResource(red, redisKey, REDIS_FIELD)
    end
  end
  -- Add new API
  apiObj = cjson.encode(apiObj):gsub("\\", "")
  local ok, err = hset(red, "apis", id, apiObj)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to save the API: ", err}))
  end
  return cjson.decode(apiObj)
end

--- Get all APIs from redis
-- @param red Redis client instance
function _M.getAllAPIs(red)
  local res, err = hgetall(red, "apis")
  if not res then
    request.err(500, utils.concatStrings({"Failed to retrieve APIs: ", err}))
  end
  return res
end

--- Get a single API from redis given its id
-- @param red Redis client instance
-- @param id id of API to get
function _M.getAPI(red, id)
  local api, err = hget(red, "apis", id)
  if not api then
    request.err(500, utils.concatStrings({"Failed to retrieve the API: ", err}))
  end
  if api == ngx.null then
    return nil
  end
  return cjson.decode(api)
end

--- Delete an API from redis given its id
-- @param red Redis client instance
-- @param id id of API to delete
function _M.deleteAPI(red, id)
  local ok, err = hdel(red, "apis", id)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to delete the API: ", err}))
  end
end

function _M.resourceToApi(red, resource)
  local resource = hget(red, resource, "resources")
  if resource == ngx.null then
    return nil
  end
  resource = cjson.decode(resource)
  return resource.apiId
end
-----------------------------
--------- Resources ---------
-----------------------------

--- Generate Redis object for resource
-- @param ops list of operations for a given resource
-- @param apiId resource api id (nil if no api)
-- @param tenantObj tenant information
function _M.generateResourceObj(ops, apiId, tenantObj)
  local resourceObj = {
    operations = {}
  }
  for op, v in pairs(ops) do
    op = op:upper()
    resourceObj.operations[op] = {
      backendUrl = v.backendUrl,
      backendMethod = v.backendMethod
    }
    if v.policies then
      resourceObj.operations[op].policies = v.policies
    end
    if v.security then
      resourceObj.operations[op].security = v.security
    end
  end
  if apiId then
    resourceObj.apiId = apiId
  end
  if tenantObj then
    resourceObj.tenantId = tenantObj.id
    resourceObj.tenantNamespace = tenantObj.namespace
    resourceObj.tenantInstance = tenantObj.instance
  end
  return cjson.encode(resourceObj)
end

--- Create/update resource in redis
-- @param red redis client instance
-- @param key redis resource key
-- @param field redis resource field
-- @param resourceObj redis object containing operations for resource
function _M.createResource(red, key, field, resourceObj)
  -- Add/update resource to redis
  local ok, err = hset(red, key, field, resourceObj)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to save the resource: ", err}))
  end
end

--- Add resource key to index set
-- @param red redis client instance
-- @param index index key
-- @param resourceKey resource key to add
function _M.addResourceToIndex(red, index, resourceKey)
  local ok, err = sadd(red, index, resourceKey)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to update the resource index set: ", err}))
  end
end

--- Delete resource key from index set
-- @param red redis client instance
-- @param index index key
-- @param key resourceKey key to delete
function _M.deleteResourceFromIndex(red, index, resourceKey)
  local ok, err = srem(red, index, resourceKey)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to update the resource index set: ", err}))
  end
end

--- Get resource in redis
-- @param red redis client instance
-- @param key redis resource key
-- @param field redis resource field
-- @return resourceObj redis object containing operations for resource
function _M.getResource(red, key, field)
  local resourceObj, err = hget(red, key, field)
  if not resourceObj then
    request.err(500, utils.concatStrings({"Failed to retrieve the resource: ", err}))
  end
  -- return nil if resource doesn't exist
  if resourceObj == ngx.null then
    return nil
  end
  return resourceObj
end

--- Get all resource keys for a tenant in redis
-- @param red redis client instance
-- @param tenantId tenant id
function _M.getAllResourceKeys(red, tenantId)
  local keys, err = smembers(red, utils.concatStrings({"resources:", tenantId, ":__index__"}))
  if not keys then
    request.err(500, utils.concatStrings({"Failed to retrieve resource keys: ", err}))
  end
  return keys
end

--- Delete resource in redis
-- @param red redis client instance
-- @param key redis resource key
-- @param field redis resource field
function _M.deleteResource(red, key, field)
  local resourceObj, err = hget(red, key, field)
  if not resourceObj then
    request.err(500, utils.concatStrings({"Failed to delete the resource: ", err}))
  end
  if resourceObj == ngx.null then
    request.err(404, "Resource doesn't exist.")
  end
  -- Delete redis resource
  local ok, err = del(red, key)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to delete the resource: ", err}))
  else
    return ok
  end
end

-----------------------------
---------- Tenants ----------
-----------------------------

--- Add tenant to redis
-- @param red Redis client instance
-- @param id id of tenant
-- @param tenantObj the tenant to add
function _M.addTenant(red, id, tenantObj)
  local tenants = _M.getAllTenants(red)
  -- Return tenant from redis if it already exists
  for tenantId, obj in pairs(tenants) do
    if tenantId%2 == 0 then
      obj = cjson.decode(obj)
      if obj.namespace == tenantObj.namespace and obj.instance == tenantObj.instance then
        return cjson.encode(obj)
      end
    end
  end
  -- Add new tenant
  tenantObj = cjson.encode(tenantObj)
  local ok, err = hset(red, "tenants", id, tenantObj)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to add the tenant: ", err}))
  end
  return tenantObj
end

--- Get all tenants from redis
-- @param red Redis client instance
function _M.getAllTenants(red)
  local res, err = hgetall(red, "tenants")
  if not res then
    request.err(500, utils.concatStrings({"Failed to retrieve tenants: ", err}))
  end
  return res
end

--- Get a single tenant from redis given its id
-- @param red Redis client instance
-- @param id id of tenant to get
function _M.getTenant(red, id)
  local tenant, err = hget(red, "tenants", id)
  if not tenant then
    request.err(500, utils.concatStrings({"Failed to retrieve the tenant: ", err}))
  end
  if tenant == ngx.null then
    return nil
  end
  return cjson.decode(tenant)
end

--- Delete an tenant from redis given its id
-- @param red Redis client instance
-- @param id id of tenant to delete
function _M.deleteTenant(red, id)
  local ok, err = hdel(red, "tenants", id)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to delete the tenant: ", err}))
  end
end

-----------------------------
--- API Key Subscriptions ---
-----------------------------

--- Create/update subscription/apikey in redis
-- @param red redis client instance
-- @param key redis subscription key to create
function _M.createSubscription(red, key)
  -- Add/update a subscription key to redis
  local ok, err = set(red, key, '')
  if not ok then
    request.err(500, utils.concatStrings({"Failed to add the subscription key", err}))
  end
end

--- Delete subscription/apikey int redis
-- @param red redis client instance
-- @param key redis subscription key to delete
function _M.deleteSubscription(red, key)
  local subscription, err = get(red, key)
  if not subscription then
    request.err(500, utils.concatStrings({"Failed to delete the subscription key: ", err}))
  end
  if subscription == ngx.null then
    request.err(404, "Subscription doesn't exist.")
  end
  local ok, err = del(red, key)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to delete the subscription key: ", err}))
  end
end

--- Check health of gateway
function _M.healthCheck()
  request.success(200,  "Status: Gateway ready.")
end

-----------------------------
-------- v2 Swagger ---------
-----------------------------

function _M.addSwagger(red, id, swagger)
  swagger = cjson.encode(swagger)
  local ok, err = hset(red, "swagger", id, swagger)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to add swagger: ", err}))
  end
  return cjson.decode(swagger)
end

function _M.getSwagger(red, id)
  local swagger, err = hget(red, "swagger", id)
  if not swagger then
    request.err(500, utils.concatStrings({"Failed to add swagger: ", err}))
  end
  if swagger == ngx.null then
    return nil
  end
  return cjson.decode(swagger)
end

function _M.deleteSwagger(red, id)
  local existing = _M.getSwagger(red, id)
  if existing == nil then
    request.err(404, 'Swagger doesn\'t exist')
  end
  local ok, err = hdel(red, "swagger", id)
  if not ok then
    request.err(500, utils.concatStrings({"Failed to delete swagger: ", err}))
  end
end


-- LRU Caching methods 

function exists(red, key) 
  if cachingEnabled then 
    local cached = c:get(key)
    if cached ~= nil then 
      return 1
    end 
  -- if it isn't in the cache, try and load it in there
    local result = red:get(key)
    if result ~= nil then
      c:set(key, result)
      return 1
    end 
    return 0 
  else 
    return red:exists(key) 
  end 
end 

function get(red, key) 
  if cachingEnabled then 
    local cached, stale = c:get(key)
    if cached ~= nil then
      return cached 
    else   
      local result = red:get(key) 
      c:set(key, result, 15) 
      return result
    end 
  else
    return red:get(key)
  end
end

function hget(red, key, id) 
  if cachingEnabled then 
    local cachedmap, stale = c:get(key)
    if cachedmap ~= nil then
      local cached = cachedmap:get(id)
      if cached ~= nil then
         return cached 
      else
        local result = red:hget(key, id) 
        cachedmap:set(id, result, 15) 
        c:set(key, cachedmap)
        return result
      end
    else
      local result = red:hget(key, id)
      local newcache = lrucache.new(CACHE_SIZE) 
      newcache:set(id, result) 
      c:set(key, newcache)
      return result  
    end
  else
    return red:hget(key, id)
  end
end 

function hgetall(red, key) 
  return red:hgetall(key)
end 

function hset(red, key, id, value)
  if cachingEnabled then 
    local cachedmap = c:get(key)
    if cachedmap ~= nil then 
      cachedmap:set(id, value) 
      c:set(key, cachedmap)
      return red:hset(key, id, value)
    else 
      local val = lrucache.new(CACHE_SIZE)
      val:set(id, value) 
      c:set(key, val)
    end 
  end
  return red:hset(key, id, value) 
end 

function expire(red, key, ttl) 
  if cachingEnabled then 
    local cached = c:get(key) 
    local value = '' 
    if cached ~= nil then -- just put it back in the cache with a ttl 
      value = cached 
    end 
    c:set(key, value, ttl)
  end
  return red:expire(key, ttl)
end 

function del(red, key) 
  c:delete(key)
  return red:del(key)
end
 
function hdel(red, key, id)
  if cachingEnabled then 
    local cachecontents = c:get(key) 
    if cachecontents ~= nil then
      cachecontents:del(id)
      c:set(key, cachecontents)
    end 
  end
  return red:hdel(key, id) 
end 

function smembers(red, key) 
  return red:smembers(key) 
end

function srem(red, key, id)
  return red:srem(key, id) 
end 

function sadd(red, key, id)
  return red:sadd(red, key, id) 
end 


_M.get = get
_M.set = set
_M.exists = exists
_M.expire = expire
return _M
