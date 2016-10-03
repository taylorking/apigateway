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

--- @module
--
-- @author Alex Song (songs)

local utils = require "lib/utils"
local logger = require "lib/logger"
local cjson = require "cjson"

local _M = {}

--- Create/overwrite Nginx Conf file for given route
-- @param baseConfDir
-- @param namespace
-- @param gatewayPath
-- @param routeObj
-- @return fileLocation location of created/updated conf file
function _M.createRouteConf(baseConfDir, namespace, gatewayPath, routeObj)
  routeObj = utils.serializeTable(cjson.decode(routeObj))
  local prefix = utils.concatStrings({"\tinclude /etc/api-gateway/conf.d/commons/common-headers.conf;\n",
                                      "\tset $upstream https://172.17.0.1;\n",
                                      "\tset $namespace ", namespace, ";\n",
                                      "\tset $gatewayPath ", gatewayPath, ";\n\n"})
  -- Set route headers and mapping by calling routing.processCall()
  local outgoingRoute = utils.concatStrings({"\taccess_by_lua_block {\n",
                                             "\t\tlocal routing = require \"routing\"\n",
                                             "\t\trouting.processCall(", routeObj, ")\n",
                                             "\t}\n\n",
                                             "\tproxy_pass $upstream;\n"})

  -- Add to endpoint conf file
  os.execute(utils.concatStrings({"mkdir -p ", baseConfDir, namespace}))
  local fileLocation = utils.concatStrings({baseConfDir, namespace, "/", gatewayPath, ".conf"})
  local file, err = io.open(fileLocation, "w")
  if not file then
    ngx.status = 500
    ngx.say(utils.concatStrings({"Error adding to endpoint conf file: ", err}))
    ngx.exit(ngx.status)
  end
  local location = utils.concatStrings({"location /api/", namespace, "/", ngx.unescape_uri(gatewayPath), " {\n",
                                        prefix,
                                        outgoingRoute,
                                        "}\n"})
  file:write(location)
  file:close()

  -- reload nginx to refresh conf files
  os.execute("/usr/local/sbin/nginx -s reload")

  return fileLocation
end


--- Delete Ngx conf file for given route
-- @param baseConfDir
-- @param namespace
-- @param gatewayPath
-- @return fileLocation location of deleted conf file
function _M.deleteRouteConf(baseConfDir, namespace, gatewayPath)
  local fileLocation = utils.concatStrings({baseConfDir, namespace, "/", gatewayPath, ".conf"})
  os.execute(utils.concatStrings({"rm -f ", fileLocation}))
  -- reload nginx to refresh conf files
  os.execute("/usr/local/sbin/nginx -s reload")

  return fileLocation
end

return _M