local ffi = require 'ffi'
local base = require "resty.core.base"
local C = ffi.C

local ffi_cast = ffi.cast
local ffi_str = ffi.string
local get_string_buf = base.get_string_buf
local get_request = base.get_request

local _M = {version = "0.1"}
local mt = {__index = _M}

local ffi_str_type = ffi.typeof("ngx_http_lua_ffi_str_t*")
local ffi_str_size = ffi.sizeof("ngx_http_lua_ffi_str_t")


ffi.cdef[[
	int ngx_http_curiefense_ffi_get_log(ngx_http_request_t *r, ngx_http_lua_ffi_str_t *out);
]]

function _M:get_log()
	local raw_buf = get_string_buf(ffi_str_size)
	local buf = ffi_cast(ffi_str_type, raw_buf)
	local rc = C.ngx_http_curiefense_ffi_get_log(get_request(), buf)
	if rc > 0 then
		local logdata = ffi_str(buf.data, buf.len)
		return logdata
	end
	return nil
end

return _M