local ngx_log = ngx.log
local ERR = ngx.ERR
local dosec_log = require "resty.dosec.log"
local socket = require "resty.dosec.socket"
local _M = {version = "0.1", socket={}}
local mt = {__index = _M}

local function exp_handler(msg)
    ngx_log(ERR, msg)
end

local function init_socket()
    ngx_log(ERR, "init socket")
    -- attack log
    local socket_attack,err = socket:init({
        host = '127.0.0.1',
        path = '/tmp/tproxy_listen.sock',
        sock_type = 'tcp',
        flush_limit = 40960,
        periodic_flush = 5,
    })
    if socket_attack == nil then
        local msg_err = "Failed to init socket for heart"
        if err then
            msg_err = msg_err.." with error:"..err
            ngx_log(ERR, msg_err.." with error:"..err)
        else
            ngx_log(ERR, msg_err)
        end
    end
    _M.socket.attack = socket_attack
    ngx_log(ERR, "init socket finished")
end

local function send_worker_log_handler()
    local socket = _M.socket.attack
    log_data = dosec_log:get_log()
    if log_data ~= nil then
        local bytes, err = socket:log(log_data)
        if err or bytes == nil or bytes == 0 then
            ngx_log(ERR, "send log failed: "..err)
        end
    end
end

function _M:send_worker_log()
    xpcall(send_worker_log_handler, exp_handler)
end
function _M:init_worker()
    xpcall(init_socket, exp_handler)
end

return _M