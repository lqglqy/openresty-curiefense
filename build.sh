#!/bin/bash
#cd bundle && patch -p0 < nginx_tproxy.patch && cd -

 ./configure --prefix=/dosec/openresty --with-luajit --with-zlib=/zlib-1.3 --add-module=./ngx-http-curiefense-module

 make -j4 && make install

 install -D lua/socket.lua /dosec/openresty/lualib/resty/dosec/socket.lua
 install -D lua/init.lua /dosec/openresty/lualib/resty/dosec/init.lua
 install -D lua/log.lua /dosec/openresty/lualib/resty/dosec/log.lua
 install conf/nginx.conf /dosec/openresty/nginx/conf/nginx.conf