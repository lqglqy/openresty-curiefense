#!/bin/bash
cd bundle && patch -p0 < nginx_tproxy.patch && cd -

 ./configure --prefix=/dosec/openresty --with-luajit --with-zlib=/zlib-1.3 --add-module=./ngx-http-curiefense-module

 make -j4 && make install