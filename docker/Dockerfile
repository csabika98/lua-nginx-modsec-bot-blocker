FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

ARG INSTALL_BOT_BLOCKER=false
ENV VER_NGINX=1.27.4
ENV VER_NGX_DEVEL_KIT=0.3.4
ENV VER_NJS=0.8.9
ENV VER_GEOIP=3.4
ENV VER_LUAJIT=2.1-20250117
ENV VER_LUA_NGINX_MODULE=0.10.28
ENV VER_LUA_RESTY_CORE=0.1.31
ENV VER_LUAROCKS=3.11.1
ENV VER_OPENRESTY_HEADERS=0.38
ENV VER_OPENRESTY_DNS=0.23
ENV VER_LUA_RESTY_LRUCACHE=0.15
ENV VER_OPENRESTY_MEMCACHED=0.17
ENV VER_OPENRESTY_MYSQL=0.27
ENV VER_OPENRESTY_REDIS=0.32
ENV VER_OPENRESTY_SHELL=0.03
ENV VER_OPENRESTY_SIGNAL=0.04
ENV VER_OPENRESTY_WEBSOCKET=0.13
ENV VER_OPENRESTY_STREAMLUA=35071d983042b6820427d2312c143a13a137b2ea
ENV VER_CLOUDFLARE_COOKIE=f418d77082eaef48331302e84330488fdc810ef4
ENV VER_OPENRESTY_TABLEPOOL=0.03
ENV VER_LUA_UPSTREAM=0.07
ENV VER_PROMETHEUS=0.20240525
ENV VER_MISC_NGINX=0.33


WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates curl g++ libmaxminddb-dev libpcre3-dev \
    libssl-dev libxml2-dev libxslt1-dev make patch unzip zlib1g-dev \
    git gnupg2 gettext-base gcc build-essential autoconf automake \
    libtool libcurl4-openssl-dev libfuzzy-dev ssdeep gettext pkg-config \
    libgeoip-dev libyajl-dev doxygen iproute2 libpcre2-dev liblua5.1-0-dev \
    wget dnsutils cron && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://nginx.org/download/nginx-${VER_NGINX}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/openresty/luajit2/archive/v${VER_LUAJIT}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/vision5/ngx_devel_kit/archive/v${VER_NGX_DEVEL_KIT}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/openresty/lua-nginx-module/archive/v${VER_LUA_NGINX_MODULE}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/openresty/headers-more-nginx-module/archive/v${VER_OPENRESTY_HEADERS}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/openresty/lua-upstream-nginx-module/archive/v${VER_LUA_UPSTREAM}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/leev/ngx_http_geoip2_module/archive/${VER_GEOIP}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/nginx/njs/archive/${VER_NJS}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/openresty/set-misc-nginx-module/archive/v${VER_MISC_NGINX}.tar.gz | tar -xz && \
    curl -fsSL https://github.com/openresty/stream-lua-nginx-module/archive/${VER_OPENRESTY_STREAMLUA}.tar.gz | tar -xz && \
    git clone https://github.com/owasp-modsecurity/ModSecurity-nginx && \
    git clone https://github.com/owasp-modsecurity/ModSecurity && \
    git clone https://github.com/coreruleset/coreruleset /etc/nginx/coreruleset



# sudo ln -sf /usr/local/bin/luajit /usr/local/bin/lua
# Build LuaJIT with explicit FFI support
RUN cd luajit2-${VER_LUAJIT} && \
    make -j$(nproc) &&  \
    make install && \
    ln -sf /usr/local/bin/luajit /usr/local/bin/lua



RUN cd ModSecurity && \
    git submodule init && \
    git submodule update && \
    ./build.sh && \
    ./configure --with-lua=/usr/local \
    --with-lua-include=/usr/local/include/luajit-2.1 \
    --with-lua-lib=/usr/local/lib && \
    make -j$(nproc) && \
    make install



# RUN export LUAJIT_LIB=/usr/local/lib
# RUN export LUAJIT_INC=/usr/local/include/luajit-2.1
# RUN export LD_LIBRARY_PATH=${LUAJIT_LIB}:${LD_LIBRARY_PATH:-}

# Configure and build Nginx with proper LuaJIT environment
RUN cd nginx-${VER_NGINX} && \
    export LUAJIT_LIB=/usr/local/lib && \
    export LUAJIT_INC=/usr/local/include/luajit-2.1 && \
    export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH && \
    ./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=nginx \
    --group=nginx \
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-ld-opt="-Wl,-rpath,${LUAJIT_LIB}" \
    --with-cc-opt="-I${LUAJIT_INC}" \
    --add-module=../ngx_devel_kit-${VER_NGX_DEVEL_KIT} \
    --add-module=../lua-nginx-module-${VER_LUA_NGINX_MODULE} \
    --add-module=../lua-upstream-nginx-module-${VER_LUA_UPSTREAM} \
    --add-module=../headers-more-nginx-module-${VER_OPENRESTY_HEADERS} \
    --add-module=../ngx_http_geoip2_module-${VER_GEOIP} \
    --add-module=../njs-${VER_NJS}/nginx \
    --add-module=../set-misc-nginx-module-${VER_MISC_NGINX} \
    --add-module=../stream-lua-nginx-module-${VER_OPENRESTY_STREAMLUA} \
    --add-module=../ModSecurity-nginx && \
    make -j$(nproc) && \
    make install

RUN groupadd --system --gid 101 nginx && \
    useradd --system --gid nginx --no-create-home --shell /bin/false --uid 101 nginx && \
    mkdir -p /var/cache/nginx /var/log/nginx /etc/nginx/sites-{available,enabled} && \
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx

COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/sites-available/default.conf
RUN mkdir -p /etc/nginx/sites_enabled/
RUN ln -s /etc/nginx/sites-available/default.conf /etc/nginx/sites-enabled/ && \
    cp ModSecurity/unicode.mapping /etc/nginx/ && \
    cp ModSecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.conf && \
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity.conf && \
    echo "Include /etc/nginx/coreruleset/crs-setup.conf" >> /etc/nginx/modsecurity.conf && \
    echo "Include /etc/nginx/coreruleset/rules/*.conf" >> /etc/nginx/modsecurity.conf

RUN if [ "$INSTALL_BOT_BLOCKER" = "true" ]; then \
    curl -sL https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/install-ngxblocker -o /usr/local/sbin/install-ngxblocker && \
    chmod +x /usr/local/sbin/install-ngxblocker && \
    /usr/local/sbin/install-ngxblocker -x && \
    /usr/local/sbin/setup-ngxblocker -x -n default.conf; \
fi

RUN rm -rf /build

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]