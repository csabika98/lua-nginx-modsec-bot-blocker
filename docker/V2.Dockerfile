# Stage 1: Build environment
FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

ARG INSTALL_BOT_BLOCKER=false
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
    libgeoip-dev libyajl-dev libpcre2-dev liblua5.1-0-dev \
    wget && \
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
    git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx && \
    git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity && \
    git clone --depth 1 https://github.com/coreruleset/coreruleset /etc/nginx/coreruleset

RUN cd luajit2-${VER_LUAJIT} && \
    make -j$(nproc) && \
    make install && \
    ln -sf /usr/local/bin/luajit /usr/local/bin/lua && \
    rm -rf ../luajit2-${VER_LUAJIT}

RUN cd ModSecurity && \
    git submodule update --init && \
    ./build.sh && \
    ./configure --with-lua=/usr/local \
    --with-lua-include=/usr/local/include/luajit-2.1 \
    --with-lua-lib=/usr/local/lib && \
    make -j$(nproc) && \
    make install && \
    rm -rf ../ModSecurity

RUN cd nginx-${VER_NGINX} && \
    export LUAJIT_LIB=/usr/local/lib && \
    export LUAJIT_INC=/usr/local/include/luajit-2.1 && \
    export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH && \
    ./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
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

RUN apt-get update && apt-get install sudo

RUN echo '#!/bin/bash\n\
install_lua_component() {\n\
    repo=$1\n\
    version=$2\n\
    src_path=$3\n\
    target_dir=/usr/local/share/lua/5.1/\n\
    git clone --depth 1 --branch "$version" "https://github.com/$repo"\n\
    cd "${repo#*/}"\n\
    sudo mkdir -p "$target_dir"\n\
    sudo cp -R $src_path "$target_dir"\n\
    cd ..\n\
    sudo rm -rf "${repo#*/}"\n\
}\n' > /install_lua_component.sh

RUN chmod +x /install_lua_component.sh && \
    . /install_lua_component.sh && \
    install_lua_component "openresty/lua-resty-core" "v$VER_LUA_RESTY_CORE" "lib/resty" && \
    install_lua_component "openresty/lua-resty-lrucache" "v$VER_LUA_RESTY_LRUCACHE" "lib/resty" && \
    install_lua_component "openresty/lua-resty-dns" "v$VER_OPENRESTY_DNS" "lib/resty" && \
    install_lua_component "openresty/lua-resty-redis" "v$VER_OPENRESTY_REDIS" "lib/resty" && \
    install_lua_component "openresty/lua-resty-memcached" "v$VER_OPENRESTY_MEMCACHED" "lib/resty" && \
    install_lua_component "openresty/lua-resty-mysql" "v$VER_OPENRESTY_MYSQL" "lib/resty" && \
    install_lua_component "openresty/lua-resty-shell" "v$VER_OPENRESTY_SHELL" "lib/resty" && \
    install_lua_component "openresty/lua-resty-signal" "v$VER_OPENRESTY_SIGNAL" "lib/resty" && \
    install_lua_component "openresty/lua-resty-websocket" "v$VER_OPENRESTY_WEBSOCKET" "lib/resty" && \
    install_lua_component "openresty/lua-tablepool" "v$VER_OPENRESTY_TABLEPOOL" "lib/"


FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

COPY --from=builder /usr/local /usr/local
COPY --from=builder /etc/nginx /etc/nginx
COPY --from=builder /usr/sbin/nginx /usr/sbin/
#COPY --from=builder /var/cache/nginx /var/cache/nginx
COPY --from=builder /etc/nginx/coreruleset /etc/nginx/coreruleset
COPY modsecurity.conf-recommended /usr/local/modsecurity/
COPY unicode.mapping /usr/local/modsecurity/

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libmaxminddb0 libpcre3 libssl3 zlib1g libxml2 libxslt1.1 \
    libgeoip1 libyajl2 liblua5.1-0 && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 101 nginx && \
    useradd --system --gid nginx --no-create-home --shell /bin/false --uid 101 nginx && \
    mkdir -p /var/log/nginx /var/cache/nginx /etc/nginx/sites-enabled && \
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx


COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/sites-available/default.conf
RUN ln -s /etc/nginx/sites-available/default.conf /etc/nginx/sites-enabled/ && \
    cp /usr/local/modsecurity/unicode.mapping /etc/nginx/ && \
    cp -r /etc/nginx/coreruleset/crs-setup.conf.example /etc/nginx/coreruleset/crs-setup.conf && \
    cp /usr/local/modsecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.conf && \
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity.conf && \
    echo "Include /etc/nginx/coreruleset/crs-setup.conf" >> /etc/nginx/modsecurity.conf && \
    echo "Include /etc/nginx/coreruleset/rules/*.conf" >> /etc/nginx/modsecurity.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]