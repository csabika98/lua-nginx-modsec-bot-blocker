#!/usr/bin/env bash
set -euxo pipefail

ULTIMATE_BAD_BOT_BLOCKER=${ULTIMATE_BAD_BOT_BLOCKER:-false}
VER_NGINX=${VER_NGINX:-1.25.3}
VER_LUA=${VER_LUA:-5.1}
VER_LUAROCKS=${VER_LUAROCKS:-3.9.2}

export DEBIAN_FRONTEND=noninteractive

(
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl g++ libmaxminddb-dev libpcre3-dev \
        libssl-dev libxml2-dev libxslt1-dev make patch unzip zlib1g-dev \
        git gnupg2 gettext-base gcc build-essential autoconf automake \
        libtool libcurl4-openssl-dev libfuzzy-dev ssdeep pkg-config \
        libgeoip-dev libyajl-dev libpcre2-dev "liblua${VER_LUA}-dev"

    BUILD_DIR=/build
    mkdir -p $BUILD_DIR
    cd $BUILD_DIR

    download_zip() {
        url=$1
        target_dir=$2
        temp_dir=$(mktemp -d)
        curl -fsSL -o temp.zip "$url"
        unzip temp.zip -d "$temp_dir"
        rm temp.zip
        nested_dir=$(find "$temp_dir" -mindepth 1 -maxdepth 1 -type d)
        mv "$nested_dir" "$target_dir"
        rm -rf "$temp_dir"
    }

    download_tgz() {
        curl -fsSL "$1" | tar -xz
    }

    download_tgz "https://nginx.org/download/nginx-${VER_NGINX}.tar.gz"
    download_tgz "https://luarocks.org/releases/luarocks-${VER_LUAROCKS}.tar.gz"
    download_zip "https://github.com/openresty/luajit2/archive/refs/heads/v2.1-agentzh.zip" luajit-2.1
    download_zip "https://github.com/vision5/ngx_devel_kit/archive/refs/heads/master.zip" ngx_devel_kit
    download_zip "https://github.com/openresty/lua-nginx-module/archive/refs/heads/master.zip" lua-nginx-module
    download_zip "https://github.com/openresty/headers-more-nginx-module/archive/refs/heads/master.zip" headers-more-nginx-module
    download_zip "https://github.com/openresty/lua-upstream-nginx-module/archive/refs/heads/master.zip" lua-upstream-nginx-module
    download_zip "https://github.com/leev/ngx_http_geoip2_module/archive/refs/heads/master.zip" ngx_http_geoip2_module
    download_zip "https://github.com/nginx/njs/archive/refs/heads/master.zip" njs
    download_zip "https://github.com/openresty/set-misc-nginx-module/archive/refs/heads/master.zip" set-misc-nginx-module
    download_zip "https://github.com/openresty/stream-lua-nginx-module/archive/refs/heads/master.zip" stream-lua-nginx-module
    download_zip "https://github.com/openresty/memc-nginx-module/archive/refs/heads/master.zip" memc-nginx-module
    download_zip "https://github.com/openresty/xss-nginx-module/archive/refs/heads/master.zip" xss-nginx-module
    download_zip "https://github.com/openresty/lua-ssl-nginx-module/archive/refs/heads/master.zip" lua-ssl-nginx-module
    download_zip "https://github.com/openresty/encrypted-session-nginx-module/archive/refs/heads/master.zip" encrypted-session-nginx-module
    download_zip "https://github.com/openresty/echo-nginx-module/archive/refs/heads/master.zip" echo-nginx-module
    download_zip "https://github.com/knyar/nginx-lua-prometheus/archive/refs/heads/main.zip" nginx-lua-prometheus
    download_zip "https://github.com/cloudflare/lua-upstream-cache-nginx-module/archive/refs/heads/master.zip" lua-upstream-cache-nginx-module
    git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx
    git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/owasp-modsecurity/ModSecurity
    git clone --depth 1 --shallow-submodules https://github.com/coreruleset/coreruleset /etc/nginx/coreruleset

    # Build LuaJIT
    make -C luajit-2.1 -j$(nproc)
    make -C luajit-2.1 install PREFIX=/usr/local
    ln -sf /usr/local/bin/luajit /usr/local/bin/lua

    # Build ModSecurity
    cd ModSecurity
    git submodule update --init
    ./build.sh
    ./configure --with-lua=/usr/local \
        --with-lua-include=/usr/local/include/luajit-2.1 \
        --with-lua-lib=/usr/local/lib
    make -j$(nproc)
    make install
    cd ..

    # Build Nginx
    cd "nginx-${VER_NGINX}"
    export LUAJIT_LIB=/usr/local/lib
    export LUAJIT_INC=/usr/local/include/luajit-2.1
    export LD_LIBRARY_PATH=/usr/local/lib${LD_LIBRARY_PATH:+:}$LD_LIBRARY_PATH
    export PATH=/usr/local/bin:$PATH
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
            $(echo \
            --add-module=../ngx_devel_kit \
            --add-module=../lua-nginx-module \
            --add-module=../headers-more-nginx-module \
            --add-module=../lua-upstream-nginx-module \
            --add-module=../ngx_http_geoip2_module \
            --add-module=../njs/nginx \
            --add-module=../set-misc-nginx-module \
            --add-module=../stream-lua-nginx-module \
            --add-module=../memc-nginx-module \
            --add-module=../xss-nginx-module \
            --add-module=../lua-ssl-nginx-module \
            --add-module=../encrypted-session-nginx-module \
            --add-module=../echo-nginx-module \
            --add-module=../lua-upstream-cache-nginx-module \
            --add-module=../ModSecurity-nginx) && \
    make -j$(nproc)
    make install
    cd ..

    # Build LuaRocks
    cd "luarocks-${VER_LUAROCKS}"
    ./configure --with-lua=/usr/local
    make -j$(nproc)
    make install
    cd ..

    VER_LUA=5.1 \
    LUA_LIB_DIR=/usr/local/share/lua/${VER_LUA} \
    PREFIX=/usr/local

    lua_components=" \
        openresty/lua-resty-core \
        openresty/lua-resty-lrucache \
        openresty/lua-resty-dns \
        openresty/lua-resty-redis \
        openresty/lua-resty-mysql \
        openresty/lua-resty-memcached \
        openresty/lua-resty-shell \
        openresty/lua-resty-signal \
        openresty/lua-resty-websocket \
        openresty/lua-tablepool \
        openresty/lua-resty-string \
        openresty/lua-resty-upload \
        openresty/lua-resty-upstream-healthcheck \
        openresty/lua-resty-balancer \
        cloudflare/lua-resty-logger-socket:lib \
        knyar/nginx-lua-prometheus:."

    set -eux; \
        for component in ${lua_components}; do \
            repo=$(echo "${component}" | cut -d: -f1); \
            path=$(echo "${component}" | cut -d: -f2); \
            dir_name=$(basename "${repo}"); \
            \
            echo "Installing ${repo}..."; \
            rm -rf "${dir_name}"; \
            git clone --depth 1 "https://github.com/${repo}" "${dir_name}"; \
            \
            cd "${dir_name}"; \
            if [ -f Makefile ]; then \
                make && \
                make install \
                    LUA_LIB_DIR="/usr/local/share/lua/5.1" \
                    PREFIX="/usr/local"; \
            else \
                case "${repo}" in \
                    cloudflare/lua-resty-logger-socket) \
                        cp -R lib/resty/logger /usr/local/share/lua/5.1/resty/ ;; \
                    knyar/nginx-lua-prometheus) \
                        cp -v *.lua /usr/local/share/lua/5.1/ ;; \
                    *) echo "Unknown component: ${repo}"; exit 1 ;; \
                esac \
            fi; \
            cd ..; \
            rm -rf "${dir_name}"; \
        done

    ls -l ${LUA_LIB_DIR}/resty
    ls -l ${PREFIX}/lib/lua/${VER_LUA}

    echo "$VER_LUA" | tee /usr/local/lua_version
    echo "$ULTIMATE_BAD_BOT_BLOCKER" | tee /usr/local/ultimate_bot
)

(
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libmaxminddb0 binutils libcurl4-openssl-dev libpcre3 libssl3 zlib1g libxml2 libxslt1.1 \
        libgeoip1 libyajl2 libpcre2-8-0 "liblua$(cat /usr/local/lua_version)-dev" libfuzzy2 ssdeep

    groupadd --system --gid 101 nginx
    useradd --system --gid nginx --no-create-home --shell /bin/false --uid 101 nginx

    mkdir -p /var/log/nginx /var/cache/nginx /etc/nginx/sites-enabled
    ln -sf /dev/stdout /var/log/nginx/error.log
    ln -sf /dev/stdout /var/log/nginx/access.log
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx

    cp nginx.conf /etc/nginx/nginx.conf
    cp defaultv2.conf /etc/nginx/sites-available/default.conf
    cp modsecurity.conf-recommended /usr/local/modsecurity/
    cp unicode.mapping /usr/local/modsecurity/

    ln -s /etc/nginx/sites-available/default.conf /etc/nginx/sites-enabled/
    cp -r /etc/nginx/coreruleset/crs-setup.conf.example /etc/nginx/coreruleset/crs-setup.conf
    cp /usr/local/modsecurity/unicode.mapping /etc/nginx/
    cp /usr/local/modsecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.conf
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity.conf
    echo "Include /etc/nginx/coreruleset/crs-setup.conf\nInclude /etc/nginx/coreruleset/rules/*.conf" >> /etc/nginx/modsecurity.conf

    if [ "$(cat /usr/local/ultimate_bot)" = "true" ]; then
        apt-get install -y --no-install-recommends sudo
        curl -sL https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/install-ngxblocker -o /usr/local/sbin/install-ngxblocker
        chmod +x /usr/local/sbin/install-ngxblocker
        /usr/local/sbin/install-ngxblocker -x
        mkdir -p /var/www
        /usr/local/sbin/setup-ngxblocker -x -v /etc/nginx/sites-enabled/default.conf -e conf
        apt-get purge -y sudo
    fi

    find /usr/local -type f -name '*.a' -delete
    strip /usr/sbin/nginx
    rm -rf /usr/local/include
)

echo "Installation complete"
echo "Run: nginx -g 'daemon off;'"