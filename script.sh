#!/bin/bash

#set -euxo pipefail


echo "----------------------------------------"
echo "1. Latest version of Nginx (current: 1.27.4)"
echo "2. Custom version"
read -p "Choose Nginx version [1-2]: " nginx_choice

case $nginx_choice in
    2)
        read -p "Enter custom Nginx version (e.g., 1.27.4): " custom_version
        export VER_NGINX=$custom_version
        echo "Using custom Nginx version: $VER_NGINX"
        ;;
    *)
        export VER_NGINX=1.27.4
        echo "Using latest Nginx version: $VER_NGINX"
        ;;
esac

VER_NGINX=${VER_NGINX:-1.27.4}
VER_LUA=${VER_LUA:-5.1}
VER_LUAROCKS=${VER_LUAROCKS:-3.11.1}

export DEBIAN_FRONTEND=noninteractive

cleanup() {
    local exit_code=$?
    echo "Cleaning up..."
    rm -rf /build
    if [ $exit_code -ne 0 ]; then
        rm -rf /etc/nginx/coreruleset
    fi
}
trap cleanup EXIT

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

    make -C luajit-2.1 -j$(nproc)
    make -C luajit-2.1 install PREFIX=/usr/local
    ln -sf /usr/local/bin/luajit /usr/local/bin/lua

    cd ModSecurity
    git submodule update --init
    ./build.sh
    ./configure --with-lua=/usr/local \
        --with-lua-include=/usr/local/include/luajit-2.1 \
        --with-lua-lib=/usr/local/lib
    make -j$(nproc)
    make install
    cd ..

    cd "nginx-${VER_NGINX}"
    curl -fsSL -o nginx-socket_cloexec.patch https://raw.githubusercontent.com/csabika98/lua-nginx-modsec-bot-blocker/refs/heads/main/nginx-socket_cloexec.patch
    patch -p1 < ./nginx-socket_cloexec.patch
    export LUAJIT_LIB=/usr/local/lib
    export LUAJIT_INC=/usr/local/include/luajit-2.1
    export LD_LIBRARY_PATH="/usr/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
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
                    LUA_LIB_DIR="/usr/local/share/lua/$VER_LUA" \
                    PREFIX="/usr/local"; \
            else \
                case "${repo}" in \
                    cloudflare/lua-resty-logger-socket) \
                        cp -R lib/resty/logger /usr/local/share/lua/$VER_LUA/resty/ ;; \
                    knyar/nginx-lua-prometheus) \
                        cp -v *.lua /usr/local/share/lua/$VER_LUA/ ;; \
                    *) echo "Unknown component: ${repo}"; exit 1 ;; \
                esac \
            fi; \
            cd ..; \
            rm -rf "${dir_name}"; \
        done

    ls -l ${LUA_LIB_DIR}/resty
    ls -l ${PREFIX}/lib/lua/${VER_LUA}

    echo "$VER_LUA" | tee /usr/local/lua_version
)

(
    BUILD_DIR=/build
    cd $BUILD_DIR

    apt-get update && \
    apt-get install -y --no-install-recommends \
        libmaxminddb0 binutils libcurl4-openssl-dev libpcre3 libssl3 zlib1g libxml2 libxslt1.1 \
        libgeoip1 libyajl2 libpcre2-8-0 "liblua$(cat /usr/local/lua_version)-dev" libfuzzy2 ssdeep

    if ! getent group nginx >/dev/null; then
        groupadd --system nginx || true
    fi
    useradd --system \
        --gid nginx \
        --no-create-home \
        --shell /bin/false \
        nginx || true

    mkdir -p /var/log/nginx /var/cache/nginx /etc/nginx/sites-enabled
    ln -sf /dev/stdout /var/log/nginx/error.log
    ln -sf /dev/stdout /var/log/nginx/access.log
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx

    tee /etc/nginx/nginx.conf <<'EOF'
    #user  nobody;
    worker_processes  1;

    events {
        worker_connections  1024;
    }

    http {
        include       mime.types;
        default_type  application/octet-stream;
        sendfile        on;
        keepalive_timeout  65;
    }
EOF

    mkdir -p /etc/nginx/sites-{available,enabled}
    mkdir -p /var/www/
    # Add to your existing nginx.conf modification section
    sed -i '/http {/a \    include sites-enabled/*.conf;' /etc/nginx/nginx.conf

    DEFAULT_VHOST="/etc/nginx/sites-available/default.conf"

     tee "$DEFAULT_VHOST" <<'EOF'
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;

        # Your existing ModSecurity and Lua configurations
        modsecurity on;
        modsecurity_rules_file /etc/nginx/modsecurity.conf;

        # Lua test endpoints
        location /admin {
            content_by_lua_block {
                local auth = ngx.var.http_authorization
                if not auth or auth ~= "Basic " .. ngx.encode_base64("admin:password") then
                    ngx.header["WWW-Authenticate"] = 'Basic realm="Restricted"'
                    ngx.exit(ngx.HTTP_UNAUTHORIZED)
                end
                ngx.say("Access granted!")
            }
        }

        location /api {
            default_type application/json;
            content_by_lua_block {
                local cjson = require("cjson")
                local data = { message = "Hello, Lua!", timestamp = os.time() }
                ngx.say(cjson.encode(data))
            }
        }

        location /lua_security_test {
            content_by_lua_block {
                local bad_patterns = { "script", "SELECT", "UNION" }
                local query = ngx.var.query_string or ""
                for _, pattern in ipairs(bad_patterns) do
                    if string.find(query, pattern, 1, true) then
                        ngx.exit(ngx.HTTP_FORBIDDEN)
                    end
                end
                ngx.say("Query is safe!")
            }
        }

        location /say_hello_lua {
            content_by_lua_block {
                    ngx.say("Hello from lua-nginx-module!")
                }
        }


        location /lua_log_test {
            content_by_lua_block {
                local file = io.open("/var/log/nginx/lua_requests.log", "a")
                if file then
                    file:write(os.date() .. " - " .. ngx.var.remote_addr .. " accessed " .. ngx.var.request_uri .. "\n")
                    file:close()
                end
                ngx.say("Logged your request!")
            }
        }

        # Add other locations and configurations here
    }
EOF

    ln -sf "$DEFAULT_VHOST" /etc/nginx/sites-enabled/default.conf    

    NGINX_DIR="/etc/nginx"
    CRS_DIR="$NGINX_DIR/coreruleset"
    CONFIG_FILE="$NGINX_DIR/nginx.conf"
    MODSEC_CONF="$NGINX_DIR/modsecurity.conf"


    echo "Setting up ModSecurity base configuration..."
    cp -f $BUILD_DIR/ModSecurity/unicode.mapping "$NGINX_DIR"
    cp -f $BUILD_DIR/ModSecurity/modsecurity.conf-recommended "$MODSEC_CONF"


    if [[ ! -d "$CRS_DIR" ]]; then
        echo "Cloning OWASP Core Rule Set..."
        git clone -q https://github.com/coreruleset/coreruleset.git "$CRS_DIR"
    else
        echo "Updating existing Core Rule Set..."
        (cd "$CRS_DIR" && git pull -q origin main)
    fi
    cp -f "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"

    echo "Configuring $MODSEC_CONF..."
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$MODSEC_CONF"

    if ! grep -q "Include coreruleset/crs-setup.conf" "$MODSEC_CONF"; then
        sed -i '1i# OWASP CRS Rules\nInclude coreruleset/crs-setup.conf\nInclude coreruleset/rules/*.conf\n' "$MODSEC_CONF"
    fi


    find /usr/local -type f -name '*.a' -delete
    strip /usr/sbin/nginx
    rm -rf /usr/local/include
)

echo "Installation complete"
echo "Run: nginx -g 'daemon off;'"