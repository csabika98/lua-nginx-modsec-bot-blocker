#!/bin/bash
set -euxo pipefail

export VER_NGINX=1.27.4
export VER_NGX_DEVEL_KIT=0.3.4
export VER_NJS=0.8.9
export VER_GEOIP=3.4
export VER_LUAJIT=2.1-20250117
export VER_LUA_NGINX_MODULE=0.10.28
export VER_LUA_RESTY_CORE=0.1.31
export VER_LUAROCKS=3.11.1
export VER_OPENRESTY_HEADERS=0.38
export VER_CLOUDFLARE_COOKIE=f418d77082eaef48331302e84330488fdc810ef4
export VER_OPENRESTY_DNS=0.23
export VER_LUA_RESTY_LRUCACHE=0.15
export VER_OPENRESTY_MEMCACHED=0.17
export VER_OPENRESTY_MYSQL=0.27
export VER_OPENRESTY_REDIS=0.32
export VER_OPENRESTY_SHELL=0.03
export VER_OPENRESTY_SIGNAL=0.04
export VER_OPENRESTY_HEALTHCHECK=0.08
export VER_OPENRESTY_WEBSOCKET=0.13
export VER_OPENRESTY_TABLEPOOL=0.03
export VER_LUA_UPSTREAM=0.07
export VER_PROMETHEUS=0.20240525
export VER_MISC_NGINX=0.33
export VER_OPENRESTY_STREAMLUA=35071d983042b6820427d2312c143a13a137b2ea

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64v8" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    sudo \
    g++ \
    libmaxminddb-dev \
    libpcre3-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    make \
    patch \
    unzip \
    zlib1g-dev \
    git \
    gnupg2 \
    gettext-base \
    gcc \
    build-essential \
    autoconf \
    automake \
    libtool \
    libcurl4-openssl-dev \
    libfuzzy-dev \
    ssdeep \
    gettext \
    pkg-config \
    libgeoip-dev \
    libyajl-dev \
    doxygen \
    libpcre3-dev \
    iproute2 \
    libpcre2-16-0 \
    libpcre2-dev \
    liblua5.1-0-dev \
    libpcre2-posix3 \
    zlib1g-dev \
    wget



BUILD_DIR=$(mktemp -d)
cd "$BUILD_DIR"



# Nginx and its modules
# https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker
# https://github.com/owasp-modsecurity/ModSecurity
# https://github.com/owasp-modsecurity/ModSecurity-nginx
# https://github.com/coreruleset/coreruleset

curl -fsSL https://nginx.org/download/nginx-${VER_NGINX}.tar.gz | tar -xz
curl -fsSL https://github.com/openresty/luajit2/archive/v${VER_LUAJIT}.tar.gz | tar -xz
curl -fsSL https://github.com/vision5/ngx_devel_kit/archive/v${VER_NGX_DEVEL_KIT}.tar.gz | tar -xz
curl -fsSL https://github.com/openresty/lua-nginx-module/archive/v${VER_LUA_NGINX_MODULE}.tar.gz | tar -xz
curl -fsSL https://github.com/openresty/headers-more-nginx-module/archive/v${VER_OPENRESTY_HEADERS}.tar.gz | tar -xz
curl -fsSL https://github.com/openresty/lua-upstream-nginx-module/archive/v${VER_LUA_UPSTREAM}.tar.gz | tar -xz
curl -fsSL https://github.com/leev/ngx_http_geoip2_module/archive/${VER_GEOIP}.tar.gz | tar -xz
curl -fsSL https://github.com/nginx/njs/archive/${VER_NJS}.tar.gz | tar -xz
curl -fsSL https://github.com/openresty/set-misc-nginx-module/archive/v${VER_MISC_NGINX}.tar.gz | tar -xz
curl -fsSL https://github.com/openresty/stream-lua-nginx-module/archive/${VER_OPENRESTY_STREAMLUA}.tar.gz | tar -xz

git clone https://github.com/owasp-modsecurity/ModSecurity-nginx
#git clone https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker

# Build LuaJIT 
cd luajit2-${VER_LUAJIT}
make -j$(nproc)
sudo make install
sudo ln -sf /usr/local/bin/luajit /usr/local/bin/lua
cd ..

# Install Modsecurity
git clone https://github.com/owasp-modsecurity/ModSecurity.git
cd ModSecurity
git submodule init
git submodule update --init
./build.sh
./configure \
    --with-lua=/usr/local \
    --with-lua-include=/usr/local/include/luajit-2.1 \
    --with-lua-lib=/usr/local/lib
make -j$(nproc)
sudo make install

cd ..


cd nginx-${VER_NGINX}

export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
export LD_LIBRARY_PATH=${LUAJIT_LIB}:${LD_LIBRARY_PATH:-}

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
    --add-module=../ModSecurity-nginx

make -j$(nproc)
sudo make install

curl -fsSL https://luarocks.org/releases/luarocks-${VER_LUAROCKS}.tar.gz | tar -xz
cd luarocks-${VER_LUAROCKS}
./configure --with-lua=/usr/local
make -j$(nproc)
sudo make install

install_lua_component() {
    repo=$1
    version=$2
    src_path=$3
    target_dir=/usr/local/share/lua/5.1/
    
    git clone --depth 1 --branch "$version" "https://github.com/$repo"
    cd "${repo#*/}"
    sudo mkdir -p "$target_dir"
    sudo cp -R $src_path "$target_dir"
    cd ..
    sudo rm -rf "${repo#*/}"
}

install_lua_component "openresty/lua-resty-core" "v$VER_LUA_RESTY_CORE" "lib/resty"
install_lua_component "openresty/lua-resty-lrucache" "v$VER_LUA_RESTY_LRUCACHE" "lib/resty"
install_lua_component "openresty/lua-resty-dns" "v$VER_OPENRESTY_DNS" "lib/resty"
install_lua_component "openresty/lua-resty-redis" "v$VER_OPENRESTY_REDIS" "lib/resty"
install_lua_component "openresty/lua-resty-memcached" "v$VER_OPENRESTY_MEMCACHED" "lib/resty"
install_lua_component "openresty/lua-resty-mysql" "v$VER_OPENRESTY_MYSQL" "lib/resty"
install_lua_component "openresty/lua-resty-shell" "v$VER_OPENRESTY_SHELL" "lib/resty"
install_lua_component "openresty/lua-resty-signal" "v$VER_OPENRESTY_SIGNAL" "lib/resty"
install_lua_component "openresty/lua-resty-websocket" "v$VER_OPENRESTY_WEBSOCKET" "lib/resty"
install_lua_component "openresty/lua-tablepool" "v$VER_OPENRESTY_TABLEPOOL" "lib/"

# sudo groupadd --system --gid 101 nginx
# sudo useradd --system --gid nginx --no-create-home \
#     --home /nonexistent --shell /bin/false --uid 101 nginx

# Create nginx group if not exists
if ! getent group nginx >/dev/null; then
    sudo groupadd --system --gid 101 nginx || 
        sudo groupadd --system nginx
fi

if ! getent passwd nginx >/dev/null; then
    sudo useradd --system \
        --gid nginx \
        --no-create-home \
        --home /nonexistent \
        --shell /bin/false \
        --uid 101 nginx || 
            sudo useradd --system \
                --gid nginx \
                --no-create-home \
                --home /nonexistent \
                --shell /bin/false nginx 
fi


sudo mkdir -p /var/cache/nginx /var/log/nginx
sudo chown -R nginx:nginx /var/cache/nginx /var/log/nginx

sudo apt-get install -y --no-install-recommends \
    libmaxminddb-dev \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev


NGINX_DIR="/etc/nginx"
CRS_DIR="$NGINX_DIR/coreruleset"
CONFIG_FILE="$NGINX_DIR/nginx.conf"
MODSEC_CONF="$NGINX_DIR/modsecurity.conf"

if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root!" 
   exit 1
fi

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

# Creating Virtual host
sudo mkdir -p /etc/nginx/sites-{available,enabled}
# Add to your existing nginx.conf modification section
sed -i '/http {/a \    include sites-enabled/*.conf;' /etc/nginx/nginx.conf

DEFAULT_VHOST="/etc/nginx/sites-available/default.conf"

sudo tee "$DEFAULT_VHOST" <<'EOF'
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

sudo ln -sf "$DEFAULT_VHOST" /etc/nginx/sites-enabled/default.conf

# echo "Updating Nginx configuration..."
# if ! grep -q "modsecurity on" "$CONFIG_FILE" || ! grep -q "location /admin" "$CONFIG_FILE"; then
#     awk '
#     BEGIN {
#         modsec_added = 0
#         lua_added = 0
#     }
#     /^[[:space:]]*server[[:space:]]*{/ {
#         server_block = 1
#         print
#         next
#     }
#     server_block && /listen[[:space:]]*80/ && !modsec_added {
#         # Add ModSecurity directives
#         print $0
#         print "        modsecurity on;"
#         print "        modsecurity_rules_file /etc/nginx/modsecurity.conf;"
#         modsec_added = 1
#         next
#     }
#     server_block && modsec_added && !lua_added {
#         # Add Lua test locations after ModSecurity
#         print "        # Lua test endpoints"
#         print "        location /admin {"
#         print "            content_by_lua_block {"
#         print "                local auth = ngx.var.http_authorization"
#         print "                if not auth or auth ~= \"Basic \" .. ngx.encode_base64(\"admin:password\") then"
#         print "                    ngx.header[\"WWW-Authenticate\"] = \"Basic realm=\\\"Restricted\\\"\""
#         print "                    ngx.exit(ngx.HTTP_UNAUTHORIZED)"
#         print "                end"
#         print "                ngx.say(\"Access granted!\")"
#         print "            }"
#         print "        }"
#         print ""
#         print "        location /api {"
#         print "            default_type application/json;"
#         print "            content_by_lua_block {"
#         print "                local cjson = require(\"cjson\")"
#         print "                local data = { message = \"Hello, Lua!\", timestamp = os.time() }"
#         print "                ngx.say(cjson.encode(data))"
#         print "            }"
#         print "        }"
#         print ""
#         print "        location /lua_security_test {"
#         print "            content_by_lua_block {"
#         print "                local bad_patterns = { \"script\", \"SELECT\", \"UNION\" }"
#         print "                local query = ngx.var.query_string or \"\""
#         print "                for _, pattern in ipairs(bad_patterns) do"
#         print "                    if string.find(query, pattern, 1, true) then"
#         print "                        ngx.exit(ngx.HTTP_FORBIDDEN)"
#         print "                    end"
#         print "                end"
#         print "                ngx.say(\"Query is safe!\")"
#         print "            }"
#         print "        }"
#         print ""
#         print "        location /lua_log_test {"
#         print "            content_by_lua_block {"
#         print "                local file = io.open(\"/var/log/nginx/lua_requests.log\", \"a\")"
#         print "                if file then"
#         print "                    file:write(os.date() .. \" - \" .. ngx.var.remote_addr .. \" accessed \" .. ngx.var.request_uri .. \"\\n\")"
#         print "                    file:close()"
#         print "                end"
#         print "                ngx.say(\"Logged your request!\")"
#         print "            }"
#         print "        }"
#         lua_added = 1
#     }
#     /}/ && server_block {
#         server_block = 0
#     }
#     { print }
#     ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
#     echo "Added ModSecurity and Lua test directives to port 80 server block"
# else
#     echo "ModSecurity and Lua configurations already present"
# fi


# echo "Updating Nginx configuration..."
# if ! grep -q "modsecurity on" "$CONFIG_FILE"; then
#     awk '
#     /^[[:space:]]*server[[:space:]]*{/ {
#         server_block=1
#         print
#         next
#     }
#     server_block && /listen[[:space:]]*80/ && !modsec_added {
#         print $0
#         print "        modsecurity on;"
#         print "        modsecurity_rules_file /etc/nginx/modsecurity.conf;"
#         modsec_added=1
#         next
#     }
#     /}/ && server_block {
#         server_block=0
#     }
#     { print }
#     ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
#     echo "Added ModSecurity directives to port 80 server block"
# else
#     echo "ModSecurity directives already present in configuration"
# fi

echo "Checking port 80 availability..."
if ss -tulnp | grep -q ":80 "; then
    echo "ERROR: Port 80 is already in use."
    exit 1
fi

echo "Testing Nginx configuration..."
nginx
nginx -t

echo "Reloading Nginx..."
nginx -s reload

echo "SUCCESS: ModSecurity configuration complete!"


# Test endpoints
curl -v http://localhost/admin
curl -v http://localhost/api
curl -v "http://localhost/lua_security_test?input=<script>"
curl -v "http://localhost/say_hello_lua"

#sudo apt-get autoremove -y
#sudo rm -rf /var/lib/apt/lists/* "$BUILD_DIR"

## install nginx-ultimate-bad-bot-blocker


# Install Bad Bot Blocker
echo "Installing nginx-ultimate-bad-bot-blocker..."
curl -sL https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/install-ngxblocker -o /tmp/install-ngxblocker
sudo mv /tmp/install-ngxblocker /usr/local/sbin/
sudo chmod +x /usr/local/sbin/install-ngxblocker

sudo /usr/local/sbin/install-ngxblocker -x
sudo chmod +x /usr/local/sbin/setup-ngxblocker
sudo chmod +x /usr/local/sbin/update-ngxblocker

# Configure bot blocker
#sudo /usr/local/sbin/setup-ngxblocker -x -e conf
sudo /usr/local/sbin/setup-ngxblocker -x -n default.conf -e conf


