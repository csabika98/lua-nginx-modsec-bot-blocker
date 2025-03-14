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
    libpcre2-16-0 \
    libpcre2-dev \
    liblua5.1-0-dev \
    libpcre2-posix3 \
    zlib1g-dev



#BUILD_DIR=$(mktemp -d)
#cd "$BUILD_DIR"
cd "/home/csabasallai/build"

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

# Build LuaJIT ,target_dir=/usr/local/share/lua/5.1/
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

sudo groupadd --system --gid 101 nginx
sudo useradd --system --gid nginx --no-create-home \
    --home /nonexistent --shell /bin/false --uid 101 nginx
sudo mkdir -p /var/cache/nginx /var/log/nginx
sudo chown -R nginx:nginx /var/cache/nginx /var/log/nginx

sudo apt-get install -y --no-install-recommends \
    libmaxminddb-dev \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev

#sudo apt-get autoremove -y
#sudo rm -rf /var/lib/apt/lists/* "$BUILD_DIR"

# Fixing unicode mapping issue
cp $BUILD_DIR/ModSecurity/unicode.mapping /etc/nginx/



NGINX_DIR="/etc/nginx"
CRS_DIR="$NGINX_DIR/coreruleset"
MODSEC_CONF="$NGINX_DIR/modsecurity.conf"


cd $BUILD_DIR/ModSecurity
cp -r modsecurity.conf-recommended /etc/nginx/modsecurity.conf

NGINX_DIR="/etc/nginx"
CRS_DIR="$NGINX_DIR/coreruleset"
MODSEC_CONF="$NGINX_DIR/modsecurity.conf"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root!" 
   exit 1
fi

cd "$NGINX_DIR" || { echo "Failed to enter $NGINX_DIR"; exit 1; }

if [[ ! -d "$CRS_DIR" ]]; then
    echo "Cloning OWASP Core Rule Set..."
    git clone https://github.com/coreruleset/coreruleset.git "$CRS_DIR"
else
    echo "Core Rule Set already exists, updating..."
    cd "$CRS_DIR" && git pull origin main
fi

if [[ ! -f "$MODSEC_CONF" ]]; then
    echo "ModSecurity configuration file not found at $MODSEC_CONF"
    exit 1
fi

if grep -q "SecRuleEngine DetectionOnly" "$MODSEC_CONF"; then
    echo "Updating SecRuleEngine to On..."
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$MODSEC_CONF"
else
    echo "SecRuleEngine already set to On or not found."
fi

if ! grep -q "Include coreruleset/crs-setup.conf" "$MODSEC_CONF"; then
    echo "Adding CRS Includes to the top of modsecurity.conf..."
    TMP_FILE=$(mktemp)
    {
        echo "# Include OWASP CRS Rules"
        echo "Include coreruleset/crs-setup.conf"
        echo "Include coreruleset/rules/*.conf"
        echo ""
        cat "$MODSEC_CONF"
    } > "$TMP_FILE"
    mv "$TMP_FILE" "$MODSEC_CONF"
else
    echo "CRS Includes already present at the top of modsecurity.conf."
fi


## install nginx-ultimate-bad-bot-blocker

# curl -sL https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/install-ngxblocker -o /usr/local/sbin/install-ngxblocker
# cd /usr/local/sbin
# sudo ./install-ngxblocker
# sudo ./install-ngxblocker -x
# sudo chmod +x /usr/local/sbin/setup-ngxblocker
# sudo chmod +x /usr/local/sbin/update-ngxblocker
# cd /usr/local/sbin/
# sudo ./setup-ngxblocker -x -e conf

# # Bad Bot Blocker
#include /etc/nginx/bots.d/ddos.conf;
#include /etc/nginx/bots.d/blockbots.conf;
#load_module /etc/nginx/modules-enabled/ngx_http_modsecurity_module.so;
sudo nginx
sudo nginx -t && sudo nginx -s reload

echo "Installation completed successfully!"