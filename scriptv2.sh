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
    export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
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
        --add-module=../ngx_devel_kit \
        --add-module=../lua-nginx-module \
        # Add remaining configure options...

    make -j$(nproc)
    make install
    cd ..

    # Build LuaRocks
    cd "luarocks-${VER_LUAROCKS}"
    ./configure --with-lua=/usr/local
    make -j$(nproc)
    make install
    cd ..

    # Install Lua components
    lua_components=" \
        openresty/lua-resty-core:lib/resty/ \
        # Add other components...
    "

    for component in ${lua_components}; do
        repo=$(echo "${component}" | cut -d: -f1)
        path=$(echo "${component}" | cut -d: -f2)
        git clone --depth 1 "https://github.com/${repo}"
        cp -R "${repo#*/}/${path}" "/usr/local/share/lua/${VER_LUA}"
        rm -rf "${repo#*/}"
    done

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