# Enhanced Nginx Build with Lua Support, ModSecurity WAF, and Security Modules


## Screenshots

![4](screenshots/4.png)

* Possibility to build for custom nginx version

* Optional modules you can install (it will be updated in the future): 
     * nginx-ultimate-bad-bot-blocker 

## Test cases - Lua Endpoint Tests


### Basic Authentication Test

Code:
```lua
location /admin {
    content_by_lua_block {
        -- Get Authorization header
        local auth = ngx.var.http_authorization
        
        -- Verify credentials format and match
        local expected_auth = "Basic " .. ngx.encode_base64("admin:password")
        
        if not auth or auth ~= expected_auth then
            -- Send authentication challenge
            ngx.header["WWW-Authenticate"] = 'Basic realm="Restricted Area"'
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
        
        -- Grant access
        ngx.say("Access granted!")
    }
}
```


#### 1. Without credentials (should fail)
```curl -v http://localhost/admin```


![2](screenshots/2.png)

<b>Expected: 401</b>

#### 2. With valid credentials (admin:password)
```curl -v -H "Authorization: Basic $(echo -n 'admin:password' | base64)" http://localhost/admin```

![3](screenshots/3.png)

<b>Expected: 200 OK with "Access granted!"</b>


---

### Security Filter Test 


Code:
```lua
location /lua_security_test {
    content_by_lua_block {
        -- Define malicious patterns to block
        local bad_patterns = {
            "script",   -- Blocks HTML script tags
            "SELECT",   -- Blocks SQL SELECT statements
            "UNION"     -- Blocks SQL UNION operators
        }

        -- Get query parameters
        local query = ngx.var.query_string or ""
        
        -- Check each pattern in the query
        for _, pattern in ipairs(bad_patterns) do
            -- plain=true: disable pattern matching
            -- start=1: search from first character
            if string.find(query, pattern, 1, true) then
                ngx.exit(ngx.HTTP_FORBIDDEN)
            end
        end

        -- If no bad patterns found
        ngx.say("Query is safe!")
    }
}
```

```curl -v "http://localhost/lua_security_test?q=safe_query"```










## Introduction

A hardened Nginx build with integrated security features including Lua scripting, ModSecurity WAF, OWASP Core Rule Set, and advanced bot protection.

## Features

- **Nginx 1.27.4** with custom-compiled modules
- **LuaJIT 2.1** scripting support
- **ModSecurity 3.0** Web Application Firewall
- **OWASP Core Rule Set** protection
- **Nginx Ultimate Bad Bot Blocker**
- **GeoIP2** support
- **Lua RESTy** components:
  - lua-resty-core
  - lua-resty-lrucache
  - lua-resty-redis
  - lua-resty-mysql
  - And more...
- Stream and HTTP Lua modules
- Enhanced security headers
- Thread support and modern protocol support

## Prerequisites

- Ubuntu 24.04 (or compatible Debian-based system)
- Root/sudo access
- 2GB+ RAM (4GB recommended for compilation)
- 5GB+ disk space

## Recommended SSL Configuration

```bash
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
ssl_ecdh_curve secp384r1;
ssl_session_timeout 10m;
ssl_session_cache shared:SSL:10m;
```

## Recommended Lua Extensions

```bash
sudo luarocks install lua-resty-jwt
sudo luarocks install lua-resty-http
```

## Test 

```bash
location /lua-test {
    content_by_lua_block {
        ngx.say("Hello from Lua!")
        ngx.log(ngx.ERR, "Custom Lua logging")
    }
}
```

## Activate Bot Blocker

```bash
include /etc/nginx/bot-blocker/blockbots.conf;
include /etc/nginx/bot-blocker/ddos.conf;
```

## Install 

* Clone the repo
* Make sh executable
* Run it with sudo

