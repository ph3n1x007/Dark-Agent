# Dark Agent

**This repository is a fork of the original [ServiceNow/Dark-Agent](https://github.com/ServiceNow/Dark-Agent), with Kerberos proxy authentication added for Linux.** It adds automatic Negotiate/SPNEGO auth for HTTP proxies using the current user's Kerberos credential cache.

The proxy changes support HTTP and HTTPX, proxies without auth, Basic auth, environment proxy settings, `NO_PROXY` exclusions, and HTTPS CONNECT. See the [proxy setup guide](documentation-payload/dark-agent/c2_profiles/HTTP.md#outbound-proxy) and [proxy test notes](Payload_Type/dark_agent/dark_agent/agent_code/spec/README.md).

![Dark Agent Logo](Payload_Type/dark_agent/dark_agent/mythic/dark.svg)

A production-ready Linux/macOS agent written in Crystal for Mythic framework. Features static OpenSSL linking, comprehensive dynamic module support, and extensive built-in Unix commands.

## Overview

Dark Agent is a fully-featured Mythic Agent for Linux and macOS environments. Built in Crystal with statically-linked OpenSSL, it provides comprehensive remote operations capabilities through dynamic module loading, extensive system commands, SOCKS proxy support, and flexible communication profiles.

## Platform Support

| Build | OS | Min glibc | Coverage |
|-------|----|-----------|---------|
| Dynamic | Linux x86_64 | 2.27 | RHEL 8+, Ubuntu 18.04+, Debian 10+ |
| Dynamic | macOS arm64 | N/A | macOS 12+ (Apple Silicon) |

Linux builds have OpenSSL statically linked with no `libssl` dependency on the target. macOS binaries are cross-compiled on Linux via Zig and ad-hoc signed with `rcodesign` (SHA-256 CodeDirectory hashes required by macOS 14+).

## Mythic Configuration

### Agent Configuration

- **Agent Name**: dark
- **Supported OS**: Linux, macOS  
- **File Extension**: bin
- **Communication Profiles**: HTTP, HTTPX (malleable)

**Build Parameters**:
- `debug_mode`: Boolean (default: false) - Enable debug logging and verbose output
- `debug_socks`: Boolean (default: false) - Enable SOCKS proxy debug logging  
- `encryption`: Boolean (default: true) - Enable AES-256-CBC encryption for traffic
- `ssl_verify`: Boolean (default: true) - Verify the server TLS certificate. Turn off only for self-signed lab certificates
- `proxy_auth_scheme`: String (default: empty) - Outbound proxy auth. Empty picks from the proxy's 407 challenge; `basic` or `negotiate` forces one
- `proxy_spn_override`: String (default: empty) - Kerberos service name for the proxy, such as `HTTP@proxy.lab.test`. Empty derives `HTTP@<proxy host>`
- `symmetric_jitter`: Boolean (default: false) - Use symmetric jitter (sleep_time ± jitter%) for better operational security
- `realtime`: Boolean (default: false) - Immediately send command responses without waiting for sleep interval
- `chunk_size`: Number (default: 512) - Size of file transfer chunks in KB, affects upload/download performance

**Available Commands**: Extensive built-in commands including system utilities, file operations, network tools, and agent management

**Security Checks**: Dark Agent includes built-in security checks for high-risk commands:
- `shell` - All shell commands require approval from another operator
- `sleep` - Sleep intervals < 10 seconds require operator approval (special warning for sleep 0)
- `kill` - All process termination requires operator approval

### Communication Profile Types

#### HTTP Profile
The standard HTTP profile is a simpler implementation that uses regular HTTP requests. It's easier to configure but offers less customization options.

#### HTTPX Profile (Malleable)
The HTTPX profile is a more advanced implementation that supports malleable communication profiles with extensive customization options:

- **Multiple Domains Support**: Configure multiple callback domains with rotation strategies
- **Domain Rotation Strategies**:
  - `round-robin`: Rotates through domains for each request
  - `fail-over`: Switches to next domain after consecutive failures
- **Traffic Transforms**: Apply custom transformations to traffic:
  - Base64/Base64URL encoding
  - XOR encryption
  - Prepend/append custom data
- **Message Placement Options**: Place messages in:
  - HTTP headers
  - URL parameters
  - Cookies
  - Request body
- **Custom Headers**: Define custom HTTP headers for requests

### Installation

From your Mythic directory, install this fork:

```sh
sudo ./mythic-cli install github https://github.com/ph3n1x007/Dark-Agent
```

To install a local copy, copy the whole repository to the Mythic host and run `sudo ./mythic-cli install folder /path/to/Dark-Agent`. Add `-f` to either command when replacing an installed version.

## Supported Commands

Dark Agent implements commands across two categories: **Built-in Commands** (native Crystal implementations) and **Object File Commands** (C object files loaded at runtime).

| Command | Description | Type | Linux | macOS | Browser Scripts | MITRE ATT&CK |
|---------|-------------|------|-------|-------|----------------|--------------|
| bof_exec | Execute a previously loaded module with arguments | Built-in | Yes | Yes | | T1059 |
| bof_list | List all currently loaded modules | Built-in | Yes | Yes | | |
| bof_load | Load a module into memory without registering as command | Built-in | Yes | Yes | | T1129 |
| bof_purge | Remove all modules from memory* | Built-in | Yes | Yes | | |
| bof_unload | Unload a specific module from memory | Built-in | Yes | Yes | | |
| download | Download file from target system (supports chunked transfers) | Built-in | Yes | Yes | | T1020, T1030, T1041 |
| exit | Terminate the agent | Built-in | Yes | Yes | | |
| jobkill | Kill a running module job by task ID | Built-in | Yes | Yes | | |
| jobs | List active module jobs with runtime information | Built-in | Yes | Yes | | |
| load | Load a module and register it as a Mythic command | Built-in | Yes | Yes | | T1129 |
| ls | List files in a directory with detailed metadata | Built-in | Yes | Yes | Yes | T1083 |
| sleep | Change agent sleep/jitter intervals | Built-in | Yes | Yes | | |
| socks | Start or stop a SOCKS5 proxy server on specified port | Built-in | Yes | Yes | | T1090 |
| unload | Unload a command from memory | Built-in | Yes | Yes | | |
| upload | Upload file to target system | Built-in | Yes | Yes | | T1105 |
| arp | Display ARP table information | Module | Yes | Yes | Yes | T1016 |
| cat | Display file contents | Module | Yes | Yes | | T1005 |
| chmod | Change file permissions | Module | Yes | Yes | | T1222.002 |
| chown | Change file ownership | Module | Yes | Yes | | T1222.002 |
| coffee | Test module execution (example "coffee brewing" command) | Module | Yes | Yes | | |
| df | Display filesystem disk space usage with mount analysis | Module | Yes | Yes | Yes | T1082 |
| env | Display environment variables | Module | Yes | Yes | | T1082 |
| hostname | Display system hostname | Module | Yes | Yes | | T1082 |
| ifconfig | Display network interface configuration | Module | Yes | Yes | Yes | T1016 |
| kill | Terminate processes by PID | Module | Yes | Yes | | T1562.001 |
| krb_dump_kirbi | Dump credentials from a Kerberos credential cache | Module | | Yes | | T1558.005 |
| krb_listccaches | Enumerate all Kerberos credential caches | Module | | Yes | | T1558.005 |
| last | Show last logged in users from wtmp log | Module | Yes | | Yes | T1033 |
| mkdir | Create directory and any necessary parent directories | Module | Yes | Yes | | T1059 |
| mounts | List all mounted filesystems with security analysis | Module | Yes | Yes | Yes | T1082 |
| mv | Move or rename files and directories | Module | Yes | Yes | | T1070.006 |
| netstat | Display network connections and routing tables | Module | Yes | | Yes | T1049 |
| nslookup | Perform DNS lookups with optional custom nameserver | Module | Yes | Yes | Yes | T1018 |
| portscan | Scan for open ports on target hosts | Module | Yes | Yes | | T1046 |
| ps | List running processes with detailed information | Module | Yes | Yes | Yes | T1057 |
| rm | Remove files and directories | Module | Yes | Yes | | T1070.004 |
| routes | Display system routing table | Module | Yes | Yes | Yes | T1016 |
| shell | Execute shell commands on the target system | Module | Yes | Yes | | T1059.004 |
| timestomp | Modify file timestamps for anti-forensics | Module | Yes | Yes | | T1070.006 |
| uptime | Show system uptime and load averages | Module | Yes | Yes | | T1082 |
| whoami | Display current user information | Module | Yes | Yes | | T1033 |

Each command (like `hostname` and `ifconfig`) is implemented using an object file module. When you use the command:

1. The command uses `bof_execute` to run the associated module
2. If the module hasn't been loaded yet, you must first use `load [command]` to load it
3. For example: `load hostname` followed by `hostname`

## Creating Custom Modules

Writing a module is straightforward. Include `beacon.h` and implement `coffee()`. The framework handles loading, execution, and sending output back to the operator.

### Minimal Example

```c
#include "../includes/beacon.h"
#include <sys/stat.h>
#include <errno.h>

void coffee(int argc, char **argv) {
    if (argc < 1) { BeaconPrintf("Usage: example <path>"); return; }

    const char *path = argv[0];
    struct stat st;

    // Simple status message
    BeaconPrintf("checking path: %s", path);

    if (stat(path, &st) != 0) {
        BeaconPrintf("error: %s", strerror(errno));
        return;
    }

    // JSON output for browser script rendering
    bof_result_t *r = bof_result_create(512);
    bof_result_append(r, "{");
    bof_field_str(r, "path",  path);
    bof_field_ull(r, "size",  (unsigned long long)st.st_size);
    bof_field_uint(r, "mode", (unsigned int)st.st_mode);
    bof_result_trim(r);
    bof_result_append(r, "}");
    bof_result_send(r);
    bof_result_destroy(r);
}
```

Compile it, drop the `.o` into the payload, load it in Mythic. Done.

### Output API

| Function | Output |
|---|---|
| `BeaconOutput(buf, len)` | send raw bytes to the operator |
| `BeaconPrintf("found %d user=%s", n, u)` | status/debug message that supports `%d %s %p %x` |
| `bof_result_append(r, "text")` | `text` |
| `bof_field_str(r, "name", "ls")` | `"name":"ls",` |
| `bof_field_int(r, "pid", 1234)` | `"pid":1234,` |
| `bof_field_uint(r, "uid", 501)` | `"uid":501,` |
| `bof_field_ull(r, "size", 102400)` | `"size":102400,` |
| `bof_field_hex(r, "flags", 0x405)` | `"flags":"0x405",` |
| `bof_result_append_mac(r, mac)` | `aa:bb:cc:dd:ee:ff` |
| `bof_result_trim(r)` | strips trailing comma |
| `bof_result_send(r)` | sends via BeaconOutput |
| `bof_result_destroy(r)` | free |

`BeaconOutput` and `BeaconPrintf` are the most common ways to write data from a module. The `bof_result_t` JSON builder is primarily useful when pairing with a Mythic browser script for structured UI rendering.

```c
bof_result_t *r = bof_result_create(4096);
bof_result_append(r, "{\"entries\":[{");
bof_field_str(r,  "name",  proc_name);
bof_field_int(r,  "pid",   pid);
bof_field_ull(r,  "size",  file_size);
bof_field_hex(r,  "flags", flags);
bof_result_trim(r);
bof_result_append(r, "}]}");
bof_result_send(r);
bof_result_destroy(r);
// → {"entries":[{"name":"ls","pid":1234,"size":102400,"flags":"0x405"}]}
```

### Arguments

Modules receive `(int argc, char **argv)`. Mythic passes arguments two ways:

#### Split Arguments (`bof_args`)
Space-separated → individual `argv` entries:
- `"192.168.1.1 22,80,443"` → `argv[0]="192.168.1.1"`, `argv[1]="22,80,443"`
- Best for modules with structured parameters (paths, modes, hosts)
- Example: `portscan 192.168.1.1 22,80,443`

#### Single String (`bof_args_str`)
Full string → `argv[0]`:
- `"ls -latr /tmp"` → `argv[0]="ls -latr /tmp"`
- Best for modules that pass a command through as-is
- Example: `shell ls -latr /tmp`

### Building

```bash
# Linux
gcc -fPIC -c your_bof.c -o your_bof.o -I src/bofs/includes

# Build all modules (runs inside the Mythic build container)
./build.sh -b    # Linux
./build.sh -B    # macOS (aarch64, requires Zig + macOS SDK)
```

## Usage

### Running the Agent

```bash
# Run the debug version
./output/dark-agent-debug

# Run the release version
./output/dark-agent
```

### Direct Mode

Dark Agent can be built in "direct mode", which creates a standalone object file loader without any Mythic server functionality. This is useful for testing modules without needing a full Mythic server.

In direct mode, the agent:
1. Loads the specified object file
2. Executes the `coffee()` function from the module
3. Passes any additional command-line arguments to the module
4. Displays any output produced by the module

This mode is ideal for module development and testing before deploying to a full Mythic environment.

Example usage:
```bash
# Build direct mode version
./build.sh -D

# Run a test module
./output/dark-agent-direct output/bofs/coffee.o
```
