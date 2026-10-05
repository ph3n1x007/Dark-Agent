+++
title = "HTTP"
chapter = false
weight = 101
+++

## Summary
Standard HTTP/HTTPS profile for reliable communication with static OpenSSL support.

The HTTP profile provides a robust communication channel using standard HTTP protocols with AES-256-CBC encryption and HMAC authentication. All HTTPS connections use statically-linked OpenSSL for maximum compatibility across systems without external dependencies.

### Profile Options

#### Callback Host
The URL for the redirector or Mythic server. This must include the protocol to use (e.g. `http://` or `https://`).

#### Callback Interval in seconds
Time to sleep between agent callbacks (default: 10).

#### Callback Jitter in percent
Randomize the callback interval within the specified threshold. e.g., if Callback Interval is 10, and jitter is 10%, Dark Agent will call back randomly between 10 and 11 seconds (or between 9 and 11 seconds if symmetric jitter is enabled).

#### Callback Port
The port at which the web server lives (80, 443, etc.)

#### Outbound Proxy

Set `proxy_host` and `proxy_port` in the HTTP profile to route requests through an HTTP proxy. The host can be bare (`127.0.0.1:3128`) or an HTTP URL (`http://127.0.0.1:3128`). A separate `proxy_port` overrides the URL port. The default port is 80. Leave the auth fields empty for a local proxy without auth. Set `proxy_user` and `proxy_pass` for Basic auth.

If `proxy_host` is empty, HTTP callback URLs use `http_proxy` or `HTTP_PROXY`; HTTPS callback URLs use `https_proxy` or `HTTPS_PROXY`. Both fall back to `all_proxy` or `ALL_PROXY`. Lowercase takes priority. Values can be HTTP URLs or bare host names with a port. URL credentials are decoded once. An invalid or unsupported proxy value fails the request instead of sending it directly. Only HTTP upstream proxies are supported, including CONNECT tunnels for HTTPS callbacks.

Environment discovery reads the running process's environment. Exported terminal variables and system environment variables work when the agent inherits them at launch. It does not read another terminal's environment, desktop proxy settings, or PAC files. Environment proxy settings honor `no_proxy` or `NO_PROXY`, including `*`, domains and subdomains, IP addresses, optional ports, and IPv4/IPv6 CIDR ranges. An explicit profile proxy takes priority over environment settings and bypass rules.

For a local proxy on port 3128, launch from the same Linux terminal after setting:

```sh
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
```

Leave `proxy_host` empty to use these variables. A matching `no_proxy`/`NO_PROXY` entry sends that destination directly. Check both variables with `printf 'no_proxy=%s\nNO_PROXY=%s\n' "${no_proxy-}" "${NO_PROXY-}"` if a request unexpectedly bypasses the proxy.

With no configured user, a `407 Proxy-Authenticate: Negotiate` challenge automatically selects Kerberos on Linux. It requires `libgssapi_krb5.so.2` and valid credentials in the default cache or the cache selected by `KRB5CCNAME`. Check the library with `ldconfig -p | grep libgssapi_krb5.so.2`; a matching line means it is present. Check tickets with `klist -s; echo $?`; 0 means valid tickets, and a nonzero result means credentials need attention. The agent does not prompt for a password or obtain a TGT itself. A proxy without auth works without Kerberos credentials.

The payload build options `proxy_auth_scheme` (`basic` or `negotiate`) and `proxy_spn_override` can force the scheme or set a host-based service name such as `HTTP@proxy.lab.test`. Leave the scheme empty for automatic selection. Kerberos derives `HTTP@<proxy hostname>` by default, so use the proxy's DNS name when its service principal uses that name. HTTPS callbacks authenticate during CONNECT, then start TLS to the callback host. Framed 407 bodies are drained before retries on the same socket. Invalid or missing Kerberos server proof fails the request.

#### Crypto type
Do not modify from aes256_hmac

#### POST request URI
The path on the web server Dark Agent will talk to

#### HTTP Headers
A dictionary of key-value pairs Dark Agent will use in web requests.

#### Kill Date
The date at which the agent will stop calling back.

#### Performs Key Exchange
Perform encrypted key exchange with Mythic on check-in. Recommended to keep as T for true.

#### Disable SSL Verify
If set to true, SSL certificate validation will be disabled. Useful for testing with self-signed certificates or internal PKI environments.

## Security Features

**Encryption & Authentication:**
- **AES-256-CBC**: Strong symmetric encryption for all traffic
- **HMAC-SHA256**: Message authentication prevents tampering
- **Static OpenSSL**: Self-contained crypto libraries, no dependencies
- **Perfect Forward Secrecy**: Unique session keys for each communication

**SSL/TLS Support:**
- **TLS 1.2/1.3**: Modern TLS protocols supported
- **Certificate Validation**: Full certificate chain validation (configurable)
- **Self-Signed Support**: Can disable validation for testing environments
- **No External Dependencies**: Works without system OpenSSL libraries

#### Additional Configuration Options

Dark Agent HTTP profile supports these behavioral parameters:

#### Symmetric Jitter
When enabled, jitter will be applied both positively and negatively to the callback interval. For example, with a 10 second callback and 20% jitter, callbacks will occur between 8 and 12 seconds apart rather than between 10 and 12 seconds.

#### Realtime Mode
When enabled, the agent will not wait for the callback interval when it has pending messages to send. This significantly reduces latency but increases network traffic.


#### Chunk Size
The size in KB of file transfer chunks for upload/download operations (default: 512KB).

### Using with Mythic

When creating a payload in Mythic with the HTTP profile, follow these steps:

1. **Select HTTP Profile**: When creating a new payload, select "HTTP" from the communication profile dropdown
2. **Configure Basic Options**:
   - Callback Host/Port: The base domain and port for server communications
   - Callback Interval: How often the agent checks in
   - Jitter: Randomization percentage for callback timing
   - Kill Date: When the agent should stop functioning

3. **Set Agent Parameters**:
   - **debug_mode**: Enable for verbose logging (recommended for initial testing)
   - **symmetric_jitter**: Enable for more unpredictable callback timing
   - **realtime**: Configure for interactive operations
   - **disable_ssl_verify**: Enable if using self-signed certificates

The build process will detect that you're using the HTTP profile and create a self-contained binary with static OpenSSL linking.

### Debugging

If you encounter issues with the HTTP profile:

1. Enable debug_mode to see detailed logging
2. Check network connectivity to the callback host
3. Verify firewall rules allow outbound connections on the specified port
4. Look for SSL certificate issues if using HTTPS
5. Examine debug output for any encryption/decryption errors

Debug output will be sent to stdout, which Mythic captures during execution. This information is invaluable for troubleshooting connectivity issues or understanding how the agent is communicating with the server.
