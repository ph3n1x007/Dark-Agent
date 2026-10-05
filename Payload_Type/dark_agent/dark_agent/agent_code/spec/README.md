# Proxy regression tests

Run these tests from `Payload_Type/dark_agent/dark_agent/agent_code` on Linux. They use loopback servers and temporary TLS certificates. They do not start the agent or contact Mythic.

Check the required tools with `crystal --version`, `python3 --version`, and `openssl version`. Each command should print its version. Install any missing tool with your system's package manager before running the tests.

```sh
export DARK_AGENT_CONFIG_PATH="$PWD/spec/fixtures/proxy_config.json"
crystal spec
crystal spec -D httpx_profile
```

The ordinary run checks proxy discovery, precedence, bypass rules, URL parsing, and HTTP/CONNECT requests with no auth or Basic auth. Kerberos cases run only when the lab runner enables them.

For real Kerberos exchanges, check `command -v krb5kdc kdb5_util kadmin.local kinit`. It should print four executable paths. These tools come from the MIT Kerberos server, admin, and client packages. The runner reports the first missing tool if the check does not show all four.

```sh
python3 spec/support/run_kerberos_lab.py -- crystal spec
python3 spec/support/run_kerberos_lab.py -- crystal spec -D httpx_profile
```

The runner creates a temporary realm, database, keytabs, and credential cache. Its KDC listens on loopback at a temporary port. It passes private Kerberos config paths only to the test processes, stops the KDC on exit, and removes the temporary files. It does not change system Kerberos settings or the user's cache.

The Kerberos cases check automatic selection from a 407 challenge, real SPNEGO token exchange, mutual auth, fixed and chunked 407 bodies, socket reuse and explicit close, and failure with missing credentials or invalid server proof. A passing run ends with `0 failures, 0 errors` for both profiles. This verifies the protocol locally; the real proxy's DNS name, SPN, and RHEL credential cache still need to match its Kerberos setup.
