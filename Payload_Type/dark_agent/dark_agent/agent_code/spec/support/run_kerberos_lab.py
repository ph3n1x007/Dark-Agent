"""Run proxy specs with an isolated MIT Kerberos realm, then remove the lab."""
import argparse
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, help="Optional root of extracted Debian Kerberos packages")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command or ["crystal", "spec"]
    if command[0] == "--":
        command = command[1:]
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    if args.runtime:
        runtime = args.runtime.resolve()
        environment["LD_LIBRARY_PATH"] = str(runtime / "usr/lib/x86_64-linux-gnu")
    tools = {}
    for name in ("krb5kdc", "kdb5_util", "kadmin.local", "kinit"):
        candidate = shutil.which(name)
        if args.runtime:
            for directory in ("usr/sbin", "usr/bin"):
                path = runtime / directory / name
                if path.is_file():
                    candidate = str(path)
        if not candidate:
            raise SystemExit(f"Missing {name}; install MIT Kerberos KDC, admin, and client tools to run this test")
        tools[name] = candidate

    def run(name, *arguments):
        result = subprocess.run([tools[name], *arguments], env=environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(result.stdout)

    with tempfile.TemporaryDirectory(prefix="dark-proxy-kerberos-") as folder:
        lab = Path(folder)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        realm = "DARK-PROXY.TEST"
        environment.update({
            "KRB5_CONFIG": str(lab / "krb5.conf"),
            "KRB5_KDC_PROFILE": str(lab / "kdc.conf"),
            "KRB5CCNAME": f"FILE:{lab / 'ccache'}",
            "KRB5_KTNAME": f"FILE:{lab / 'proxy.keytab'}",
            "DARK_AGENT_KERBEROS_TEST": "1",
            "DARK_AGENT_CONFIG_PATH": str(root / "spec/fixtures/proxy_config.json"),
        })
        (lab / "krb5.conf").write_text(f"""[libdefaults]
 default_realm = {realm}
 dns_lookup_realm = false
 dns_lookup_kdc = false
 dns_canonicalize_hostname = false
 rdns = false
[realms]
 {realm} = {{
  kdc = 127.0.0.1:{port}
 }}
""")
        modules = f" db_module_dir = {runtime / 'usr/lib/x86_64-linux-gnu/krb5/plugins/kdb'}\n" if args.runtime else ""
        (lab / "kdc.conf").write_text(f"""[kdcdefaults]
 kdc_ports = {port}
 kdc_tcp_ports = {port}
 kdc_listen = 127.0.0.1:{port}
 kdc_tcp_listen = 127.0.0.1:{port}
[realms]
 {realm} = {{
  database_module = proxy_lab
  key_stash_file = {lab / 'stash'}
  acl_file = {lab / 'acl'}
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 }}
[dbmodules]
{modules} proxy_lab = {{
  db_library = db2
  database_name = {lab / 'principal'}
 }}
""")
        (lab / "acl").write_text("")
        run("kdb5_util", "create", "-s", "-P", secrets.token_hex(32), "-r", realm)
        for principal, keytab in ((f"client@{realm}", "client.keytab"), (f"HTTP/localhost@{realm}", "proxy.keytab")):
            run("kadmin.local", "-r", realm, "-q", f"addprinc -randkey {principal}")
            run("kadmin.local", "-r", realm, "-q", f"ktadd -k {lab / keytab} {principal}")
        with (lab / "kdc.log").open("w") as log:
            kdc = subprocess.Popen([tools["krb5kdc"], "-n", "-r", realm, "-P", str(lab / "kdc.pid")],
                                   env=environment, stdout=log, stderr=subprocess.STDOUT)
            try:
                ready = False
                for _ in range(50):
                    if kdc.poll() is not None:
                        raise RuntimeError((lab / "kdc.log").read_text())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.1)
                if not ready:
                    raise RuntimeError("Temporary KDC did not start")
                run("kinit", "-k", "-t", str(lab / "client.keytab"), f"client@{realm}")
                print("Temporary Kerberos realm ready; running proxy specs", flush=True)
                return subprocess.run(command, cwd=root, env=environment).returncode
            finally:
                if kdc.poll() is None:
                    kdc.terminate()
                    try:
                        kdc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        kdc.kill()
                        kdc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
