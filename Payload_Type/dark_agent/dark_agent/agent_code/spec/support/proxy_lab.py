"""Loopback HTTP proxy fixture. Uses the system GSSAPI for real Kerberos tests."""
import argparse
import base64
import ctypes
import json
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path


class Buffer(ctypes.Structure):
    _fields_ = [("length", ctypes.c_size_t), ("value", ctypes.c_void_p)]


class Acceptor:
    def __init__(self):
        self.lib = ctypes.CDLL("libgssapi_krb5.so.2")
        self.context = ctypes.c_void_p()
        u32p = ctypes.POINTER(ctypes.c_uint32)
        ptrp = ctypes.POINTER(ctypes.c_void_p)
        bufp = ctypes.POINTER(Buffer)
        self.lib.gss_accept_sec_context.argtypes = [
            u32p, ptrp, ctypes.c_void_p, bufp, ctypes.c_void_p,
            ptrp, ptrp, bufp, u32p, u32p, ptrp,
        ]
        self.lib.gss_accept_sec_context.restype = ctypes.c_uint32
        self.lib.gss_release_buffer.argtypes = [u32p, bufp]
        self.lib.gss_delete_sec_context.argtypes = [u32p, ptrp, bufp]

    def step(self, value):
        raw = base64.b64decode(value.split(" ", 1)[1], validate=True)
        storage = ctypes.create_string_buffer(raw)
        incoming = Buffer(len(raw), ctypes.cast(storage, ctypes.c_void_p))
        outgoing = Buffer()
        minor, flags = ctypes.c_uint32(), ctypes.c_uint32()
        major = self.lib.gss_accept_sec_context(
            ctypes.byref(minor), ctypes.byref(self.context), None,
            ctypes.byref(incoming), None, None, None,
            ctypes.byref(outgoing), ctypes.byref(flags), None, None,
        )
        try:
            if major not in (0, 1):
                raise RuntimeError(f"GSS accept failed: major={major:#x}, minor={minor.value:#x}")
            token = ctypes.string_at(outgoing.value, outgoing.length) if outgoing.length else b""
            return major == 0, base64.b64encode(token).decode()
        finally:
            self.lib.gss_release_buffer(ctypes.byref(minor), ctypes.byref(outgoing))

    def close(self):
        minor = ctypes.c_uint32()
        if self.context.value:
            self.lib.gss_delete_sec_context(ctypes.byref(minor), ctypes.byref(self.context), None)


def read_request(connection):
    stream = connection.makefile("rb", buffering=0)
    try:
        line = stream.readline(8192).decode().strip()
        if not line:
            return None
        headers = {}
        while True:
            raw = stream.readline(16384)
            if not raw:
                raise RuntimeError("EOF in request headers")
            if raw == b"\r\n":
                break
            name, value = raw.decode().split(":", 1)
            headers[name.lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        body = bytearray()
        while len(body) < length:
            chunk = stream.read(length - len(body))
            if not chunk:
                raise RuntimeError("EOF in request body")
            body.extend(chunk)
        return {"line": line, "headers": headers, "body": body.decode()}
    finally:
        stream.close()


def challenge(connection, args):
    headers = 'Proxy-Authenticate: Basic realm="lab"\r\nProxy-Authenticate: nEgOtIaTe\r\n'
    if args.close_first:
        headers += "Connection: close\r\n"
    if args.framing == "chunked":
        connection.sendall(("HTTP/1.1 407 Proxy Authentication Required\r\n" + headers +
                            "Transfer-Encoding: chunked\r\n\r\n4\r\nneed\r\n5\r\n auth\r\n0\r\nX-Lab: drained\r\n\r\n").encode())
    else:
        connection.sendall(("HTTP/1.1 407 Proxy Authentication Required\r\n" + headers +
                            "Content-Length: 9\r\n\r\nneed auth").encode())


def run(args, directory):
    tls = None
    if args.tls:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=origin.test"], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
    acceptor = Acceptor() if args.auth == "negotiate" else None
    stats = {"connections": 0, "requests": [], "origin": None}
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(10)
            print(listener.getsockname()[1], flush=True)
            finished = False
            while not finished:
                connection, _ = listener.accept()
                stats["connections"] += 1
                connection.settimeout(10)
                try:
                    while True:
                        request = read_request(connection)
                        if request is None:
                            finished = True
                            break
                        stats["requests"].append(request)
                        authorization = request["headers"].get("proxy-authorization")
                        final_token = ""
                        if args.auth == "basic":
                            expected = "Basic " + base64.b64encode(b"lab:p:ss").decode()
                            if authorization != expected:
                                raise RuntimeError("Incorrect Basic credentials")
                        elif args.auth == "negotiate":
                            if not authorization:
                                challenge(connection, args)
                                if args.close_first:
                                    break
                                continue
                            complete, final_token = acceptor.step(authorization)
                            if not complete:
                                connection.sendall(("HTTP/1.1 407 Proxy Authentication Required\r\n"
                                                    f"Proxy-Authenticate: Negotiate {final_token}\r\n"
                                                    "Content-Length: 0\r\n\r\n").encode())
                                continue
                            if args.bad_final:
                                final_token = base64.b64encode(b"invalid-gss-token").decode()
                            if args.missing_final:
                                final_token = ""
                        elif authorization:
                            raise RuntimeError("Credentials sent to a proxy without auth")

                        header = f"Proxy-Authenticate: Negotiate {final_token}\r\n" if final_token else ""
                        if args.tls:
                            if not request["line"].startswith("CONNECT origin.test:8443 "):
                                raise RuntimeError("Incorrect CONNECT authority")
                            connection.sendall(("HTTP/1.1 200 Connection Established\r\n" + header + "\r\n").encode())
                            if args.bad_final or args.missing_final:
                                finished = True
                                break
                            connection = tls.wrap_socket(connection, server_side=True)
                            origin = read_request(connection)
                            if origin["headers"].get("proxy-authorization"):
                                raise RuntimeError("Proxy credentials leaked into tunnel")
                            stats["origin"] = origin
                            header = ""
                        connection.sendall((f"HTTP/1.1 {args.status} Lab Response\r\n" + header +
                                            "Content-Length: 8\r\n\r\nproxy-ok").encode())
                        finished = True
                        break
                finally:
                    connection.close()
        print(json.dumps(stats), flush=True)
    finally:
        if acceptor:
            acceptor.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--auth", choices=["none", "basic", "negotiate"], default="none")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--close-first", action="store_true")
    parser.add_argument("--bad-final", action="store_true")
    parser.add_argument("--missing-final", action="store_true")
    parser.add_argument("--framing", choices=["fixed", "chunked"], default="fixed")
    parser.add_argument("--status", type=int, default=200)
    with tempfile.TemporaryDirectory(prefix="dark-proxy-fixture-") as directory:
        run(parser.parse_args(), directory)
