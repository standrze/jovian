#!/usr/bin/env python3
"""Wire checks for Martian's remaining modifiers, HAR capture, control API, TLS and drain."""
import argparse
import base64
import contextlib
import gzip
import http.client
import json
import os
import pathlib
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


SLOW_STARTED = threading.Event()
SLOW_RELEASE = threading.Event()


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urlsplit(self.path).path
        body = json.dumps({"path": self.path, "headers": list(self.headers.items())}).encode()
        kind = "application/json"
        if path == "/binary":
            body, kind = bytes(range(256)) * 32, "application/octet-stream"
        elif path == "/slow":
            SLOW_STARTED.set()
            assert SLOW_RELEASE.wait(5)
            body = b"drained"
        elif path == "/gzip":
            body = gzip.compress(b'{"hello":"decoded","token":"gzip-secret"}')
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Set-Cookie", "origin=1")
        if path == "/gzip":
            self.send_header("Content-Encoding", "gzip")
        if path == "/chunked":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Type", self.headers.get("Content-Type", "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(16384):
            self.request.sendall(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jovian", default=".build/debug/jovian")
    parser.add_argument("--live", action="store_true", help="also check trusted HTTPS through the TLS proxy listener")
    args = parser.parse_args()
    jovian = str(pathlib.Path(args.jovian).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix="jovian-completion-") as directory:
        root = pathlib.Path(directory)
        env = dict(os.environ, JOVIAN_SESSIONS_DIR=str(root / "sessions"), JOVIAN_SMOKE_PROXY_PASSWORD="fixture-password")
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        echo.daemon_threads = True
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{origin.server_port}"

        def call(port, method, path, value=None, headers=None, tls=None):
            conn = (http.client.HTTPSConnection("127.0.0.1", port, context=tls, timeout=10) if tls else
                    http.client.HTTPConnection("127.0.0.1", port, timeout=10))
            body = json.dumps(value).encode() if isinstance(value, dict) else value
            conn.request(method, path, body, headers or {})
            response = conn.getresponse()
            result = response.status, response.getheaders(), response.read()
            conn.close()
            return result

        def configure(api, node):
            result = call(api, "POST", "/configure", node)
            assert result[0] == 200, result

        def logs(api, minimum=0):
            for _ in range(100):
                entries = json.loads(call(api, "GET", "/logs")[2])["log"]["entries"]
                if len(entries) >= minimum:
                    return entries
                time.sleep(.01)
            raise AssertionError(f"expected {minimum} HAR entries, got {len(entries)}")

        @contextlib.contextmanager
        def serve(*extra):
            port, api = free_port(), free_port()
            log_file = open(root / f"proxy-{port}.log", "w+")
            process = subprocess.Popen([jovian, "serve", "--port", str(port), "--api-port", str(api), *extra],
                                       env=env, stdout=log_file, stderr=log_file)
            try:
                for _ in range(150):
                    if process.poll() is not None:
                        log_file.seek(0)
                        raise AssertionError(log_file.read())
                    try:
                        if call(api, "GET", "/health")[0] == 200:
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    raise AssertionError("proxy did not start")
                yield process, port, api, log_file
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise
                log_file.close()

        def append(value):
            return {"header.Append": {"name": "X-Order", "value": value}}

        try:
            with serve() as (_, port, api, _):
                configure(api, {"fifo.Group": {"modifiers": [
                    {"stash.Modifier": {"headerName": "X-Original", "scope": ["request", "response"]}},
                    {"url.Modifier": {"path": "/rewritten"}},
                    {"priority.Group": {"modifiers": [
                        {"priority": 5, "modifier": append("first")},
                        {"priority": 0, "modifier": append("last")},
                        {"priority": 5, "modifier": append("newer")}
                    ]}},
                    {"cookie.Modifier": {"name": "test", "value": "new", "domain": "fixture.test",
                                         "path": "/", "maxAge": -1, "secure": True, "httpOnly": True}}
                ]}})
                status, headers, data = call(port, "GET", base + "/before", headers={"Cookie": "test=old"})
                seen = json.loads(data)
                assert status == 200 and seen["path"] == "/rewritten", (status, seen)
                assert [v for k, v in seen["headers"] if k.lower() == "x-order"] == ["newer", "first", "last"]
                assert [v for k, v in headers if k.lower() == "x-order"] == ["newer", "first", "last"]
                checks.append("priority order and equal-priority reverse declaration order on both directions")
                assert dict(headers)["X-Original"] == base + "/before"
                checks.append("stash survives URL rewrite and echoes original URL")
                assert dict(seen["headers"])["Cookie"] == "test=old; test=new"
                assert [v for k, v in headers if k.lower() == "set-cookie"] == [
                    "origin=1", "test=new; Path=/; Domain=fixture.test; Max-Age=0; HttpOnly; Secure"]
                checks.append("canonical cookie append and attributes preserve origin cookies")
                assert "postData" not in logs(api, 1)[0]["request"]
                assert "text" not in logs(api, 1)[0]["response"]["content"]
                checks.append("HAR body retention disabled by default")
                assert call(port, "GET", "http://martian.proxy/health")[0] == 200
                configure(api, {"failure.Verifier": {"message": "API must bypass this"}})
                assert call(port, "GET", "http://martian.proxy/verify")[0] == 200
                assert len(logs(api)) == 1
                checks.append("reserved API bypasses modifiers and HAR logging without DNS")
                reset = call(port, "POST", "http://martian.proxy/verify/reset")
                assert reset[0] == 200
                checks.append("verification reset through reserved API")

            with serve("--har-bodies", "--har-body-limit", "128", "--body-redact-field", "custom_secret") as (_, port, api, _):
                payload = b'{"password":"wire-secret","custom_secret":"custom-value","ok":1}'
                result = call(port, "POST", base + "/echo", payload, {"Content-Type": "application/json"})
                assert result[2] == payload  # Retention redaction must not alter the forwarded body.
                entry = logs(api, 1)[-1]
                for captured in [entry["request"]["postData"], entry["response"]["content"]]:
                    decoded = base64.b64decode(captured["text"]) if captured.get("encoding") == "base64" or captured.get("_encoding") == "base64" else captured["text"].encode()
                    assert b"wire-secret" not in decoded and b"custom-value" not in decoded and b"REDACTED" in decoded
                checks.append("HAR captures both directions with default/custom field redaction and unchanged forwarding")
                form = b"password=form-secret&ok=1"
                call(port, "POST", base + "/echo", form, {"Content-Type": "application/x-www-form-urlencoded"})
                captured = logs(api, 2)[-1]["response"]["content"]
                assert b"form-secret" not in base64.b64decode(captured["text"])
                checks.append("HAR URL-encoded form field redaction")
                call(port, "GET", base + "/binary")
                captured = logs(api, 3)[-1]["response"]["content"]
                assert base64.b64decode(captured["text"]) == bytes(range(128)) and captured["_truncated"]
                checks.append("binary HAR capture uses bounded base64 prefix")
                status, _, data = call(port, "GET", base + "/chunked")
                assert status == 200 and json.loads(data)["path"] == "/chunked"
                captured = logs(api, 4)[-1]["response"]["content"]
                assert base64.b64decode(captured["text"]).startswith(b'{"headers"')
                checks.append("chunked HAR capture excludes chunk framing")
                call(port, "POST", base + "/echo", b"x" * 4_194_305)
                entry = logs(api, 5)[-1]
                assert entry["request"]["postData"]["text"].encode() == b"x" * 128
                assert entry["request"]["postData"]["_truncated"]
                checks.append("streaming upload HAR retains bounded payload prefix")

            ca = root / "ca"
            subprocess.run([jovian, "ca", "create", "--directory", str(ca)], env=env, check=True, stdout=subprocess.DEVNULL)
            subprocess.run([jovian, "ca", "issue", "127.0.0.1", "--directory", str(ca)], env=env, check=True, stdout=subprocess.DEVNULL)
            tls_port = free_port()
            tls_args = ["--tls-port", str(tls_port), "--tls-cert", str(ca / "hosts/127.0.0.1/cert.pem"),
                        "--tls-key", str(ca / "hosts/127.0.0.1/key.pem")]
            context = ssl.create_default_context(cafile=str(ca / "ca-cert.pem"))
            with serve("--intercept-ca", str(ca), "--api-cors", *tls_args) as (_, port, api, _):
                for endpoint in [api, port]:
                    target = "/authority.cer" if endpoint == api else "http://martian.proxy/authority.cer"
                    status, headers, data = call(endpoint, "GET", target)
                    assert status == 200 and data == (ca / "ca-cert.pem").read_bytes()
                    assert dict(headers)["Content-Type"] == "application/x-x509-ca-cert"
                    assert b"PRIVATE KEY" not in data
                checks.append("identical PEM CA export on admin and reserved proxy API")
                headers = {"Origin": "http://fixture.test", "Access-Control-Request-Method": "POST",
                           "Access-Control-Request-Headers": "Content-Type"}
                for endpoint in [api, port]:
                    target = "/configure" if endpoint == api else "http://martian.proxy/configure"
                    status, response_headers, data = call(endpoint, "OPTIONS", target, headers=headers)
                    assert status == 200 and not data
                    assert dict(response_headers)["Access-Control-Allow-Origin"] == "*"
                checks.append("CORS preflight on both control listeners")
                assert call(tls_port, "GET", base + "/tls", tls=context)[0] == 200
                assert call(tls_port, "GET", "http://martian.proxy/health", tls=context)[0] == 200
                checks.append("trusted TLS proxy carries absolute-form HTTP and control requests")
            with serve(*tls_args) as (_, port, api, _):
                with context.wrap_socket(socket.create_connection(("127.0.0.1", tls_port)), server_hostname="127.0.0.1") as sock:
                    sock.sendall(f"CONNECT 127.0.0.1:{echo.server_address[1]} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
                    data = b""
                    while b"\r\n\r\n" not in data:
                        data += sock.recv(4096)
                    assert data.startswith(b"HTTP/1.1 200")
                    for index in range(16):
                        payload = bytes([index]) * 32_768
                        sock.sendall(payload)
                        echoed = b""
                        while len(echoed) < len(payload):
                            echoed += sock.recv(len(payload) - len(echoed))
                        assert echoed == payload
                checks.append("opaque CONNECT works inside the TLS proxy transport")
                if args.live:
                    status, _, data = call(tls_port, "GET", "https://example.com/", tls=context)
                    assert status == 200 and b"Example Domain" in data
                    checks.append("trusted HTTPS origin forwarding through encrypted proxy")
                    status, _, data = call(tls_port, "GET", "/", headers={"Host": "example.com"}, tls=context)
                    assert status == 200 and b"Example Domain" in data
                    checks.append("origin-form requests on TLS listener use validated HTTPS")
                    # A separate SSLObject represents end-to-end origin TLS inside the outer proxy TLS.
                    with context.wrap_socket(socket.create_connection(("127.0.0.1", tls_port)), server_hostname="127.0.0.1") as outer:
                        outer.settimeout(15)
                        outer.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                        established = b""
                        while b"\r\n\r\n" not in established:
                            established += outer.recv(4096)
                        assert established.startswith(b"HTTP/1.1 200")
                        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                        inner = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname="example.com")

                        def flush():
                            while outgoing.pending:
                                outer.sendall(outgoing.read())

                        def drive(operation):
                            while True:
                                try:
                                    value = operation()
                                    flush()
                                    return value
                                except ssl.SSLWantWriteError:
                                    flush()
                                except ssl.SSLWantReadError:
                                    flush()
                                    data = outer.recv(16384)
                                    if data:
                                        incoming.write(data)
                                    else:
                                        incoming.write_eof()

                        drive(inner.do_handshake)
                        drive(lambda: inner.write(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"))
                        response = b""
                        while b"Example Domain" not in response:
                            chunk = drive(lambda: inner.read(16384))
                            if not chunk:
                                break
                            response += chunk
                        assert response.startswith(b"HTTP/1.1 200") and b"Example Domain" in response
                    checks.append("end-to-end origin TLS works inside CONNECT over encrypted proxy")

            with serve("--proxy-user", "tester", "--proxy-password-env", "JOVIAN_SMOKE_PROXY_PASSWORD", *tls_args) as (_, _, _, _):
                assert call(tls_port, "GET", "http://martian.proxy/health", tls=context)[0] == 407
                auth = "Basic " + base64.b64encode(b"tester:fixture-password").decode()
                assert call(tls_port, "GET", "http://martian.proxy/health", headers={"Proxy-Authorization": auth}, tls=context)[0] == 200
                checks.append("TLS listener authenticates reserved control requests")
                try:
                    call(tls_port, "GET", "http://martian.proxy/health", tls=ssl.create_default_context())
                    raise AssertionError("untrusted proxy certificate accepted")
                except ssl.SSLCertVerificationError:
                    pass
                checks.append("untrusted TLS proxy identity rejected by client")

            with serve() as (process, port, api, log_file):
                configure(api, {"url.Filter": {"path": "/gzip", "modifier": {"log.Logger": {
                    "scope": ["response"], "decode": True
                }}}})
                call(port, "GET", base + "/unmatched")
                status, headers, data = call(port, "GET", base + "/gzip")
                assert status == 200 and b"gzip-secret" in gzip.decompress(data)
                process.terminate()
                process.wait(timeout=5)
                log_file.seek(0)
                text = log_file.read()
                assert text.count("Response from") == 1 and "decoded" in text and "gzip-secret" not in text
                checks.append("filtered canonical logger decodes/redacts snapshot without altering compressed forwarding")

            with serve("--shutdown-grace-ms", "2000") as (process, port, _, _):
                result = []
                thread = threading.Thread(target=lambda: result.append(call(port, "GET", base + "/slow")))
                thread.start()
                assert SLOW_STARTED.wait(3)
                process.send_signal(signal.SIGTERM)
                time.sleep(.15)
                assert process.poll() is None, "process exited before active response drained"
                SLOW_RELEASE.set()
                thread.join(3)
                process.wait(timeout=3)
                assert result[0][0] == 200 and result[0][2] == b"drained"
                checks.append("SIGTERM waits for in-flight response before process exit")

            failed = subprocess.run([jovian, "serve", "--tls-port", "0", "--tls-cert", str(ca / "ca-cert.pem"),
                                     "--tls-key", str(ca / "hosts/127.0.0.1/key.pem")], env=env, capture_output=True, timeout=5)
            assert failed.returncode != 0 and b"do not match" in failed.stderr, failed.stderr
            checks.append("mismatched TLS certificate/key rejected before listening")
        finally:
            SLOW_RELEASE.set()
            origin.shutdown()
            origin.server_close()
            echo.shutdown()
            echo.server_close()
    for check in checks:
        print("PASS", check)
    print(f"{len(checks)} Martian completion wire checks passed")


if __name__ == "__main__":
    main()
