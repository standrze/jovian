#!/usr/bin/env python3
"""Local wire checks for Via, message headers, aggregation, streaming, ranges, and SNI/nested TLS."""
import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


PAYLOAD = b"stream-response-marker\n" + b"x" * (5 * 1024 * 1024)


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits = 0

    def log_message(self, *_):
        pass

    def do_GET(self):
        Origin.hits += 1
        body = json.dumps(dict(self.headers.items())).encode() if self.path == "/headers" else PAYLOAD
        self.send_response(200)
        if self.path == "/chunked":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(f"{len(body):x};large=yes\r\n".encode() + body + b"\r\n0\r\nX-End: yes\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[:100] if self.path == "/interrupted" else body)
            if self.path == "/interrupted":
                self.close_connection = True

    def do_POST(self):
        Origin.hits += 1
        if self.headers.get("Transfer-Encoding") == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if not size:
                    while self.rfile.readline() != b"\r\n":
                        pass
                    break
                chunks.append(self.rfile.read(size))
                assert self.rfile.read(2) == b"\r\n"
            data = b"".join(chunks)
        else:
            data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.dumps({"length": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                           "headers": dict(self.headers.items())}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jovian", default=".build/debug/jovian")
    args = parser.parse_args()
    jovian = str(pathlib.Path(args.jovian).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix="jovian-upgrades-") as directory:
        root = pathlib.Path(directory)
        env = dict(os.environ, JOVIAN_SESSIONS_DIR=str(root / "sessions"), NSUnbufferedIO="YES")
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{origin.server_port}"

        def call(port, method, target, body=None, headers=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                conn.request(method, target, body, headers or {})
                response = conn.getresponse()
                return response.status, dict(response.getheaders()), response.read()
            finally:
                conn.close()

        def api(port, method, path, node=None):
            status, _, data = call(port, method, path, json.dumps(node) if node is not None else None,
                                   {"Content-Type": "application/json"})
            return status, json.loads(data) if data.startswith(b"{") else data

        def configure(api_port, node):
            result = api(api_port, "POST", "/configure", node)
            assert result[0] == 200, result

        @contextlib.contextmanager
        def serve(*extra, port=None):
            port, api_port = port or free_port(), free_port()
            log = open(root / f"proxy-{port}.log", "w+")
            process = subprocess.Popen([jovian, "serve", "--port", str(port), "--api-port", str(api_port), *extra],
                                       env=env, stdout=log, stderr=log)
            try:
                for _ in range(150):
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError(log.read())
                    try:
                        if api(api_port, "GET", "/health")[0] == 200:
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    raise AssertionError("proxy did not start")
                yield process, port, api_port, log
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise
                log.close()

        def group(*nodes, aggregate=False):
            return {"fifo.Group": {"aggregateErrors": aggregate, "modifiers": list(nodes)}}

        def header(name, value, scope="request"):
            return {"header.Modifier": {"name": name, "value": value, "scope": [scope]}}

        def replacement(data=b"0123456789"):
            return {"body.Modifier": {"body": base64.b64encode(data).decode(), "contentType": "text/plain",
                                      "scope": ["response"]}}

        try:
            with serve() as (_, port, admin, _):
                status, _, data = call(port, "GET", base + "/headers", headers={"Via": "1.0 upstream"})
                via = json.loads(data)["Via"]
                assert status == 200 and via.startswith("1.0 upstream, 1.1 jovian-"), via
                hits = Origin.hits
                assert call(port, "GET", base + "/headers", headers={"Via": via})[0] == 400
                assert Origin.hits == hits
                checks.append("Via preserves previous hops and rejects a returning identity before origin contact")

                configure(admin, group(header("Host", "virtual.test"),
                    {"header.Copy": {"from": "Host", "to": "X-Copied-Host", "scope": ["request"]}},
                    {"header.Copy": {"from": "Content-Length", "to": "X-Copied-Length", "scope": ["request"]}},
                    {"header.Copy": {"from": "Host", "to": "X-Response-Host", "scope": ["response"]}}))
                status, fields, data = call(port, "GET", base + "/headers")
                seen = json.loads(data)
                assert status == 200 and seen["Host"] == seen["X-Copied-Host"] == "virtual.test"
                assert seen["X-Copied-Length"] == "0" and fields["X-Response-Host"] == ""
                checks.append("Host overrides preserve destination routing; special header copy sees zero length and empty response Host")

                configure(admin, group({"header.Blacklist": {"names": ["Host"], "scope": ["request"]}},
                    {"header.Copy": {"from": "Host", "to": "X-Cleared-Host", "scope": ["request"]}}))
                status, _, data = call(port, "GET", base + "/headers")
                seen = json.loads(data)
                assert status == 200 and seen["Host"] == base.removeprefix("http://") and seen["X-Cleared-Host"] == ""
                checks.append("deleted Host reads empty to modifiers and falls back to URL authority on the wire")

                for aggregate in (False, True):
                    configure(admin, group({"header.Append": {"name": "Host", "value": "duplicate", "scope": ["request"]}},
                                            {"failure.Verifier": {"message": "after error"}}, aggregate=aggregate))
                    assert call(port, "GET", base + "/headers")[0] == 502
                    assert len(api(admin, "GET", "/verify")[1]["errors"]) == int(aggregate)
                checks.append("aggregateErrors runs subsequent request verifiers; default groups fail fast")
                configure(admin, group({"header.Append": {"name": "Content-Length", "value": "1", "scope": ["response"]}},
                    {"header.Verifier": {"name": "X-Missing", "scope": ["response"]}}, aggregate=True))
                assert call(port, "GET", base + "/headers")[0] == 502
                assert len(api(admin, "GET", "/verify")[1]["errors"]) == 1
                checks.append("aggregateErrors also runs subsequent response modifiers")

                configure(admin, header("Content-Length", "99"))
                status, _, data = call(port, "GET", base + "/headers")
                assert status == 200 and json.loads(data)["Content-Length"] == "0"
                checks.append("modifier Content-Length is normalized to the body actually forwarded")
                configure(admin, {"noop.Modifier": {}})
                for framing in [b"Content-Length: bad", b"Content-Length: 0\r\ncontent-length: 0",
                                b"Transfer-Encoding: gzip, chunked", b"Transfer-Encoding: chunked\r\nContent-Length: 0"]:
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                        sock.sendall(b"POST " + base.encode() + b"/headers HTTP/1.1\r\nHost: fixture\r\n" + framing + b"\r\n\r\n")
                        rejected = sock.recv(4096)
                        assert not rejected or rejected.startswith((b"HTTP/1.1 400", b"HTTP/1.1 502")), (framing, rejected)
                checks.append("ambiguous, malformed and unsupported message framing is rejected before reading a body")

                configure(admin, group({"skip.RoundTrip": {}}, replacement()))
                for value, expected in [("bytes=2-4", b"234"), ("bytes=-3", b"789"), ("bytes=8-", b"89")]:
                    status, fields, data = call(port, "GET", "http://mock.invalid/", headers={"Range": value})
                    assert status == 206 and data == expected and int(fields["Content-Length"]) == len(data)
                status, fields, data = call(port, "GET", "http://mock.invalid/", headers={"Range": "bytes=0-1,8-9"})
                assert status == 206 and fields["Content-Type"].startswith("multipart/byteranges;")
                assert b"bytes 0-1/10\r\n\r\n01\r\n" in data and b"bytes 8-9/10\r\n\r\n89\r\n" in data
                assert int(fields["Content-Length"]) == len(data) and "Content-Range" not in fields
                assert call(port, "GET", "http://mock.invalid/", headers={"Range": "bytes=99-"})[0] == 416
                status, fields, body = call(port, "HEAD", "http://mock.invalid/", headers={"Range": "bytes=2-4"})
                assert status == 206 and body == b""
                assert all(fields.get(key) == value for key, value in {"Content-Type": "text/plain", "Content-Length": "3", "Content-Range": "bytes 2-4/10", "Accept-Ranges": "bytes", "Connection": "keep-alive"}.items())
                assert fields["Via"].startswith("1.1 jovian-")
                checks.append("body replacement serves single, suffix, open, multipart, unsatisfiable and HEAD ranges")

                files = root / "files"
                files.mkdir()
                (files / "large.txt").write_bytes(PAYLOAD)
                configure(admin, {"static.Modifier": {"rootPath": str(files)}})
                assert call(port, "GET", "http://mock.invalid/large.txt")[2] == PAYLOAD
                status, fields, data = call(port, "GET", "http://mock.invalid/large.txt", headers={"Range": "bytes=0-5,-5"})
                assert status == 206 and int(fields["Content-Length"]) == len(data)
                assert b"stream\r\n" in data and b"xxxxx\r\n" in data
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("HEAD", "http://mock.invalid/large.txt")
                response = conn.getresponse()
                assert response.getheader("Content-Length") == str(len(PAYLOAD)) and not response.read()
                conn.request("GET", "http://mock.invalid/large.txt", headers={"Range": "bytes=0-5"})
                assert conn.getresponse().read() == b"stream"
                conn.close()
                checks.append("large static files stream correctly, including multipart and HEAD keep-alive")

            with serve() as (_, downstream, _, _):
                with serve("--upstream-proxy", f"http://127.0.0.1:{downstream}") as (_, port, _, _):
                    status, _, data = call(port, "GET", base + "/headers")
                    assert status == 200 and json.loads(data)["Via"].count("jovian-") == 2
                    checks.append("two chained Jovian proxies append distinct Via identities")
            self_port = free_port()
            with serve("--upstream-proxy", f"http://127.0.0.1:{self_port}", port=self_port) as (_, port, admin, _):
                assert call(port, "GET", base + "/headers")[0] == 400
                configure(admin, {"header.Blacklist": {"names": ["Via"], "scope": ["request"]}})
                assert call(port, "GET", base + "/headers")[0] == 400
                assert call(port, "CONNECT", "fixture.test:443")[0] == 400
                checks.append("self-chained HTTP and CONNECT fail promptly; header rules cannot erase loop protection")

            with serve() as (process, port, admin, log):
                configure(admin, {"log.Logger": {"scope": ["request", "response"]}})
                upload = b"stream-upload-marker\n" + b"u" * (5 * 1024 * 1024)
                status, _, data = call(port, "POST", base + "/upload", upload)
                assert status == 200 and json.loads(data)["sha256"] == hashlib.sha256(upload).hexdigest()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("POST", base + "/upload", iter([upload]), encode_chunked=True)
                response = conn.getresponse()
                assert response.status == 200 and json.loads(response.read())["length"] == len(upload)
                conn.close()
                for path in ["/fixed", "/chunked"]:
                    assert call(port, "GET", base + path)[2] == PAYLOAD
                try:
                    call(port, "GET", base + "/interrupted")
                    raise AssertionError("early EOF was not detected")
                except http.client.IncompleteRead as error:
                    assert b"502 Bad Gateway" not in error.partial
                    assert error.partial == PAYLOAD[:100]
                process.terminate()
                process.wait(timeout=8)
                log.seek(0)
                text = log.read()
                assert text.count("stream-upload-marker") == 2 and text.count("stream-response-marker") == 3
                assert text.count("[body truncated]") >= 4 and "[stream interrupted]" in text
                assert "streaming body unavailable" not in text
                checks.append("streaming request/fixed/chunked response logs capture bounded prefixes without changing payloads")
                checks.append("early EOF produces exactly one interrupted streaming log")

            ca = root / "ca"
            subprocess.run([jovian, "ca", "create", "--directory", str(ca)], check=True, capture_output=True, env=env)
            context = ssl.create_default_context(cafile=str(ca / "ca-cert.pem"))
            tls_port = free_port()
            with serve("--tls-port", str(tls_port), "--tls-ca", str(ca), "--intercept-ca", str(ca)) as (_, _, admin, _):
                for name in ["first.proxy.test", "second.proxy.test"]:
                    with context.wrap_socket(socket.create_connection(("127.0.0.1", tls_port)), server_hostname=name) as sock:
                        assert ("DNS", name) in sock.getpeercert()["subjectAltName"]
                        sock.sendall(b"GET http://martian.proxy/health HTTP/1.1\r\nHost: martian.proxy\r\n\r\n")
                        assert sock.recv(4096).startswith(b"HTTP/1.1 200")
                checks.append("dynamic TLS selects separately trusted certificates for distinct SNI names")
                no_sni = ssl.create_default_context(cafile=str(ca / "ca-cert.pem"))
                no_sni.check_hostname = False
                with no_sni.wrap_socket(socket.create_connection(("127.0.0.1", tls_port))) as sock:
                    assert ("DNS", "localhost") in sock.getpeercert()["subjectAltName"]
                checks.append("missing SNI uses the configured default identity")
                try:
                    context.wrap_socket(socket.create_connection(("127.0.0.1", tls_port)), server_hostname="-invalid.test")
                    raise AssertionError("invalid SNI accepted")
                except ssl.SSLError:
                    pass
                checks.append("invalid SNI names are rejected during the handshake")
                configure(admin, group({"skip.RoundTrip": {}}, replacement(),
                    header("X-Intercepted", "yes", "response")))
                with context.wrap_socket(socket.create_connection(("127.0.0.1", tls_port)), server_hostname="proxy.test") as outer:
                    outer.settimeout(10)
                    outer.sendall(b"CONNECT nested.test:443 HTTP/1.1\r\nHost: nested.test:443\r\n\r\n")
                    established = b""
                    while b"\r\n\r\n" not in established:
                        established += outer.recv(4096)
                    assert established.startswith(b"HTTP/1.1 200")
                    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                    inner = context.wrap_bio(incoming, outgoing, server_hostname="nested.test")

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
                    assert ("DNS", "nested.test") in inner.getpeercert()["subjectAltName"]
                    for selected, expected in [(b"2-4", b"234"), (b"8-", b"89")]:
                        drive(lambda: inner.write(b"GET / HTTP/1.1\r\nHost: nested.test\r\nRange: bytes=" + selected + b"\r\n\r\n"))
                        response = b""
                        while b"\r\n\r\n" not in response:
                            response += drive(lambda: inner.read(16384))
                        head, body = response.split(b"\r\n\r\n", 1)
                        length = int(next(line.split(b":", 1)[1] for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")))
                        while len(body) < length:
                            body += drive(lambda: inner.read(16384))
                        assert head.startswith(b"HTTP/1.1 206") and b"X-Intercepted: yes" in head and body == expected
                checks.append("CONNECT inside proxy TLS is intercepted with trusted inner TLS, modifiers and keep-alive")
            tls_port = free_port()
            with serve("--tls-port", str(tls_port), "--tls-ca", str(ca), "--intercept-ca", str(ca),
                       "--shutdown-grace-ms", "100") as (process, _, _, _):
                with context.wrap_socket(socket.create_connection(("127.0.0.1", tls_port)), server_hostname="proxy.test") as outer:
                    outer.sendall(b"CONNECT nested.test:443 HTTP/1.1\r\nHost: nested.test:443\r\n\r\n")
                    assert outer.recv(4096).startswith(b"HTTP/1.1 200")
                    start = time.monotonic()
                    process.terminate()
                    process.wait(timeout=3)
                    assert time.monotonic() - start < 2
            checks.append("shutdown interrupts a pending inner TLS handshake within the drain deadline")
        finally:
            origin.shutdown()
            origin.server_close()
    for check in checks:
        print("PASS:", check)
    print(f"{len(checks)} proxy upgrade wire checks passed")


if __name__ == "__main__":
    main()
