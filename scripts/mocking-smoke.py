#!/usr/bin/env python3
"""Exercise canonical mocks/verifiers and synthetic-response framing over real loopback HTTP."""
import argparse
import contextlib
import http.client
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            # Replaced streaming bodies deliberately retire their upstream socket.
            pass

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)
        if "/held" in self.path:
            self.server.arrived.set()
            assert self.server.release.wait(5), "held response was never released"
        body = b"origin contacted"
        self.send_response(200)
        chunked = "/chunked" in self.path
        self.send_header("Transfer-Encoding" if chunked else "Content-Length", "chunked" if chunked else str(len(body)))
        self.end_headers()
        self.wfile.write(b"10\r\n" + body + b"\r\n0\r\n\r\n" if chunked else body)

    def do_HEAD(self):
        self.server.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "16")
        self.end_headers()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jovian", default=".build/debug/jovian")
    args = parser.parse_args()
    jovian = str(pathlib.Path(args.jovian).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix="jovian-mocking-") as directory:
        root = pathlib.Path(directory)
        files = root / "files"
        files.mkdir()
        (files / "fixture.txt").write_bytes(b"0123456789")
        (files / "link").symlink_to(root / "secret.txt")
        (root / "secret.txt").write_text("must never escape")
        (files / "large").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        origin.hits = []
        origin.arrived = threading.Event()
        origin.release = threading.Event()
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        env = dict(os.environ, JOVIAN_SESSIONS_DIR=str(root / "sessions"))

        @contextlib.contextmanager
        def serve(*extra):
            port, api = free_port(), free_port()
            process = subprocess.Popen([jovian, "serve", "--port", str(port), "--api-port", str(api),
                                        "--upstream-proxy", f"http://127.0.0.1:{origin.server_port}", *extra],
                                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise AssertionError(process.stderr.read().decode())
                    try:
                        if api_call(api, "GET", "/health")[0] == 200:
                            break
                    except OSError:
                        time.sleep(.03)
                else:
                    raise AssertionError("proxy did not start")
                yield port, api
            finally:
                process.terminate()
                process.wait(timeout=5)
                process.stderr.close()

        def api_call(api, method, path, document=None):
            connection = http.client.HTTPConnection("127.0.0.1", api, timeout=5)
            connection.request(method, path, None if document is None else json.dumps(document),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read()
            connection.close()
            return response.status, json.loads(body) if body.startswith(b"{") else body

        def configure(api, node):
            status, body = api_call(api, "POST", "/configure", node)
            assert status == 200, (status, body)

        def errors(api):
            return api_call(api, "GET", "/verify")[1]["errors"]

        def request(port, path="/ready", method="GET", headers=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request(method, "http://mock.invalid" + path, headers=headers or {})
            response = connection.getresponse()
            status, fields, body = response.status, dict(response.getheaders()), response.read()
            connection.close()
            return status, fields, body

        def static():
            return {"static.Modifier": {"rootPath": str(files), "explicitPaths": {"/ready": "fixture.txt"}}}

        try:
            with serve() as (port, api):
                configure(api, static())
                status, fields, body = request(port)
                assert status == 200 and body == b"0123456789"
                assert all(fields.get(key) == value for key, value in {"Content-Type": "text/plain; charset=utf-8", "Accept-Ranges": "bytes", "Content-Length": "10", "Connection": "keep-alive"}.items())
                assert fields["Via"].startswith("1.1 jovian-")
                assert not origin.hits
                checks.append("canonical static mock and path map bypass origin and next hop")

                for value, status, body in [("bytes=2-4", 206, b"234"), ("bytes=8-", 206, b"89"),
                                            ("bytes=-2", 206, b"89"), ("bytes=99-", 416, b"")]:
                    actual, fields, content = request(port, headers={"Range": value})
                    assert (actual, content) == (status, body)
                    assert "Content-Range" in fields
                checks.append("single, open-ended, suffix and unsatisfiable ranges")

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("HEAD", "http://mock.invalid/ready")
                response = connection.getresponse()
                assert response.status == 200 and response.getheader("Content-Length") == "10" and response.read() == b""
                connection.request("GET", "http://mock.invalid/ready")
                assert connection.getresponse().read() == b"0123456789"
                connection.close()
                checks.append("HEAD sends metadata only and preserves the next response on keep-alive")

                for path, status in [("/missing", 404), ("/%2e%2e/secret.txt", 403), ("/link", 403)]:
                    actual, _, body = request(port, path)
                    assert (actual, body) == (status, b""), (path, actual, body)
                assert request(port, method="POST")[0] == 405
                assert not origin.hits
                checks.append("missing files, traversal, symlinks and unsupported methods fail locally")

                nodes = [static(),
                         {"pingback.Verifier": {"path": "/ready", "query": "q=A+B"}},
                         {"header.Verifier": {"scope": ["request"], "name": "X-Mode", "value": "fixture"}},
                         {"method.Verifier": {"method": "GET"}},
                         {"url.Verifier": {"scheme": "http", "host": "mock.invalid", "path": "/ready"}},
                         {"querystring.Verifier": {"name": "q", "value": "A B"}},
                         {"header.Verifier": {"scope": ["response"], "name": "Content-Type"}},
                         {"status.Verifier": {"statusCode": 200}}]
                configure(api, {"fifo.Group": {"modifiers": nodes}})
                assert len(errors(api)) == 1  # Admin reads do not fulfill a pingback.
                assert request(port, "/ready?q=A+B", headers={"X-Mode": "fixture"})[0] == 200
                assert not errors(api)
                api_call(api, "POST", "/verify/reset")
                assert len(errors(api)) == 1
                assert request(port, "/missing", method="POST")[0] == 405
                assert len(errors(api)) == 7
                checks.append("all expectation verifiers compose, accumulate failures and reset; pingback starts pending")

                configure(api, {"fifo.Group": {"modifiers": [
                    {"skip.RoundTrip": {}}, {"failure.Verifier": {"message": "fixture reached"}},
                    {"body.Modifier": {"scope": ["response"], "body": "aGVsbG8="}},
                    {"status.Modifier": {"statusCode": 201}}
                ]}})
                assert request(port)[::2] == (201, b"hello")
                assert len(errors(api)) == 1 and "fixture reached" in errors(api)[0]["message"]
                assert not origin.hits
                checks.append("skip.RoundTrip composes arbitrary mock bodies/statuses; failure.Verifier only records")

                # The proxy must close instead of interpreting an unread upload as another request.
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    sock.sendall(b"POST http://mock.invalid/ready HTTP/1.1\r\nHost: mock.invalid\r\n"
                                 b"Content-Length: 5000000\r\n\r\nGET http://mock.invalid/smuggled HTTP/1.1\r\n\r\n")
                    response = http.client.HTTPResponse(sock)
                    response.begin()
                    assert response.status == 201 and response.getheader("Connection") == "close"
                    assert response.read() == b"hello"
                    assert sock.recv(1024) == b""
                assert len(errors(api)) == 2
                checks.append("early mock closes safely with an unread streaming upload")

                for expected in [204, 205, 304]:
                    configure(api, {"fifo.Group": {"modifiers": [
                        {"skip.RoundTrip": {}}, {"body.Modifier": {"scope": ["response"], "body": "aGVsbG8="}},
                        {"header.Modifier": {"scope": ["response"], "name": "Transfer-Encoding", "value": "chunked"}},
                        {"status.Modifier": {"statusCode": expected}}
                    ]}})
                    status, fields, body = request(port)
                    assert status == expected and body == b"" and "Transfer-Encoding" not in fields
                    assert fields.get("Content-Length") == {204: None, 205: "0", 304: "5"}[expected]
                checks.append("synthetic no-content responses suppress bodies and conflicting framing headers")

                configure(api, {"header.Verifier": {"scope": ["request"], "name": "Authorization", "value": "expected-secret"}})
                assert request(port, headers={"Authorization": "actual-secret"})[0] == 200
                assert "secret" not in json.dumps(errors(api))
                assert len(origin.hits) == 1
                assert api_call(api, "POST", "/configure", {"static.Modifier": {
                    "rootPath": str(files), "explicitPaths": {"/bad": "../secret.txt"}}})[0] == 400
                request(port)
                assert len(errors(api)) == 2
                checks.append("ordinary forwarding remains available, errors redact values, rejected rules stay inactive")

            subprocess.run([jovian, "sessions", "new", "scoped", "--origin", "http://mock.invalid"],
                           env=env, capture_output=True, check=True, timeout=10)
            with serve("--session", "scoped") as (port, api):
                configure(api, {"fifo.Group": {"modifiers": [
                    {"url.Modifier": {"host": "outside.invalid"}}, static()
                ]}})
                assert request(port)[0] == 403
                assert len(origin.hits) == 2
                checks.append("session scope is checked before serving a file for a rewritten URL")

            with serve() as (port, api):
                configure(api, {"static.Modifier": {"scope": ["response"], "rootPath": str(files),
                                                   "explicitPaths": {"/chunked": "fixture.txt", "/ready": "fixture.txt"}}})
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                for _ in range(2):
                    connection.request("GET", "http://mock.invalid/chunked")
                    response = connection.getresponse()
                    assert response.status == 200 and response.getheader("Transfer-Encoding") is None
                    assert response.read() == b"0123456789"
                connection.request("HEAD", "http://mock.invalid/ready")
                response = connection.getresponse()
                assert response.getheader("Content-Length") == "10" and response.read() == b""
                connection.request("GET", "http://mock.invalid/ready")
                assert connection.getresponse().read() == b"0123456789"
                connection.close()
                checks.append("response-only static replacement reframes chunked origins, retires unread connections and respects HEAD")

                configure(api, {"noop.Modifier": {}})
                status, _, body = request(port)
                assert status == 200 and body == b"origin contacted" and not errors(api)
                checks.append("canonical no-op preserves ordinary forwarding")

                configure(api, {"fifo.Group": {"modifiers": [
                    {"header.Modifier": {"scope": ["response"], "name": "X-Generation", "value": "old"}},
                    {"status.Verifier": {"statusCode": 200}}
                ]}})
                result = []
                worker = threading.Thread(target=lambda: result.append(request(port, "/held")))
                worker.start()
                assert origin.arrived.wait(5), "request did not reach held origin"
                configure(api, {"fifo.Group": {"modifiers": [
                    {"status.Modifier": {"statusCode": 201}}, {"status.Verifier": {"statusCode": 201}}
                ]}})
                origin.release.set()
                worker.join(timeout=5)
                assert result and result[0][0] == 200 and result[0][1]["X-Generation"] == "old"
                assert request(port)[0] == 201 and not errors(api)
                checks.append("configuration replacement keeps in-flight responses on their original tree and verifier store")
        finally:
            origin.shutdown()
            origin.server_close()
    for check in checks:
        print("PASS", check)
    print(f"{len(checks)} mocking/verifier checks passed")


if __name__ == "__main__":
    main()
