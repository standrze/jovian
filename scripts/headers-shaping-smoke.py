#!/usr/bin/env python3
"""Real HTTP checks for canonical header operations and traffic-shaping policy.

--live adds an interrupted intercepted HTTPS transfer against a trusted origin.
"""
import argparse
import base64
import concurrent.futures
import contextlib
import http.client
import json
import os
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PAYLOAD = bytes(range(256)) * 32


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass  # Deliberately interrupted responses retire their origin socket.

    def do_GET(self):
        path = urlsplit(self.path).path
        body = json.dumps(list(self.headers.items())).encode() if path == "/headers" else PAYLOAD
        status = 200
        if path == "/range":
            body = body[1024:2048]
            status = 206
        self.send_response(status)
        self.send_header("X-From", "response-first")
        self.send_header("X-From", "response-second")
        self.send_header("X-Remove", "response-secret")
        self.send_header("X-Seen-ID", self.headers.get("X-Martian-ID", ""))
        if path == "/range":
            self.send_header("Content-Range", f"bytes 1024-2047/{len(PAYLOAD)}")
        if path == "/chunked":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(f"{len(body):x};fixture=yes\r\n".encode() + body + b"\r\n0\r\nX-Trailer: kept\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(16384):
            self.request.sendall(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jovian", default=".build/debug/jovian")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    jovian = str(pathlib.Path(args.jovian).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix="jovian-shaping-") as directory:
        root = pathlib.Path(directory)
        env = dict(os.environ, JOVIAN_SESSIONS_DIR=str(root / "sessions"))
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        echo.daemon_threads = True
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{origin.server_port}"

        def api_call(api, method, path, value=None):
            connection = http.client.HTTPConnection("127.0.0.1", api, timeout=5)
            connection.request(method, path, None if value is None else json.dumps(value),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read()
            connection.close()
            return response.status, json.loads(body) if body.startswith(b"{") else body

        def configure(api, value):
            result = api_call(api, "POST", "/configure", value)
            assert result[0] == 200, result

        def shape(api, rules=None, defaults=None):
            value = {"trafficshape": {"shapes": rules or [], "default": defaults or {}}}
            status, echoed = api_call(api, "POST", "/shape-traffic", value)
            assert status == 200 and echoed == value, (status, echoed)
            return value

        @contextlib.contextmanager
        def serve(*extra):
            port, api = free_port(), free_port()
            process = subprocess.Popen([jovian, "serve", "--port", str(port), "--api-port", str(api), *extra],
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

        def fetch(port, path="/file", headers=None, method="GET", body=None, connection=None):
            own = connection is None
            connection = connection or http.client.HTTPConnection("127.0.0.1", port, timeout=12)
            started = time.monotonic()
            connection.request(method, base + path, body=body, headers=headers or {})
            response = connection.getresponse()
            partial = False
            pieces = []
            try:
                while piece := response.read1(16384):
                    pieces.append(piece)
                partial = response.length is not None and response.length > 0
            except http.client.IncompleteRead as error:
                pieces.append(error.partial)
                partial = True
            content = b"".join(pieces)
            result = response.status, response.getheaders(), content, partial, time.monotonic() - started
            if own:
                connection.close()
            return result

        try:
            with serve() as (port, api):
                configure(api, {"fifo.Group": {"modifiers": [
                    {"header.Append": {"name": "X-From", "value": "appended"}},
                    {"header.Copy": {"from": "X-From", "to": "X-To"}},
                    {"header.Blacklist": {"names": ["x-remove"]}}, {"header.Id": {}}
                ]}})
                status, fields, body, partial, _ = fetch(port, "/headers", {"X-From": "request-first", "X-Remove": "secret"})
                headers = json.loads(body)
                assert status == 200 and not partial
                assert [v for k, v in headers if k.lower() == "x-from"] == ["request-first", "appended"]
                assert [v for k, v in headers if k.lower() == "x-to"] == ["request-first"]
                assert not any(k.lower() == "x-remove" for k, _ in fields + headers)
                assert [v for k, v in fields if k.lower() == "x-from"] == ["response-first", "response-second", "appended"]
                assert dict(fields)["X-To"] == "response-first" and dict(fields)["X-Seen-ID"]
                checks.append("canonical append/copy/blacklist preserve ordered values and request-only ID reaches the origin")

                configure(api, {"modifier": {"type": "headerID", "echoResponse": True}})
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                first = fetch(port, connection=connection)
                second = fetch(port, connection=connection)
                supplied = fetch(port, headers={"X-Martian-ID": "caller-id"}, connection=connection)
                connection.close()
                first_id, second_id = dict(first[1])["X-Martian-ID"], dict(second[1])["X-Martian-ID"]
                assert first_id != second_id and dict(first[1])["X-Seen-ID"] == first_id
                assert dict(supplied[1])["X-Martian-ID"] == "caller-id"
                logs = api_call(api, "GET", "/logs")[1]["log"]["entries"]
                assert any(any(h["name"] == "X-Martian-ID" and h["value"] == first_id for h in row["request"]["headers"])
                           and any(h["name"] == "X-Martian-ID" and h["value"] == first_id for h in row["response"]["headers"])
                           for row in logs)
                checks.append("native response echo correlates origin, response and HAR; keep-alive IDs are distinct and supplied IDs survive")

                for path in ["/file", "/chunked"]:
                    shape(api, [{"url_regex": path + "$", "close_connections": [{"byte": 100, "count": 1}]}])
                    result = fetch(port, path)
                    assert result[0] == 200 and result[2] == PAYLOAD[:100] and result[3], (path, result[:4])
                    assert fetch(port, path)[2:4] == (PAYLOAD, False)
                    entries = api_call(api, "GET", "/logs")[1]["log"]["entries"]
                    assert any(row["response"]["status"] == 200 and row["response"]["bodySize"] == 100
                               and any(h["name"] == "X-Martian-ID" for h in row["request"]["headers"])
                               for row in entries)
                checks.append("forced close stops fixed and chunked payloads at byte 100 without appending a 502; count is consumed")

                shape(api, [{"url_regex": "/range$", "close_connections": [{"byte": 1100, "count": -1}]}])
                result = fetch(port, "/range")
                assert result[2] == PAYLOAD[1024:1100] and result[3]
                checks.append("single-range shaping uses absolute resource offsets")

                shape(api, [{"url_regex": "/file$", "halts": [{"byte": 100, "duration": 220, "count": 1}]}])
                first, second = fetch(port), fetch(port)
                assert first[2] == second[2] == PAYLOAD and first[4] >= .20 and first[4] - second[4] >= .15
                checks.append("halt resumes with exact content and its shared finite count expires")

                shape(api, [{"url_regex": "/file$", "throttles": [
                    {"bytes": "0-4096", "bandwidth": 8192}, {"bytes": "4096-", "bandwidth": 4096}
                ]}])
                result = fetch(port)
                assert result[2] == PAYLOAD and 1.35 <= result[4] < 8, result[4]
                unmatched = fetch(port, "/unmatched")
                assert unmatched[2] == PAYLOAD and unmatched[4] < .5
                checks.append("half-open adjacent byte throttles change rate; unmatched URLs bypass shape rules")

                shape(api, [{"url_regex": "/file$", "max_global_bandwidth": 8192}])
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    started = time.monotonic()
                    results = list(pool.map(lambda _: fetch(port), range(2)))
                    elapsed = time.monotonic() - started
                assert all(r[2] == PAYLOAD for r in results) and 1.8 <= elapsed < 8, elapsed
                checks.append("simultaneous transfers share max_global_bandwidth instead of each receiving the full cap")

                shape(api, [{"url_regex": "/file$", "close_connections": [{"byte": 10, "count": 1}]}])
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(lambda _: fetch(port), range(2)))
                assert sorted(len(r[2]) for r in results) == [10, len(PAYLOAD)]
                checks.append("concurrent requests atomically claim a one-shot close action")

                shape(api, defaults={"bandwidth": {"up": 8192, "down": 0}})
                result = fetch(port, method="POST", body=PAYLOAD)
                assert result[2] == PAYLOAD and .9 <= result[4] < 8, result[4]
                shape(api, defaults={"bandwidth": {"down": 8192}})
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    started = time.monotonic()
                    results = list(pool.map(lambda _: fetch(port, "/unmatched"), range(2)))
                    elapsed = time.monotonic() - started
                assert all(r[2] == PAYLOAD for r in results) and 1.8 <= elapsed < 8, elapsed
                checks.append("default upload and aggregate download budgets apply independently of URL matching")

                shape(api, defaults={"latency": 150})
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                first, second = fetch(port, connection=connection), fetch(port, connection=connection)
                connection.close()
                assert first[4] >= .28 and second[4] < .15, (first[4], second[4])
                checks.append("default latency applies once per read/write direction, not on each keep-alive request")

                active = shape(api, [{"url_regex": "/file$", "close_connections": [{"byte": 100, "count": -1}]}])
                assert api_call(api, "POST", "/shape-traffic", {"trafficshape": {"shapes": [{"url_regex": "["}]}})[0] == 400
                assert api_call(api, "GET", "/shape-traffic")[1] == active
                assert fetch(port)[2] == PAYLOAD[:100]
                shape(api)
                assert fetch(port)[2:4] == (PAYLOAD, False)
                assert dict(fetch(port)[1])["X-Martian-ID"]
                checks.append("rejected policy remains inactive; reset removes shaping without resetting header rules")

                (root / "fixture.bin").write_bytes(PAYLOAD)
                configure(api, {"static.Modifier": {"rootPath": str(root), "explicitPaths": {"/static": "fixture.bin"}}})
                shape(api, [{"url_regex": "/static$", "close_connections": [{"byte": 4, "count": -1}]}])
                assert fetch(port, "/static")[2:4] == (PAYLOAD[:4], True)
                entries = api_call(api, "GET", "/logs")[1]["log"]["entries"]
                assert any(row["request"]["url"].endswith("/static") and row["response"]["status"] == 200 and row["response"]["bodySize"] == 4 for row in entries)
                checks.append("URL shaping also applies to local synthetic static responses")

                configure(api, {"noop.Modifier": {}})
                shape(api, defaults={"bandwidth": {"down": 4096}})
                with socket.create_connection(("127.0.0.1", port), timeout=8) as sock:
                    sock.sendall(f"CONNECT 127.0.0.1:{echo.server_address[1]} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
                    head = bytearray()
                    while not head.endswith(b"\r\n\r\n"):
                        head += sock.recv(1)
                    assert head.startswith(b"HTTP/1.1 200")
                    started = time.monotonic()
                    sock.sendall(PAYLOAD)
                    received = bytearray()
                    while len(received) < len(PAYLOAD):
                        received += sock.recv(len(PAYLOAD) - len(received))
                    assert received == PAYLOAD and time.monotonic() - started >= 1.8
                checks.append("opaque CONNECT tunnels retain default transport shaping")

            if args.live:
                ca = root / "ca"
                subprocess.run([jovian, "ca", "create", "--directory", str(ca)], env=env,
                               capture_output=True, check=True, timeout=15)
                with serve("--intercept-ca", str(ca)) as (port, api):
                    shape(api, [{"url_regex": "^https://example\\.com(?::443)?/", "close_connections": [{"byte": 16, "count": 1}]}])
                    result = subprocess.run(["curl", "--silent", "--show-error", "--max-time", "20", "--http1.1",
                                             "--noproxy", "", "--proxy", f"http://127.0.0.1:{port}",
                                             "--cacert", str(ca / "ca-cert.pem"), "https://example.com/"],
                                            capture_output=True, timeout=25)
                    assert result.returncode == 18 and len(result.stdout) == 16, (result.returncode, result.stderr, result.stdout)
                    checks.append("intercepted trusted HTTPS closes at the configured plaintext-body offset")
        finally:
            origin.shutdown()
            origin.server_close()
            echo.shutdown()
            echo.server_close()
    for check in checks:
        print("PASS", check)
    print(f"{len(checks)} header/shaping checks passed")


if __name__ == "__main__":
    main()
