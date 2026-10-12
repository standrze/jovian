#!/usr/bin/env python3
"""Local wire checks for chaining, rewrites, filters, credentials, and TLS rejection.

Use --live to additionally check intercepted HTTPS against a publicly trusted origin.
All certificates, sessions, and captures are isolated in a temporary directory.
"""
import argparse
import base64
import contextlib
import http.client
import json
import os
import pathlib
import select
import socket
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


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)
        body = json.dumps({"path": self.path, "headers": dict(self.headers)}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "mode=fixture; Path=/")
        self.end_headers()
        self.wfile.write(body)


class NextProxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def authorized(self):
        self.server.hits.append((self.command, self.path, self.headers.get("Proxy-Authorization")))
        self.server.channels.append(self.client_address)
        if self.headers.get("Proxy-Authorization") != self.server.authorization:
            self.send_response(407)
            self.send_header("Proxy-Authenticate", 'Basic realm="fixture"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        target = urlsplit(self.path)
        assert target.scheme == "http" and target.hostname, self.path
        host = "127.0.0.1" if target.hostname.endswith(".invalid") else target.hostname
        connection = http.client.HTTPConnection(host, target.port or 80, timeout=5)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("proxy-authorization", "connection")}
        headers["Connection"] = "close"
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        self.send_response(response.status)
        for name, value in response.getheaders():
            if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        connection.close()

    def do_CONNECT(self):
        if not self.authorized():
            return
        target = urlsplit("https://" + self.path)
        if target.hostname == "denied.invalid":
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if target.hostname == "greeting.invalid":
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\nhello")
            self.close_connection = True
            return
        remote = socket.create_connection((target.hostname, target.port), timeout=5)
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True
        peers = [self.connection, remote]
        try:
            while peers:
                ready, _, _ = select.select(peers, [], [], 10)
                if not ready:
                    break
                for source in ready:
                    destination = remote if source is self.connection else self.connection
                    data = source.recv(16384)
                    if not data:
                        peers.remove(source)
                        destination.shutdown(socket.SHUT_WR)
                    else:
                        destination.sendall(data)
        except (ConnectionError, OSError):
            pass  # TLS rejection or either peer closing ends a tunnel normally.
        finally:
            remote.close()


@contextlib.contextmanager
def fixture(handler, tls=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    server.hits = []
    server.channels = []
    server.authorization = "Basic " + base64.b64encode(b"next:next-secret").decode()
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jovian", default=".build/debug/jovian")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    jovian = str(pathlib.Path(args.jovian).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix="jovian-routing-") as directory, contextlib.ExitStack() as stack:
        root = pathlib.Path(directory)
        env = dict(os.environ, JOVIAN_SESSIONS_DIR=str(root / "sessions"), NEXT_PROXY_PASSWORD="next-secret")

        def command(*arguments):
            return subprocess.run([jovian, *arguments], env=env, capture_output=True, text=True, check=True, timeout=15)

        ca = root / "ca"
        command("ca", "create", "--directory", str(ca))
        command("ca", "issue", "localhost", "--directory", str(ca))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(ca / "hosts/localhost/cert.pem", ca / "hosts/localhost/key.pem")
        origin = stack.enter_context(fixture(Origin))
        secure_origin = stack.enter_context(fixture(Origin, tls))
        next_proxy = stack.enter_context(fixture(NextProxy))
        upstream = f"http://127.0.0.1:{next_proxy.server_port}"
        base = f"http://127.0.0.1:{origin.server_port}"

        @contextlib.contextmanager
        def serve(*extra, chain=True):
            port, api = free_port(), free_port()
            arguments = [jovian, "serve", "--port", str(port), "--api-port", str(api)]
            if chain:
                arguments += ["--upstream-proxy", upstream, "--upstream-proxy-user", "next",
                              "--upstream-proxy-password-env", "NEXT_PROXY_PASSWORD"]
            process = subprocess.Popen(arguments + list(extra), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise AssertionError(process.stderr.read().decode())
                    try:
                        connection = http.client.HTTPConnection("127.0.0.1", api, timeout=.2)
                        connection.request("GET", "/health")
                        response = connection.getresponse()
                        response.read()
                        connection.close()
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

        def api_call(api, method, path, data=None):
            connection = http.client.HTTPConnection("127.0.0.1", api, timeout=5)
            connection.request(method, path, None if data is None else json.dumps(data), {"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read()
            connection.close()
            return response.status, json.loads(body) if body.startswith((b"{", b"[")) else body.decode()

        def get(port, target, headers=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("GET", target, headers=headers or {})
            response = connection.getresponse()
            status, response_headers, body = response.status, dict(response.getheaders()), response.read()
            connection.close()
            return status, response_headers, body

        with serve("--capture-sensitive-headers") as (port, api):
            # This name cannot resolve locally. Only the next-hop fixture maps it.
            target = f"http://origin.invalid:{origin.server_port}/via-next"
            status, _, body = get(port, target, {"Proxy-Authorization": "Basic client-secret"})
            assert status == 200 and json.loads(body)["path"] == "/via-next"
            assert "Proxy-Authorization" not in json.loads(body)["headers"]
            assert next_proxy.hits[-1] == ("GET", target, next_proxy.authorization)
            _, capture = api_call(api, "GET", "/logs")
            assert "next-secret" not in json.dumps(capture) and next_proxy.authorization not in json.dumps(capture)
            checks.append("HTTP absolute-form forwarding, next-hop DNS, credential isolation")

            assert get(port, target + "-again")[0] == 200
            assert next_proxy.channels[-1] == next_proxy.channels[-2]
            assert get(port, f"http://other.invalid:{origin.server_port}/separate-origin")[0] == 200
            assert next_proxy.channels[-1] != next_proxy.channels[-2]
            checks.append("HTTP pool reuses the same route and separates final origins")

            configure = {"fifo.Group": {"modifiers": [
                {"url.Filter": {"scope": ["request"], "path": "/rewrite", "modifier": {
                    "url.Modifier": {"host": "origin.invalid", "path": "/changed", "query": "q=a%2Fb"}}}},
                {"port.Modifier": {"port": origin.server_port}}
            ]}}
            assert api_call(api, "POST", "/configure", configure)[0] == 200
            status, _, body = get(port, base + "/rewrite", {"Authorization": "Bearer original", "Cookie": "session=original"})
            result = json.loads(body)
            assert status == 200 and result["path"] == "/changed?q=a%2Fb"
            assert result["headers"]["Host"] == f"origin.invalid:{origin.server_port}"
            assert "Authorization" not in result["headers"] and "Cookie" not in result["headers"]
            checks.append("URL/port rewrite chooses final route and strips unchanged cross-origin credentials")

            for rule in [
                {"header.Filter": {"name": "X-Mode", "value": "yes"}},
                {"querystring.Filter": {"name": "mode", "value": "yes"}},
                {"cookie.Filter": {"name": "mode", "value": "yes"}},
                {"url.RegexFilter": {"regex": "/filters\\?mode=yes$"}}
            ]:
                fields = next(iter(rule.values()))
                fields.update({"scope": ["request"],
                               "modifier": {"header.Modifier": {"name": "X-Branch", "value": "true"}},
                               "else": {"header.Modifier": {"name": "X-Branch", "value": "false"}}})
                assert api_call(api, "POST", "/configure", rule)[0] == 200
                for match in (True, False):
                    target = base + ("/filters?mode=yes" if match else "/other")
                    headers = {"X-Mode": "yes", "Cookie": "mode=yes"} if match else {}
                    status, _, body = get(port, target, headers)
                    assert status == 200 and json.loads(body)["headers"]["X-Branch"] == str(match).lower()
            checks.append("header/query/cookie/regex true and else branches over real HTTP")

            assert api_call(api, "POST", "/configure", {"header.RegexFilter": {
                "scope": ["request"], "header": "X-Long", "regex": "(a+)+$",
                "modifier": {"header.Modifier": {"name": "X-Should-Not-Send", "value": "yes"}}
            }})[0] == 200
            before = len(next_proxy.hits)
            assert get(port, base + "/timeout", {"X-Long": "a" * 20000 + "!"})[0] == 502
            assert len(next_proxy.hits) == before
            checks.append("regex timeout fails before origin connection")

            assert api_call(api, "POST", "/configure", {})[0] == 200
            # Actual HTTPS through an opaque, authenticated CONNECT tunnel.
            result = subprocess.run(["curl", "--silent", "--show-error", "--max-time", "10", "--noproxy", "",
                                     "--proxy", f"http://127.0.0.1:{port}", "--cacert", str(ca / "ca-cert.pem"),
                                     f"https://localhost:{secure_origin.server_port}/tunnel"], capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)["path"] == "/tunnel"
            assert any(hit[:2] == ("CONNECT", f"localhost:{secure_origin.server_port}") for hit in next_proxy.hits)
            checks.append("HTTPS CONNECT through authenticated next hop")
            connection = socket.create_connection(("127.0.0.1", port), timeout=5)
            connection.sendall(b"CONNECT denied.invalid:443 HTTP/1.1\r\nHost: denied.invalid:443\r\n\r\n")
            assert connection.recv(4096).startswith(b"HTTP/1.1 403")
            connection.close()
            checks.append("next-hop CONNECT rejection has no direct fallback")

            connection = socket.create_connection(("127.0.0.1", port), timeout=5)
            target = f"127.0.0.1:{origin.server_port}"
            connection.sendall((f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
                                f"GET /coalesced-client HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").encode())
            received = b""
            while data := connection.recv(16384):
                received += data
            connection.close()
            assert received.startswith(b"HTTP/1.1 200 ") and b"/coalesced-client" in received, received
            connection = socket.create_connection(("127.0.0.1", port), timeout=5)
            connection.sendall(b"CONNECT greeting.invalid:443 HTTP/1.1\r\nHost: greeting.invalid:443\r\n\r\n")
            received = b""
            while data := connection.recv(16384):
                received += data
            connection.close()
            assert received.endswith(b"hello"), received
            checks.append("CONNECT preserves coalesced payload bytes in both directions")

        with serve("--intercept-ca", str(ca)) as (port, api):
            before = len(secure_origin.hits)
            result = subprocess.run(["curl", "--silent", "--show-error", "--max-time", "10", "--noproxy", "",
                                     "--proxy", f"http://127.0.0.1:{port}", "--cacert", str(ca / "ca-cert.pem"),
                                     f"https://localhost:{secure_origin.server_port}/untrusted"], capture_output=True, text=True)
            assert result.returncode == 0 and result.stdout == "Bad Gateway", (result.stdout, result.stderr)
            assert len(secure_origin.hits) == before
            checks.append("intercepted chained TLS rejects untrusted origin before application data")
            if args.live:
                result = subprocess.run(["curl", "--silent", "--show-error", "--max-time", "30", "--noproxy", "",
                                         "--proxy", f"http://127.0.0.1:{port}", "--cacert", str(ca / "ca-cert.pem"),
                                         "https://example.com/"], capture_output=True, text=True)
                assert result.returncode == 0 and "Example Domain" in result.stdout, (result.stdout, result.stderr)
                checks.append("live intercepted chained TLS validates example.com with macOS trust")
                assert api_call(api, "POST", "/configure", {"url.Modifier": {
                    "scheme": "https", "host": "example.com", "path": "/"
                }})[0] == 200
                status, _, body = get(port, "http://unresolvable.invalid/scheme-rewrite")
                assert status == 200 and b"Example Domain" in body
                checks.append("live HTTP-to-HTTPS rewrite selects a validated chained TLS route")

        command("sessions", "new", "scoped", "--origin", base)
        with serve("--session", "scoped") as (port, api):
            assert get(port, "http://martian.proxy/health")[0] == 200
            assert api_call(api, "POST", "/configure", {"url.Modifier": {"host": f"other.invalid:{origin.server_port}"}})[0] == 200
            before = len(next_proxy.hits)
            assert get(port, base + "/out-of-scope")[0] == 403
            assert len(next_proxy.hits) == before
            checks.append("rewrites cannot escape session origin through a chained proxy")

        with serve(chain=False) as (port, api):
            assert api_call(api, "POST", "/configure", {"fifo.Group": {"modifiers": [
                {"url.Modifier": {"host": "127.0.0.1", "path": "/direct-rewrite"}},
                {"port.Modifier": {"port": origin.server_port}}
            ]}})[0] == 200
            status, _, body = get(port, "http://unresolvable.invalid/original")
            assert status == 200 and json.loads(body)["path"] == "/direct-rewrite"
            checks.append("direct route uses rewritten host and port before DNS")

        with serve("--upstream-proxy", f"http://127.0.0.1:{free_port()}", chain=False) as (port, _):
            before = len(origin.hits)
            assert get(port, base + "/must-not-fallback")[0] == 502
            assert len(origin.hits) == before
            checks.append("next-hop TCP failure never bypasses the proxy")

        with serve("--upstream-proxy-user", "wrong") as (port, _):
            before = len(origin.hits)
            assert get(port, base + "/proxy-auth-failure")[0] == 407
            assert len(origin.hits) == before
            checks.append("next-hop authentication failure never reaches the origin")

    print(json.dumps({"passed": True, "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
