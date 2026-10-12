#!/usr/bin/env python3
"""HTTPS and SOCKS5 next-hop wire tests. No system trust changes; all fixtures are isolated.

--live also verifies origin TLS through each next hop against example.com.
"""
import argparse
import base64
import contextlib
import http.client
import hashlib
import json
from http.server import ThreadingHTTPServer
import os
import pathlib
import select
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

from importlib.util import spec_from_file_location, module_from_spec

_spec = spec_from_file_location("routing_fixture", pathlib.Path(__file__).with_name("routing-smoke.py"))
routing = module_from_spec(_spec)
_spec.loader.exec_module(routing)


def exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("closed during fixture handshake")
        data += chunk
    return data


def pump(left, right):
    peers = [left, right]
    try:
        while peers:
            ready = [peer for peer in peers if isinstance(peer, ssl.SSLSocket) and peer.pending()]
            if not ready:
                ready, _, _ = select.select(peers, [], [], 5)
            if not ready:
                return
            for source in ready:
                target = right if source is left else left
                data = source.recv(16384)
                if not data:
                    peers.remove(source)
                    target.shutdown(socket.SHUT_WR)
                else:
                    target.sendall(data)
    except (ConnectionError, OSError):
        pass


class Origin(routing.Origin):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        result = json.dumps({"sha256": hashlib.sha256(body).hexdigest(), "headers": dict(self.headers)}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


class IPv6HTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


@contextlib.contextmanager
def ipv6_fixture():
    server = IPv6HTTPServer(("::1", 0), Origin)
    server.daemon_threads = True
    server.hits = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


class HTTPSProxy(routing.NextProxy):
    def do_POST(self):
        if not self.authorized():
            return
        target = urlsplit(self.path)
        host = "127.0.0.1" if target.hostname.endswith(".invalid") else target.hostname
        body = self.rfile.read(int(self.headers["Content-Length"]))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("proxy-authorization", "connection")}
        connection = http.client.HTTPConnection(host, target.port or 80, timeout=5)
        connection.request("POST", target.path, body, headers)
        response = connection.getresponse()
        result = response.read()
        self.send_response(response.status)
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)
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
            self.connection.sendall(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nhello")
            self.close_connection = True
            return
        host = "127.0.0.1" if target.hostname.endswith(".invalid") else target.hostname
        with socket.create_connection((host, target.port), timeout=5) as remote:
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True
            pump(self.connection, remote)


class HalfCloseEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        self.request.settimeout(5)
        while True:
            chunk = self.request.recv(65536)
            if not chunk:
                break
            data += chunk
        self.request.sendall(b"after-eof:" + hashlib.sha256(data).hexdigest().encode())


@contextlib.contextmanager
def echo_fixture():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), HalfCloseEcho)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


class SOCKSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(8)
        try:
            version, count = exact(sock, 2)
            methods = exact(sock, count)
            self.server.greeted.set()
            if self.server.mode == "stall":
                while sock.recv(1):
                    pass
                return
            required = 2 if self.server.auth else 0
            if self.server.mode == "downgrade":
                sock.sendall(b"\x05\x00")
                return
            if version != 5 or required not in methods:
                sock.sendall(b"\x05\xff")
                return
            # Deliberately fragment every negotiation reply.
            sock.sendall(b"\x05")
            sock.sendall(bytes([required]))
            if required == 2:
                version = exact(sock, 1)[0]
                user = exact(sock, exact(sock, 1)[0])
                password = exact(sock, exact(sock, 1)[0])
                valid = version == 1 and user == b"next" and password == b"next-secret"
                sock.sendall(bytes([1, 0 if valid else 1]))
                if not valid:
                    return
            version, command, reserved, kind = exact(sock, 4)
            assert (version, command, reserved) == (5, 1, 0)
            if kind == 1:
                host = socket.inet_ntop(socket.AF_INET, exact(sock, 4))
            elif kind == 4:
                host = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
            else:
                assert kind == 3
                host = exact(sock, exact(sock, 1)[0]).decode()
            port = int.from_bytes(exact(sock, 2), "big")
            self.server.hits.append((kind, host, port))
            if self.server.mode == "truncated":
                sock.sendall(b"\x05\x00\x00\x01\x7f")
                return
            if self.server.mode == "bad-version":
                sock.sendall(b"\x04\x00\x00\x01")
                return
            if self.server.mode == "bad-reserved":
                sock.sendall(b"\x05\x00\x01\x01")
                return
            if self.server.mode == "bad-address":
                sock.sendall(b"\x05\x00\x00\x02")
                return
            if host == "denied.invalid":
                sock.sendall(b"\x05\x05\x00\x01")
                return
            # Domain bound address tests variable-length response parsing.
            reply = b"\x05\x00\x00\x03\x03abc\x12\x34"
            if host == "greeting.invalid":
                sock.sendall(reply + b"hello")
                return
            destination = "127.0.0.1" if host.endswith(".invalid") else host
            with socket.create_connection((destination, port), timeout=5) as remote:
                for byte in reply:
                    sock.sendall(bytes([byte]))
                pump(sock, remote)
        except (ConnectionError, OSError, EOFError):
            pass


@contextlib.contextmanager
def socks_fixture(auth=False, mode="normal"):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SOCKSProxy)
    server.daemon_threads = True
    server.auth = auth
    server.mode = mode
    server.hits = []
    server.greeted = threading.Event()
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
    with tempfile.TemporaryDirectory(prefix="jovian-upstream-") as directory, contextlib.ExitStack() as stack:
        root = pathlib.Path(directory)
        env = dict(os.environ, JOVIAN_SESSIONS_DIR=str(root / "sessions"), NEXT_PROXY_PASSWORD="next-secret",
                   WRONG_PROXY_PASSWORD="wrong-password")
        ca = root / "ca"
        for arguments in [("ca", "create", "--directory", str(ca)), ("ca", "issue", "localhost", "--directory", str(ca))]:
            subprocess.run([jovian, *arguments], env=env, check=True, capture_output=True, timeout=15)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(ca / "hosts/localhost/cert.pem", ca / "hosts/localhost/key.pem")
        client_tls = ssl.create_default_context(cafile=str(ca / "ca-cert.pem"))
        echo = stack.enter_context(echo_fixture())
        origin = stack.enter_context(routing.fixture(Origin))
        ipv6_origin = stack.enter_context(ipv6_fixture())
        secure_origin = stack.enter_context(routing.fixture(Origin, server_tls))
        https = stack.enter_context(routing.fixture(HTTPSProxy, server_tls))
        socks = stack.enter_context(socks_fixture())
        auth_socks = stack.enter_context(socks_fixture(auth=True))
        https_url = f"https://localhost:{https.server_port}"
        socks_url = f"socks5://127.0.0.1:{socks.server_address[1]}"
        auth_url = f"socks5h://127.0.0.1:{auth_socks.server_address[1]}"
        base = f"http://fixture.invalid:{origin.server_port}"
        counter = 0

        @contextlib.contextmanager
        def serve(url, auth=False, ca_file=None, password="NEXT_PROXY_PASSWORD", extra=()):
            nonlocal counter
            counter += 1
            port, api = routing.free_port(), routing.free_port()
            log = root / f"traffic-{counter}.jsonl"
            arguments = [jovian, "serve", "--port", str(port), "--api-port", str(api), "--upstream-proxy", url,
                         "--log", str(log), "--capture-sensitive-headers", "--shutdown-grace-ms", "100"]
            if auth:
                arguments += ["--upstream-proxy-user", "next", "--upstream-proxy-password-env", password]
            if ca_file:
                arguments += ["--upstream-proxy-ca", str(ca_file)]
            process = subprocess.Popen(arguments + list(extra), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                for _ in range(150):
                    if process.poll() is not None:
                        raise AssertionError(process.stderr.read().decode())
                    try:
                        with socket.create_connection(("127.0.0.1", api), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    raise AssertionError("proxy did not start")
                yield port, api, process, log
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=4)
                process.stderr.close()

        def request(port, target, method="GET", body=None, headers=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
            connection.request(method, target, body=body, headers=headers or {})
            response = connection.getresponse()
            result = response.status, response.read()
            connection.close()
            return result

        def api_call(api, method, path, data=None):
            return request(api, path, method, None if data is None else json.dumps(data), {"Content-Type": "application/json"})

        @contextlib.contextmanager
        def tunnel(port, target):
            sock = socket.create_connection(("127.0.0.1", port), timeout=8)
            try:
                sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                head = b""
                while not head.endswith(b"\r\n\r\n"):
                    head += exact(sock, 1)
                assert head.startswith(b"HTTP/1.1 200"), head
                yield sock
            finally:
                sock.close()

        roots = ca / "ca-cert.pem"
        transports = [(https_url, True, roots, https), (socks_url, False, None, socks), (auth_url, True, None, auth_socks)]
        for url, auth, ca_file, fixture in transports:
            name = urlsplit(url).scheme
            with serve(url, auth, ca_file) as (port, api, process, log):
                start_hits = len(fixture.hits)
                # A persistent client makes request two start after the first exchange
                # has returned its upstream connection, avoiding a cross-client timing race.
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
                try:
                    for path in ["/first", "/second"]:
                        connection.request("GET", base + path, headers={"Proxy-Authorization": "Basic client-secret"})
                        response = connection.getresponse()
                        status, body = response.status, response.read()
                        assert status == 200, (name, status, body)
                        data = json.loads(body)
                        assert data["path"] == path, data
                        assert "Proxy-Authorization" not in data["headers"], data
                        assert "next-secret" not in body.decode(), body
                finally:
                    connection.close()
                if name.startswith("socks"):
                    assert len(fixture.hits) - start_hits == 1, fixture.hits  # pooled origin connection
                    assert fixture.hits[-1] == (3, "fixture.invalid", origin.server_port), fixture.hits
                checks.append(name + " HTTP forwarding, pooling, remote DNS, and credential separation")

                payload = b"streamed-upload-" * (384 * 1024)
                status, body = request(port, base + "/upload", "POST", payload)
                assert status == 200 and json.loads(body)["sha256"] == hashlib.sha256(payload).hexdigest(), (name, status)
                assert "Proxy-Authorization" not in json.loads(body)["headers"]
                checks.append(name + " large streamed upload preserves payload")
                if name.startswith("socks"):
                    for host, expected_type, server_port in [("127.0.0.1", 1, origin.server_port), ("[::1]", 4, ipv6_origin.server_port)]:
                        status, body = request(port, f"http://{host}:{server_port}/ip-literal")
                        assert status == 200, (name, host, status, body)
                        assert fixture.hits[-1][0] == expected_type, fixture.hits
                    checks.append(name + " IPv4 and IPv6 destination addresses")

                with tunnel(port, f"localhost:{secure_origin.server_port}") as raw:
                    with client_tls.wrap_socket(raw, server_hostname="localhost") as secure:
                        secure.sendall(b"GET /opaque HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        response = http.client.HTTPResponse(secure)
                        response.begin()
                        assert response.status == 200 and json.loads(response.read())["path"] == "/opaque"
                checks.append(name + " opaque TLS CONNECT")

                with tunnel(port, "greeting.invalid:443") as raw:
                    assert exact(raw, 5) == b"hello"
                checks.append(name + " CONNECT preserves early bytes")
                with tunnel(port, f"127.0.0.1:{echo.server_address[1]}") as raw:
                    payload = b"half-close-payload" * 16384
                    raw.sendall(payload)
                    raw.shutdown(socket.SHUT_WR)
                    expected = b"after-eof:" + hashlib.sha256(payload).hexdigest().encode()
                    assert exact(raw, len(expected)) == expected
                checks.append(name + " CONNECT half-close preserves final response")
                status, _ = request(port, "denied.invalid:443", "CONNECT")
                assert status == (403 if url.startswith("http") else 502), status
                checks.append(name + " CONNECT denial preserves HTTP rejection or reports SOCKS failure")

                status, body = request(port, f"https://localhost:{secure_origin.server_port}/untrusted")
                assert status == 502, (status, body)
                assert "/untrusted" not in secure_origin.hits
                checks.append(name + " origin TLS trust stays independent of proxy CA")

                status, har = api_call(api, "GET", "/logs")
                assert status == 200
                for value in (har.decode(), log.read_text()):
                    assert "next-secret" not in value and "bmV4dDpuZXh0LXNlY3JldA==" not in value
                checks.append(name + " next-hop credentials excluded from HAR and logs")

                if args.live:
                    status, body = request(port, "https://example.com/")
                    assert status == 200 and b"Example Domain" in body, (name, status, body[:300])
                    checks.append(name + " trusted origin TLS, including nested HTTPS proxy TLS")

                    # Intercepted client TLS reaches the same next-hop/origin transport path.
                    rules = {"url.Modifier": {"scheme": "https", "host": "example.com", "path": "/", "query": ""}}
                    assert api_call(api, "POST", "/configure", rules)[0] == 200
                    status, body = request(port, base + "/rewrite-to-https")
                    assert status == 200 and b"Example Domain" in body, (name, status, body[:300])
                    checks.append(name + " URL rewrite to trusted HTTPS")

        # Proxy endpoint trust and hostname checks fail before any HTTP credentials reach it.
        for url in [https_url, f"https://127.0.0.1:{https.server_port}"]:
            before = len(https.hits)
            with serve(url, True, None if url == https_url else roots) as (port, *_):
                status, _ = request(port, base + "/proxy-trust-rejection")
                assert status == 502, status
            assert len(https.hits) == before
        checks.append("HTTPS proxy rejects untrusted and wrong-host certificates before authentication")

        for url, ca_file in [(https_url, roots), (auth_url, None)]:
            with serve(url, True, ca_file, password="WRONG_PROXY_PASSWORD") as (port, *_):
                status, _ = request(port, base + "/bad-auth")
                assert status == (407 if url == https_url else 502), status
        assert "/bad-auth" not in origin.hits
        checks.append("HTTPS 407 and SOCKS authentication rejection do not reach origin")

        for mode in ["downgrade", "bad-version", "bad-reserved", "bad-address", "truncated"]:
            server = stack.enter_context(socks_fixture(auth=True, mode=mode))
            with serve(f"socks5://127.0.0.1:{server.server_address[1]}", True) as (port, *_):
                status, _ = request(port, base + "/malformed-" + mode)
                assert status == 502, (mode, status)
        assert not any(path.startswith("/malformed-") for path in origin.hits)
        checks.append("SOCKS rejects authentication downgrade and malformed or truncated replies")

        for scheme in ["https", "socks5"]:
            server = stack.enter_context(socks_fixture(mode="stall"))
            with serve(f"{scheme}://127.0.0.1:{server.server_address[1]}") as (port, api, process, log):
                connection = socket.create_connection(("127.0.0.1", port), timeout=5)
                try:
                    connection.sendall(("GET " + base + "/stall HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n").encode())
                    assert server.greeted.wait(2)
                    start = time.monotonic()
                    process.terminate()
                    process.wait(timeout=2)
                    assert time.monotonic() - start < 2
                finally:
                    connection.close()
        checks.append("shutdown interrupts pending SOCKS negotiation and HTTPS handshake")

        for scheme in ["https", "socks5"]:
            with serve(f"{scheme}://127.0.0.1:{routing.free_port()}") as (port, *_):
                status, _ = request(port, f"http://127.0.0.1:{origin.server_port}/no-direct-fallback")
                assert status == 502
        assert "/no-direct-fallback" not in origin.hits
        checks.append("unavailable next hops never fall back to direct connections")

        # Validate CLI-only option combinations at startup.
        for extra in [["--upstream-proxy-ca", str(roots)], ["--upstream-proxy", socks_url, "--upstream-proxy-ca", str(roots)]]:
            result = subprocess.run([jovian, "serve", *extra], env=env, capture_output=True, timeout=3)
            assert result.returncode != 0
        checks.append("CA option rejects missing or non-HTTPS next hop")

        if args.live:
            for url, auth, ca_file, _ in transports:
                with serve(url, auth, ca_file, extra=("--intercept-ca", str(ca))) as (port, *_):
                    with tunnel(port, "example.com:443") as raw:
                        with client_tls.wrap_socket(raw, server_hostname="example.com") as secure:
                            secure.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                            response = http.client.HTTPResponse(secure)
                            response.begin()
                            assert response.status == 200 and b"Example Domain" in response.read()
                checks.append(urlsplit(url).scheme + " intercepted HTTPS through next hop")
    print(json.dumps({"passed": True, "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
