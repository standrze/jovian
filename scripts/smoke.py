#!/usr/bin/env python3
"""Verify standalone jovian HTTP forwarding, HAR capture, and its local admin API."""

import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        body = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def har_targets(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return [entry["request"]["url"] for entry in data["log"]["entries"]]


def wait_for_har(path, expected):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if path.exists() and har_targets(path) == expected:
            return
        time.sleep(.05)
    actual = har_targets(path) if path.exists() else "missing"
    raise AssertionError(f"HAR entries at {path}: {actual}")


def request(proxy_port, fixture_port, path):
    target = f"http://127.0.0.1:{fixture_port}{path}"
    connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=3)
    try:
        connection.request("GET", target, headers={"Connection": "close"})
        response = connection.getresponse()
        assert response.status == 200
        assert response.read() == path.encode()
    finally:
        connection.close()
    return target


def admin_json(port, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        assert response.status == 200
        return json.loads(response.read())
    finally:
        connection.close()


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_listener(process, port):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"jovian exited: {process.returncode}\n{process.stderr.read().decode(errors='replace')}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError(f"jovian did not listen on {port}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binary", nargs="?", type=Path,
        default=Path(__file__).resolve().parents[1] / ".build/debug/jovian")
    binary = parser.parse_args().binary.resolve()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="jovian-smoke-") as temporary:
            root = Path(temporary)
            capture = root / "capture" / "traffic.har"
            proxy_port = available_port()
            admin_port = available_port()
            while admin_port == proxy_port:
                admin_port = available_port()
            process = subprocess.Popen(
                [str(binary), "serve", "--host", "127.0.0.1", "--port", str(proxy_port),
                 "--api-host", "127.0.0.1", "--api-port", str(admin_port), "--har", str(capture)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, cwd=root)
            try:
                wait_for_listener(process, proxy_port)
                wait_for_listener(process, admin_port)
                health = admin_json(admin_port, "/health")
                assert health["status"] == "ok"
                assert health["harEntries"] == 0
                print("PASS jovian local admin health is ready")

                target = request(proxy_port, server.server_port, "/fixture")
                wait_for_har(capture, [target])
                print("PASS jovian forwards local HTTP and saves HAR to the chosen path")

                health = admin_json(admin_port, "/health")
                assert health["status"] == "ok"
                assert health["harEntries"] == 1
                logs = admin_json(admin_port, "/logs")
                assert [entry["request"]["url"] for entry in logs["log"]["entries"]] == [target]
                print("PASS jovian admin API exposes the captured HAR entry")
            finally:
                stop(process)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
