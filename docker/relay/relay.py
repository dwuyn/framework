"""Minimal dependency-free gateway relay shipped in the relay image."""

from __future__ import annotations

import http.client
import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOCKET = "/run/veriplanpt-gateway/gateway.sock"


class UnixConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(SOCKET)
        self.sock = sock


class Handler(BaseHTTPRequestHandler):
    _ALLOWED = {"/v1/generate", "/v1/models", "/v1/chat/completions"}

    def _proxy(self, method: str) -> None:
        if self.path not in self._ALLOWED:
            self.send_error(404)
            return
        try:
            body = b""
            if method == "POST":
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 1_048_576:
                    raise ValueError("invalid request size")
                body = self.rfile.read(length)
                json.loads(body.decode("utf-8"))
            headers = {"Content-Type": self.headers.get("Content-Type", "application/json")}
            if self.headers.get("Authorization"):
                headers["Authorization"] = self.headers["Authorization"]
            connection = UnixConnection("localhost", timeout=30)
            try:
                connection.request(method, self.path, body=body, headers=headers)
                response = connection.getresponse()
                self.send_response(response.status)
                content_type = response.getheader("Content-Type", "application/json")
                self.send_header("Content-Type", content_type)
                content_length = response.getheader("Content-Length")
                if content_length is not None:
                    self.send_header("Content-Length", content_length)
                else:
                    self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = response.read(16 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            finally:
                connection.close()
        except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(502)

    def do_GET(self) -> None:  # noqa: N802
        self._proxy("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._proxy("POST")

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    if os.geteuid() == 0:
        raise SystemExit("gateway relay refuses root")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
