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
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/generate":
            self.send_error(404)
            return
        try:
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
                connection.request("POST", "/v1/generate", body=body, headers=headers)
                response = connection.getresponse()
                value = response.read()
                self.send_response(response.status)
            finally:
                connection.close()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(value)))
            self.end_headers()
            self.wfile.write(value)
        except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(502)

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    if os.geteuid() == 0:
        raise SystemExit("gateway relay refuses root")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
