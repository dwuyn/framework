from __future__ import annotations

import http.client
import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from src.pipeline import gateway_relay


class _GatewayHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        body = json.dumps({"echo": payload}, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def test_relay_forwards_only_generate_to_unix_socket(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_relay.os, "geteuid", lambda: 1000)
    socket_path = tmp_path / "gateway.sock"
    backend = _UnixServer(str(socket_path), _GatewayHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    relay = gateway_relay.serve_relay(host="127.0.0.1", port=0, socket_path=str(socket_path))
    relay_thread = threading.Thread(target=relay.serve_forever, daemon=True)
    relay_thread.start()
    try:
        client = http.client.HTTPConnection("127.0.0.1", relay.server_address[1])
        client.request("POST", "/v1/generate", body=b'{"x": 1}', headers={"Content-Type": "application/json"})
        response = client.getresponse()
        assert response.status == 200
        assert json.loads(response.read()) == {"echo": {"x": 1}}
        client.close()
    finally:
        relay.shutdown()
        relay.server_close()
        backend.shutdown()
        backend.server_close()
