#!/usr/bin/env python3
"""Provider-free Unix-socket gateway for actual-driver certification.

The relay image remains on the container network path.  This server is only a
deterministic test double: it accepts exactly one model request per run ID,
returns normalized usage, and records every request for the certification
receipt.  It never contacts a provider.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import socketserver
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

_TOKEN = re.compile(r"^[^~]+~[^~]+~[0-9a-f]{64}$")


class _State:
    def __init__(self, expected: int) -> None:
        self.expected = expected
        self.requests: list[dict[str, Any]] = []
        self.by_run: dict[str, int] = {}


class _Handler(BaseHTTPRequestHandler):
    state: _State

    def _json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/models":
            self._json(200, {"object": "list", "data": [{"id": "mock-live"}]})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in {"/v1/generate", "/v1/chat/completions"}:
            self._json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_048_576:
                raise ValueError("invalid content length")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("payload is not an object")
            authorization = str(self.headers.get("Authorization", ""))
            token = authorization.removeprefix("Bearer ")
            if not _TOKEN.fullmatch(token):
                raise ValueError("token must contain exactly three tilde-separated parts")
            _phase, run_id, profile_hash = token.split("~")
            if self.state.by_run.get(run_id, 0) >= 1:
                self._json(409, {"error": "duplicate_model_response", "run_id": run_id})
                return
            self.state.by_run[run_id] = self.state.by_run.get(run_id, 0) + 1
            request_number = len(self.state.requests) + 1
            request_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            record = {
                "request_number": request_number,
                "path": self.path,
                "run_id": run_id,
                "profile_hash": profile_hash,
                "request_sha256": request_hash,
            }
            self.state.requests.append(record)
            usage = {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16, "usd": 0.000001}
            if self.path == "/v1/chat/completions":
                response: dict[str, Any] = {
                    "id": f"mock-{request_number}", "object": "chat.completion",
                    "model": "mock-live",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "mock response"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16},
                }
            else:
                response = {"text": "mock response", "usage": usage, "response_status": "ok"}
            response["response_hash"] = hashlib.sha256(
                json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            self._json(200, response)
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "invalid_mock_request"})

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected", required=True, type=int)
    args = parser.parse_args()
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    if args.socket.exists():
        args.socket.unlink()
    state = _State(args.expected)
    handler = type("MockHandler", (_Handler,), {"state": state})
    server = _UnixServer(str(args.socket), handler)
    os.chmod(args.socket, 0o600)
    signal.signal(signal.SIGTERM, lambda _signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt))
    try:
        while len(state.requests) < state.expected:
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    args.evidence.write_text(json.dumps({
        "schema_version": "1.0.0", "mode": "provider-free-mock-live",
        "expected_responses": state.expected, "response_count": len(state.requests),
        "provider_calls": 0, "vertex_calls": 0,
        "duplicate_run_ids": sorted(run_id for run_id, count in state.by_run.items() if count > 1),
        "requests": state.requests,
        "all_cells_one_response": len(state.requests) == state.expected and all(
            count == 1 for count in state.by_run.values()
        ),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
