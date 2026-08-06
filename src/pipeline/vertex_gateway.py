"""Credential-owning in-process gateway for isolated benchmark containers.

The HTTP serving layer may expose this gateway only after the experiment
coordinator has verified a signed approval.  Baseline containers receive a
short-lived gateway token, never Vertex credentials.
"""

from __future__ import annotations

import json
import os
import re
import socketserver
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping, Sequence

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.vertex_runtime import (
    GeminiExecutor,
    GemmaMaaSExecutor,
    GoogleGenAITransport,
    InvocationResult,
    OpenAICompatibleClientTransport,
)

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class GatewayError(ValueError):
    """A container request was not authorized for the pinned experiment."""


@dataclass(frozen=True)
class GatewayRequest:
    run_id: str
    model_label: str
    profile_hash: str
    contents: Any

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GatewayRequest":
        request = cls(
            run_id=str(value.get("run_id", "")),
            model_label=str(value.get("model_label", "")),
            profile_hash=str(value.get("profile_hash", "")),
            contents=value.get("contents", value.get("prompt")),
        )
        if not _RUN_ID.fullmatch(request.run_id):
            raise GatewayError("gateway request run_id is invalid")
        if request.contents is None:
            raise GatewayError("gateway request contents is required")
        return request


class VertexGateway:
    """Authorize a pinned model request before delegating to an injected executor."""

    def __init__(
        self,
        *,
        profiles: Sequence[ModelProfile],
        allowed_run_ids: set[str],
        token: str,
        gemini: GeminiExecutor,
        gemma: GemmaMaaSExecutor,
        token_expires_at: str = "",
    ) -> None:
        if not token:
            raise GatewayError("gateway token is required")
        self.profiles = {profile.logical_label: profile for profile in profiles}
        if len(self.profiles) != len(profiles):
            raise GatewayError("gateway profiles must have unique labels")
        if not allowed_run_ids or any(not _RUN_ID.fullmatch(run_id) for run_id in allowed_run_ids):
            raise GatewayError("gateway requires safe approved run IDs")
        self.allowed_run_ids = set(allowed_run_ids)
        self.token = token
        self.token_expires_at = token_expires_at
        if token_expires_at:
            try:
                expiry = datetime.fromisoformat(token_expires_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise GatewayError("gateway token expiry is invalid") from exc
            if expiry.tzinfo is None:
                raise GatewayError("gateway token expiry must include a timezone")
        self.gemini = gemini
        self.gemma = gemma

    def invoke(self, request: Mapping[str, Any], *, token: str) -> InvocationResult:
        if token != self.token:
            raise GatewayError("gateway token is invalid")
        if self.token_expires_at:
            expiry = datetime.fromisoformat(self.token_expires_at.replace("Z", "+00:00"))
            if datetime.now(UTC) >= expiry.astimezone(UTC):
                raise GatewayError("gateway token has expired")
        parsed = GatewayRequest.from_dict(request)
        if parsed.run_id not in self.allowed_run_ids:
            raise GatewayError("gateway request run_id is not approved")
        profile = self.profiles.get(parsed.model_label)
        if profile is None or profile.profile_hash != parsed.profile_hash:
            raise GatewayError("gateway request profile is not pinned")
        if profile.logical_label.startswith("gemini-"):
            return self.gemini.invoke(profile, parsed.contents)
        if not isinstance(parsed.contents, Sequence) or isinstance(parsed.contents, (str, bytes)):
            raise GatewayError("Gemma gateway contents must be chat messages")
        messages = [dict(item) for item in parsed.contents if isinstance(item, Mapping)]
        if len(messages) != len(parsed.contents):
            raise GatewayError("Gemma gateway messages must be objects")
        return self.gemma.invoke(profile, messages)


def build_host_gateway(
    *, profiles: Sequence[ModelProfile], allowed_run_ids: set[str], token: str,
    token_expires_at: str, project: str,
    gemini_client_factory: Callable[[str, str], Any],
    gemma_client_factory: Callable[[str], Any],
) -> VertexGateway:
    """Build credential-owning transports from verified host-side metadata.

    Factories are injected so verify-only tests never import an SDK or make a
    request.  The Gemma endpoint is taken from its pinned profile; this
    function has no endpoint constant to drift from Model Garden metadata.
    """
    if not project.strip():
        raise GatewayError("host gateway requires a project")
    gemini_profiles = [profile for profile in profiles if profile.logical_label.startswith("gemini-")]
    gemma_profiles = [profile for profile in profiles if profile.logical_label == "gemma-4-26b-a4b-it"]
    if len(gemini_profiles) != 2 or len(gemma_profiles) != 1:
        raise GatewayError("host gateway requires exactly two Gemini and one Gemma profile")
    gemini_client = gemini_client_factory(project, "global")
    gemma_endpoint = gemma_profiles[0].endpoint_url
    if not gemma_endpoint.startswith("https://") or "googleapis.com" not in gemma_endpoint:
        raise GatewayError("Gemma endpoint is not a verified Google endpoint")
    gemma_client = gemma_client_factory(gemma_endpoint)
    return VertexGateway(
        profiles=profiles,
        allowed_run_ids=allowed_run_ids,
        token=token,
        token_expires_at=token_expires_at,
        gemini=GeminiExecutor(GoogleGenAITransport(gemini_client)),
        gemma=GemmaMaaSExecutor(OpenAICompatibleClientTransport(gemma_client)),
    )


def gateway_handler(gateway: VertexGateway) -> type[BaseHTTPRequestHandler]:
    """Create the internal-only HTTP handler used by the container proxy."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/generate":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 1_048_576:
                    raise GatewayError("gateway request size is invalid")
                value = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(value, Mapping):
                    raise GatewayError("gateway request must be an object")
                auth = self.headers.get("Authorization", "")
                token = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else ""
                result = gateway.invoke(value, token=token)
                body = json.dumps(result.to_dict(), sort_keys=True).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (GatewayError, UnicodeDecodeError, ValueError):
                self.send_error(403)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


def serve_gateway(gateway: VertexGateway, *, host: str, port: int) -> ThreadingHTTPServer:
    """Construct, but do not start, the internal gateway server."""
    if host not in {"127.0.0.1", "::1", "0.0.0.0"} or port < 1 or port > 65535:
        raise GatewayError("gateway bind address is invalid")
    return ThreadingHTTPServer((host, port), gateway_handler(gateway))


class _ThreadingUnixGatewayServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve_gateway_unix(gateway: VertexGateway, *, socket_path: str) -> socketserver.UnixStreamServer:
    """Bind the host gateway only to a fresh owner-only Unix socket."""
    path = os.path.abspath(socket_path)
    if os.path.lexists(path):
        raise GatewayError("gateway Unix socket path must be new and not a symlink")
    parent = os.path.dirname(path)
    if not os.path.isdir(parent) or os.path.islink(parent):
        raise GatewayError("gateway Unix socket parent directory must be a real directory")
    stat = os.stat(parent)
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o777 != 0o700:
        raise GatewayError("gateway Unix socket parent directory is not owner-only")
    server = _ThreadingUnixGatewayServer(path, gateway_handler(gateway))
    os.chmod(path, 0o600)
    return server
