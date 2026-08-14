"""Controlled local provider shim used by baseline containers.

The shim deliberately has no Google SDK or credential discovery path. A
container can call only the configured HTTP gateway, or the deterministic fake
provider used by contract smokes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class ProviderShimError(RuntimeError):
    """Raised when a request cannot be routed through the controlled gateway."""

    def __init__(self, message: str, *, failure_id: str = "", retryable: bool = False) -> None:
        super().__init__(message)
        self.failure_id = failure_id
        self.retryable = retryable
        self.model_response_received = False


_CALL_INDEX = 0


def _gateway_url() -> str:
    value = os.environ.get("VERIPLANPT_PROVIDER_URL", "http://gateway-relay:8080/v1/generate")
    if value.startswith("https://aiplatform.googleapis.com") or "googleapis.com" in value:
        raise ProviderShimError("direct Vertex endpoints are forbidden in baseline containers")
    if not value.startswith(("http://", "https://")):
        raise ProviderShimError("provider gateway must be an HTTP(S) URL")
    return value


def request(payload: dict[str, object]) -> dict[str, object]:
    """Send one JSON request to the controlled provider gateway."""
    if any(os.environ.get(name) for name in (
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_ADC", "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION", "GOOGLE_GENAI_USE_VERTEXAI",
    )):
        raise ProviderShimError("Vertex credentials must not be present in a baseline container")
    if os.environ.get("VERIPLANPT_GATEWAY_LIVE", "").lower() == "true":
        for name in (
            "VERIPLANPT_RUN_ID", "VERIPLANPT_MODEL_LABEL", "VERIPLANPT_PROFILE_HASH",
            "VERIPLANPT_PROVIDER_TOKEN", "VERIPLANPT_PROVIDER_TOKEN_EXPIRES_AT",
        ):
            if not os.environ.get(name):
                raise ProviderShimError(f"{name} is required for the live gateway")
        try:
            expires = datetime.fromisoformat(
                os.environ["VERIPLANPT_PROVIDER_TOKEN_EXPIRES_AT"].replace("Z", "+00:00")
            ).astimezone(UTC)
        except ValueError as exc:
            raise ProviderShimError("gateway token expiry is invalid") from exc
        if datetime.now(UTC) >= expires:
            raise ProviderShimError("gateway token has expired")
        payload = {
            **payload,
            "run_id": os.environ["VERIPLANPT_RUN_ID"],
            "model_label": os.environ["VERIPLANPT_MODEL_LABEL"],
            "profile_hash": os.environ["VERIPLANPT_PROFILE_HASH"],
            "contents": payload.get("contents", payload.get("prompt")),
        }
        epoch = os.environ.get("VERIPLANPT_EPOCH", "")
        if epoch:
            global _CALL_INDEX
            payload["epoch"] = epoch
            payload["call_index"] = int(os.environ.get("VERIPLANPT_CALL_INDEX", _CALL_INDEX))
            _CALL_INDEX += 1
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-VeriPlanPT-Provider-Shim": "1"}
    token = os.environ.get("VERIPLANPT_PROVIDER_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    evidence_root = Path(os.environ.get("VERIPLANPT_OUTPUT_DIR", os.environ.get("VERIPLANPT_RUN_DIR", ".")))
    try:
        with urlopen(Request(_gateway_url(), data=body, headers=headers, method="POST"), timeout=30) as response:
            value = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        failure: dict[str, object] = {}
        try:
            decoded = json.loads(exc.read().decode("utf-8"))
            if isinstance(decoded, dict):
                failure = decoded
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        failure_id = str(failure.get("failure_id", ""))
        record = {
            "failure_id": failure_id,
            "upstream_status": failure.get("upstream_status"),
            "retryable": bool(failure.get("retryable", False)),
            "error_body_sha256": str(failure.get("error_body_sha256", "")),
            "google_request_id": str(failure.get("google_request_id", "")),
            "model_response_received": False,
        }
        evidence_root.mkdir(parents=True, exist_ok=True)
        with evidence_root.joinpath("provider-failures.jsonl").open("a", encoding="utf-8") as evidence:
            evidence.write(json.dumps(record, sort_keys=True) + "\n")
        raise ProviderShimError(
            f"provider gateway request failed: {type(exc).__name__}",
            failure_id=failure_id, retryable=bool(failure.get("retryable", False)),
        ) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ProviderShimError(f"provider gateway request failed: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise ProviderShimError("provider gateway response must be a JSON object")
    evidence_root.mkdir(parents=True, exist_ok=True)
    with evidence_root.joinpath("provider-calls.jsonl").open("a", encoding="utf-8") as evidence:
        evidence.write(json.dumps({
            "request_sha256": hashlib.sha256(body).hexdigest(),
            "response_sha256": str(value.get("response_hash", "")),
        }, sort_keys=True) + "\n")
    return value


def models() -> dict[str, object]:
    """Return the pinned model list through the internal relay."""
    if any(os.environ.get(name) for name in (
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_ADC", "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION", "GOOGLE_GENAI_USE_VERTEXAI",
    )):
        raise ProviderShimError("Vertex credentials must not be present in a baseline container")
    try:
        with urlopen(Request(_gateway_url().rsplit("/v1/", 1)[0] + "/v1/models", headers={
            "Authorization": f"Bearer {os.environ.get('VERIPLANPT_PROVIDER_TOKEN', '')}",
        }, method="GET"), timeout=30) as response:
            value = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ProviderShimError(f"provider model list failed: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise ProviderShimError("provider model list must be a JSON object")
    return value


def chat_completion(messages: list[dict[str, object]], *, model: str = "", stream: bool = False) -> dict[str, object]:
    """OpenAI-compatible convenience adapter for baseline wrappers."""
    base = os.environ.get("VERIPLANPT_PROVIDER_BASE_URL", "http://gateway-relay:8080/v1").rstrip("/")
    previous = os.environ.get("VERIPLANPT_PROVIDER_URL")
    os.environ["VERIPLANPT_PROVIDER_URL"] = base + "/chat/completions"
    try:
        return request({"model": model or os.environ.get("VERIPLANPT_MODEL_LABEL", ""), "messages": messages, "stream": stream})
    finally:
        if previous is None:
            os.environ.pop("VERIPLANPT_PROVIDER_URL", None)
        else:
            os.environ["VERIPLANPT_PROVIDER_URL"] = previous


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract-smoke", action="store_true")
    args = parser.parse_args()
    if args.contract_smoke:
        result: dict[str, object] = {"provider": "fake", "status": "ok", "network": "gateway-only"}
        if os.environ.get("VERIPLANPT_PROVIDER_URL"):
            result["gateway_response"] = request({"task": "vp-validation-0001", "prompt": "stubbed model response"})
            result["provider"] = "controlled-gateway"
        print(json.dumps(result, sort_keys=True))
        return 0
    raise SystemExit("provider_shim.py is a library; use --contract-smoke for the offline probe")


if __name__ == "__main__":
    raise SystemExit(main())
