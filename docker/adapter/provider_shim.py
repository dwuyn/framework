"""Controlled local provider shim used by baseline containers.

The shim deliberately has no Google SDK or credential discovery path. A
container can call only the configured HTTP gateway, or the deterministic fake
provider used by contract smokes.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class ProviderShimError(RuntimeError):
    """Raised when a request cannot be routed through the controlled gateway."""


def _gateway_url() -> str:
    value = os.environ.get("VERIPLANPT_PROVIDER_URL", "http://provider-gateway:8080/v1/generate")
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
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-VeriPlanPT-Provider-Shim": "1"}
    token = os.environ.get("VERIPLANPT_PROVIDER_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(Request(_gateway_url(), data=body, headers=headers, method="POST"), timeout=30) as response:
            value = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ProviderShimError(f"provider gateway request failed: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise ProviderShimError("provider gateway response must be a JSON object")
    return value


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
