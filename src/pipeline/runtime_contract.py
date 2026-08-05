"""Runtime-only locks and credential/signature gates.

This module contains checks that are deliberately independent from provider
SDKs.  It is safe to use during verify-only preflight: it never creates a
Vertex client and never performs inference.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from src.pipeline.framework_adapter import ModelProfile

ALIAS_EXCEPTION_SCHEMA = "1.0.0"
LOCKED_MODEL_LABELS = tuple(sorted(ModelProfile.ALLOWED_MODELS))
ALIAS_EXCEPTION_KEYS = frozenset({
    "schema_version", "project", "dataset_lock_hash", "model_labels", "expires_at", "reason",
})
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def canonical_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _parse_utc(value: Any, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def _verify_detached_minisign(payload: bytes, signature_path: str | Path, public_key: str) -> None:
    if not public_key.strip():
        raise ValueError("minisign public key is required")
    signature = Path(signature_path)
    if not signature.is_file():
        raise ValueError("detached minisign signature is missing")
    minisign = shutil.which("minisign")
    if minisign is None:
        raise ValueError("minisign is unavailable; refusing unsigned runtime exception")
    with tempfile.TemporaryDirectory(prefix="veriplanpt-runtime-signature-") as temp:
        message = Path(temp) / "signed.json"
        message.write_bytes(payload)
        result = subprocess.run(
            [minisign, "-Vm", str(message), "-P", public_key, "-x", str(signature)],
            capture_output=True, text=True, check=False,
        )
    if result.returncode != 0:
        raise ValueError("minisign verification failed")


def verify_alias_exception(
    exception: Mapping[str, Any], *, signature_path: str | Path, public_key: str,
    project: str, dataset_lock_hash: str, now: datetime | None = None,
) -> dict[str, Any]:
    """Verify the narrowly scoped signed exception for Gemini ``@default``."""
    if set(exception) != ALIAS_EXCEPTION_KEYS:
        unexpected = sorted(set(exception).difference(ALIAS_EXCEPTION_KEYS))
        missing = sorted(ALIAS_EXCEPTION_KEYS.difference(exception))
        detail = []
        if missing:
            detail.append(f"missing: {', '.join(missing)}")
        if unexpected:
            detail.append(f"unexpected: {', '.join(unexpected)}")
        raise ValueError("alias exception fields are not exact (" + "; ".join(detail) + ")")
    if exception["schema_version"] != ALIAS_EXCEPTION_SCHEMA:
        raise ValueError("alias exception schema_version is invalid")
    if str(exception["project"]) != project or not project.strip():
        raise ValueError("alias exception project mismatch")
    if str(exception["dataset_lock_hash"]) != dataset_lock_hash or not SHA256.fullmatch(dataset_lock_hash):
        raise ValueError("alias exception dataset lock hash mismatch")
    labels = exception["model_labels"]
    if labels != list(LOCKED_MODEL_LABELS):
        raise ValueError("alias exception must cover exactly the three locked model labels")
    reason = str(exception["reason"])
    if "@default" not in reason or not reason.strip():
        raise ValueError("alias exception reason must explain the @default exception")
    expires = _parse_utc(exception["expires_at"], "alias exception expires_at")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if current >= expires:
        raise ValueError("alias exception has expired")
    _verify_detached_minisign(canonical_json(exception), signature_path, public_key)
    return {
        "schema_version": ALIAS_EXCEPTION_SCHEMA,
        "project": project,
        "dataset_lock_hash": dataset_lock_hash,
        "model_labels": list(LOCKED_MODEL_LABELS),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
    }


def validate_runtime_profile(
    profile: ModelProfile, *, strict: bool = False,
) -> None:
    """Apply the stronger runtime rules without breaking legacy pilot fixtures."""
    if not strict:
        return
    if profile.location != "global":
        raise ValueError(f"runtime profile {profile.logical_label} must use global")
    if profile.logical_label == "gemma-4-26b-a4b-it":
        if profile.resource_revision != "001":
            raise ValueError("Gemma MaaS runtime profile must use @001")
        if profile.generation_parameters.get("thinking") in {True, "true", "enabled"}:
            raise ValueError("Gemma thinking must be disabled")
        if profile.usage_semantics.get("total_formula") != "input+output":
            raise ValueError("Gemma runtime profile must not bill thinking tokens")
        if profile.usage_semantics.get("output_includes_reasoning") != "true":
            raise ValueError("Gemma runtime profile must declare output-only billing")
        if not profile.endpoint_url.startswith("https://") or "googleapis.com" not in profile.endpoint_url:
            raise ValueError("Gemma runtime profile requires the metadata-pinned MaaS endpoint")
    else:
        if profile.resource_revision != "default" or profile.resolution_mode != "provider_alias":
            raise ValueError(f"{profile.logical_label} must use the explicit @default provider alias")


def verify_impersonated_adc(service_account: str, *, project: str) -> dict[str, str]:
    """Verify ADC can mint an impersonated token; no Vertex request is made."""
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com", service_account):
        raise ValueError("runtime requires a service-account impersonation target")
    if not project.strip():
        raise ValueError("runtime requires a GCP project")
    gcloud = shutil.which("gcloud")
    if gcloud is None:
        raise ValueError("gcloud is unavailable; ADC preflight cannot pass")
    result = subprocess.run(
        [gcloud, "auth", "application-default", "print-access-token",
         "--impersonate-service-account", service_account],
        capture_output=True, text=True, check=False, timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise ValueError("ADC service-account impersonation preflight failed")
    return {"project": project, "service_account": service_account, "token_obtained": "true"}


def validate_lock_reference(value: Any, *, name: str, artifact_root: str | Path) -> str:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} reference must be an object")
    path_value = value.get("artifact_path")
    if not isinstance(path_value, str) or not path_value.strip():
        raise ValueError(f"{name} reference requires artifact_path")
    path = Path(path_value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{name} artifact_path must be relative")
    expected = str(value.get("sha256", ""))
    if not SHA256.fullmatch(expected):
        raise ValueError(f"{name} reference requires a SHA-256")
    actual = sha256_file(Path(artifact_root).resolve() / path)
    if actual != expected:
        raise ValueError(f"{name} artifact hash mismatch")
    return actual
