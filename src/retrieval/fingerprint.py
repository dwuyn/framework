"""
Service fingerprint normalization and CPE enrichment.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from src.memory.world_state import ServiceInfo, WorldState
from src.retrieval.models import ProductFingerprint
from src.state import service_target_key

_TOKEN_RE = re.compile(r"[^a-z0-9]+", re.IGNORECASE)
_VERSION_RE = re.compile(r"\b\d+(?:\.\d+)+(?:[a-z]+\d+)?\b", re.IGNORECASE)

_ALIASES: dict[str, tuple[str, str, list[str]]] = {
    "apache": ("apache", "httpd", ["linux"]),
    "apache httpd": ("apache", "httpd", ["linux"]),
    "httpd": ("apache", "httpd", ["linux"]),
    "nginx": ("nginx", "nginx", ["linux"]),
    "openssh": ("openbsd", "openssh", ["linux"]),
    "ssh": ("openbsd", "openssh", ["linux"]),
    "http proxy": ("apache", "httpd", ["linux"]),
    "mysql": ("oracle", "mysql", ["linux"]),
    "mariadb": ("mariadb", "mariadb", ["linux"]),
    "postgres": ("postgresql", "postgresql", ["linux"]),
    "postgresql": ("postgresql", "postgresql", ["linux"]),
    "phpmailer": ("phpmailer", "phpmailer", ["linux"]),
    "iis": ("microsoft", "iis", ["windows"]),
    "microsoft-iis": ("microsoft", "iis", ["windows"]),
    "smb": ("microsoft", "smb", ["windows"]),
    "rdp": ("microsoft", "rdp", ["windows"]),
    "ftp": ("generic", "ftp", []),
    "tomcat": ("apache", "tomcat", ["linux"]),
    "jetty": ("eclipse", "jetty", ["linux"]),
}


def _normalize_token(value: str) -> str:
    return _TOKEN_RE.sub(" ", (value or "").strip().lower()).strip()


def _guess_identity(service_name: str, banner: str) -> tuple[str, str, list[str]]:
    candidates = [
        _normalize_token(service_name),
        _normalize_token(banner),
    ]
    for text in candidates:
        if not text:
            continue
        for alias, target in _ALIASES.items():
            if alias in text:
                return target
    token = _normalize_token(service_name) or _normalize_token(banner)
    if not token:
        return "unknown", "unknown", []
    parts = token.split()
    if len(parts) >= 2:
        return parts[0], parts[1], []
    return parts[0], parts[0], []


def _guess_auth_hint(service_name: str, banner: str) -> str:
    text = f"{service_name} {banner}".lower()
    if any(token in text for token in ("login", "auth", "credential", "password", "ssh", "ftp")):
        return "required"
    return "unknown"


def _canonical_version(version: str, banner: str) -> str:
    """Extract the first meaningful version token from a service version/banner."""
    for source in (version or "", banner or ""):
        if not source:
            continue
        match = _VERSION_RE.search(source)
        if match:
            return match.group(0)
    return version or ""


def _cpe_candidates(vendor: str, product: str, version: str) -> list[str]:
    if not vendor or not product or "unknown" in (vendor, product):
        return []
    version = version or "*"
    return [
        f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
    ]


def _build_fingerprint(target_ip: str, service: ServiceInfo) -> ProductFingerprint:
    vendor, product, platform_hints = _guess_identity(service.name, service.banner)
    version = _canonical_version(service.version or "", service.banner or "")
    evidence = list(service.evidence or [])
    evidence.append(
        f"Normalized {service.name or '?'} on {target_ip}:{service.port} to {vendor}/{product} {version or '?'}"
    )
    return ProductFingerprint(
        target_ip=target_ip,
        port=service.port,
        protocol=service.protocol,
        raw_service=service.name,
        raw_banner=service.banner,
        raw_version=service.version,
        vendor=vendor,
        product=product,
        version=version,
        cpe_candidates=_cpe_candidates(vendor, product, version),
        platform_hints=platform_hints,
        auth_hint=_guess_auth_hint(service.name, service.banner),
        confidence=float(service.confidence or 0.0),
        evidence=evidence,
    )


def build_fingerprints(
    ws: WorldState,
    top_services: int = 5,
    state: Mapping[str, Any] | None = None,
) -> list[ProductFingerprint]:
    services: list[tuple[str, ServiceInfo]] = []
    state = state or {}
    target_services = list(state.get("target_services", []) or [])
    attempted_services = {str(item) for item in (state.get("attempted_services", []) or [])}
    if target_services:
        current_index = int(state.get("current_service_index", 0) or 0)
        ordered_targets = target_services[current_index:] + target_services[:current_index]
        for target in ordered_targets:
            service_key = str(target.get("service_key") or service_target_key(
                str(target.get("target_ip", "")),
                target.get("port", 0),
                str(target.get("name", "")),
            ))
            if service_key in attempted_services:
                continue
            host = ws.hosts.get(str(target.get("target_ip", "")))
            if not host:
                continue
            service = host.get_service(int(target.get("port", 0) or 0))
            if not service:
                continue
            # Phase 2 must stay scoped to the active service. Once a target
            # service inventory exists, only fingerprint the current service.
            return [_build_fingerprint(str(target.get("target_ip", "")), service)]

    for ip, host in ws.hosts.items():
        for service in host.services:
            key = service_target_key(ip, service.port, service.name)
            if key in attempted_services:
                continue
            services.append((ip, service))
    services.sort(
        key=lambda item: (
            float(item[1].confidence or 0.0),
            bool(item[1].version),
        ),
        reverse=True,
    )
    selected = services[:top_services] if top_services > 0 else services
    return [_build_fingerprint(ip, service) for ip, service in selected]


def apply_cpe_updates(ws: WorldState, fingerprints: Iterable[ProductFingerprint]) -> WorldState:
    for fp in fingerprints:
        host = ws.hosts.get(fp.target_ip)
        if not host:
            continue
        service = host.get_service(fp.port)
        if not service:
            continue
        if fp.cpe_candidates:
            service.cpe = fp.cpe_candidates[0]
    return ws
