"""
Applicability assessment and shortlist construction.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Any

from packaging import version

from src.memory.world_state import WorldState
from src.retrieval.models import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
)

_TRUST = {
    "vendor": 1.0,
    "kev": 0.95,
    "nvd": 0.85,
    "cvemap": 0.85,
    "exploitdb": 0.80,
    "github": 0.65,
    "google": 0.35,
}


def _tri_to_num(value: str) -> float:
    return {"yes": 1.0, "unknown": 0.5, "no": 0.0}.get(value, 0.5)


def _match_version(target_version: str, ranges: list[dict[str, Any]]) -> str:
    if not target_version:
        return "unknown"
    if not ranges:
        return "unknown"
    try:
        current = version.parse(target_version)
    except Exception:
        return "unknown"
    any_unknown = False
    for item in ranges:
        exact = str(item.get("version") or "").strip()
        min_ver = str(item.get("min_version") or "").strip()
        max_ver = str(item.get("max_version") or "").strip()
        if exact:
            try:
                return "yes" if version.parse(exact) == current else "no"
            except Exception:
                any_unknown = True
                continue
        try:
            if min_ver and current < version.parse(min_ver):
                continue
            if max_ver and current > version.parse(max_ver):
                continue
            return "yes"
        except Exception:
            any_unknown = True
    return "unknown" if any_unknown else "no"


def _match_cpe(fp: ProductFingerprint, record: AuthoritativeRecord) -> str:
    text = " ".join([
        record.title.lower(),
        record.description.lower(),
        " ".join(record.references).lower(),
        " ".join(f"{item.get('vendor','')} {item.get('product','')}" for item in record.affected_ranges).lower(),
    ])
    product = (fp.product or fp.raw_service).lower()
    vendor = (fp.vendor or "").lower()
    if product and product in text:
        return "yes" if not vendor or vendor in text else "unknown"
    if vendor and vendor in text:
        return "unknown"
    return "unknown" if not product else "no"


def _match_platform(fp: ProductFingerprint, record: AuthoritativeRecord) -> str:
    if not fp.platform_hints or not record.platform_hints:
        return "unknown"
    if set(fp.platform_hints).intersection(record.platform_hints):
        return "yes"
    return "no"


_PLATFORM_ALIASES: dict[str, str] = {
    "win": "windows", "win32": "windows", "win64": "windows",
    "w32": "windows", "w64": "windows", "winnt": "windows",
    "gnu/linux": "linux",
    "osx": "macos", "darwin": "macos", "mac": "macos",
}

_FOREIGN_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _check_snippet_target_assumptions(snippet: ProcedureSnippet, fp: ProductFingerprint) -> str:
    """Cross-check snippet target_assumptions against fingerprint platform hints."""
    if not snippet.target_assumptions:
        return "unknown"

    fp_platforms = {h.lower().strip() for h in fp.platform_hints}
    expanded_fp = set(fp_platforms)
    for hint in fp_platforms:
        if hint in _PLATFORM_ALIASES:
            expanded_fp.add(_PLATFORM_ALIASES[hint])

    snippet_platforms: set[str] = set()
    for assumption in snippet.target_assumptions:
        normalized = assumption.lower().strip()
        snippet_platforms.add(normalized)
        if normalized in _PLATFORM_ALIASES:
            snippet_platforms.add(_PLATFORM_ALIASES[normalized])

    if snippet_platforms and expanded_fp:
        if snippet_platforms & expanded_fp:
            return "yes"
        return "no"

    return "unknown"


def _check_foreign_target_ips(snippet: ProcedureSnippet, fp: ProductFingerprint) -> tuple[str, list[str]]:
    """Check for hardcoded foreign target IPs in snippet commands.

    Returns (signal, offending_ips) where signal is 'clean', 'warning', or
    'no_good_commands'.
    """
    if not snippet.commands:
        return "clean", []

    allowed = {ip for ip in (fp.target_ip, "127.0.0.1", "0.0.0.0") if ip}
    offending_ips: set[str] = set()
    clean_commands = 0

    for cmd in snippet.commands:
        ips_in_cmd = set(_FOREIGN_IP_RE.findall(cmd))
        foreign = ips_in_cmd - allowed
        if foreign:
            offending_ips.update(foreign)
        else:
            clean_commands += 1

    if not offending_ips:
        return "clean", []
    if clean_commands > 0:
        return "warning", sorted(offending_ips)
    return "no_good_commands", sorted(offending_ips)


def _match_auth(ws: WorldState, fp: ProductFingerprint, record: AuthoritativeRecord) -> str:
    if record.auth_hint != "required":
        return "yes"
    if ws.credentials:
        return "yes"
    if fp.auth_hint == "required":
        return "unknown"
    return "unknown"


def _match_network(ws: WorldState, fp: ProductFingerprint) -> str:
    host = ws.hosts.get(fp.target_ip)
    if not host:
        return "unknown"
    service = host.get_service(fp.port)
    if not service:
        return "unknown"
    return "yes" if service.accessibility == "open" else "no" if service.accessibility == "closed" else "unknown"


def _procedure_ready(snippet: ProcedureSnippet) -> bool:
    return bool(
        snippet.commands
        or snippet.dependencies
        or snippet.setup_commands
        or snippet.verify_commands
        or snippet.usage_notes
    )


def _estimated_cost(candidate: PocCandidate, snippet: ProcedureSnippet) -> float:
    cost = 1.0
    if candidate.source == "github":
        cost += 0.25
    if candidate.source == "google":
        cost += 0.35
    if len(snippet.placeholders) >= 4:
        cost += 0.15
    if len(snippet.dependencies) >= 3:
        cost += 0.15
    if any(token in (candidate.language or "").lower() for token in ("ruby", "perl", "java")):
        cost += 0.1
    return round(cost, 3)


def flatten_assessment_map(assessments: list[ApplicabilityAssessment]) -> dict[str, ApplicabilityAssessment]:
    return {item.candidate_id: item for item in assessments}


def assess_candidates(
    ws: WorldState,
    fingerprints: list[ProductFingerprint],
    records: list[AuthoritativeRecord],
    candidates: list[PocCandidate],
    snippets: list[ProcedureSnippet],
) -> list[ApplicabilityAssessment]:
    snippet_map = {item.candidate_id: item for item in snippets}
    by_cve: dict[str, list[PocCandidate]] = defaultdict(list)
    for candidate in candidates:
        by_cve[candidate.cve_id].append(candidate)

    assessments: list[ApplicabilityAssessment] = []
    for record in records:
        matching_fps = [
            fp for fp in fingerprints
            if (fp.product and fp.product.lower() in (record.title + " " + record.description).lower())
            or fp.raw_service.lower() in (record.title + " " + record.description).lower()
        ] or fingerprints[:1]
        fp = matching_fps[0] if matching_fps else None
        if fp is None:
            continue
        for candidate in by_cve.get(record.cve_id, []):
            snippet = snippet_map.get(candidate.candidate_id, ProcedureSnippet(candidate_id=candidate.candidate_id))
            version_match = _match_version(fp.version, record.affected_ranges)
            cpe_match = _match_cpe(fp, record)
            platform_match = _match_platform(fp, record)
            snippet_assumption_match = _check_snippet_target_assumptions(snippet, fp)
            foreign_ip_signal, foreign_ips = _check_foreign_target_ips(snippet, fp)
            if snippet_assumption_match == "no" and platform_match != "no":
                platform_match = "no"
            auth_match = _match_auth(ws, fp, record)
            network_match = _match_network(ws, fp)
            procedure_ready = _procedure_ready(snippet)
            trust_score = _TRUST.get(record.source, _TRUST.get(candidate.source, 0.5))
            estimated_cost = _estimated_cost(candidate, snippet)
            applicability = (
                _tri_to_num(version_match) * 0.35
                + _tri_to_num(cpe_match) * 0.25
                + _tri_to_num(platform_match) * 0.15
                + _tri_to_num(auth_match) * 0.10
                + _tri_to_num(network_match) * 0.15
            )
            readiness = 1.0 if procedure_ready else 0.35
            score = (
                applicability * 0.40
                + trust_score * 0.25
                + readiness * 0.20
                + min(max(candidate.raw_confidence, 0.0), 1.0) * 0.10
                - (estimated_cost / 5.0) * 0.05
            )
            hard_mismatch = "no" in {version_match, cpe_match, platform_match, network_match}
            reasons = [
                f"version={version_match}",
                f"cpe={cpe_match}",
                f"platform={platform_match}",
                f"auth={auth_match}",
                f"network={network_match}",
                f"procedure_ready={procedure_ready}",
            ]
            if snippet_assumption_match != "unknown":
                reasons.append(f"snippet_platform={snippet_assumption_match}")
            if foreign_ip_signal == "warning":
                reasons.append(f"foreign_ip_hygiene=warning:{','.join(foreign_ips)}")
            elif foreign_ip_signal == "no_good_commands":
                reasons.append(f"foreign_ip_hygiene=all_foreign:{','.join(foreign_ips)}")
            if hard_mismatch:
                verdict = "reject"
            elif score >= 0.72:
                verdict = "strong"
            elif score >= 0.50:
                verdict = "weak"
            else:
                verdict = "reject"
            if verdict == "strong" and version_match != "yes":
                verdict = "weak"
                reasons.append("version_confirmation_required")
            assessments.append(ApplicabilityAssessment(
                cve_id=record.cve_id,
                candidate_id=candidate.candidate_id,
                version_match=version_match,
                cpe_match=cpe_match,
                platform_match=platform_match,
                auth_match=auth_match,
                network_match=network_match,
                procedure_ready=procedure_ready,
                trust_score=round(trust_score, 3),
                estimated_cost=estimated_cost,
                score=round(max(score, 0.0), 3),
                verdict=verdict,
                reasons=reasons,
            ))
    return assessments


def build_shortlist(
    fingerprints: list[ProductFingerprint],
    records: list[AuthoritativeRecord],
    candidates: list[PocCandidate],
    snippets: list[ProcedureSnippet],
    assessments: list[ApplicabilityAssessment],
    top_cves: int = 5,
) -> list[dict[str, Any]]:
    fp_map = {(fp.target_ip, fp.port): fp for fp in fingerprints}
    record_map = {record.cve_id: record for record in records}
    candidate_map = {candidate.candidate_id: candidate for candidate in candidates}
    snippet_map = {snippet.candidate_id: snippet for snippet in snippets}
    shortlist: list[dict[str, Any]] = []

    assessments = sorted(
        assessments,
        key=lambda item: (item.verdict == "strong", item.score, item.trust_score),
        reverse=True,
    )
    used_cves: set[str] = set()
    for assessment in assessments:
        record = record_map.get(assessment.cve_id)
        candidate = candidate_map.get(assessment.candidate_id)
        snippet = snippet_map.get(assessment.candidate_id)
        if record is None or candidate is None:
            continue
        text = (record.title + " " + record.description).lower()
        fp = next(
            (
                item for item in fingerprints
                if item.product.lower() in text or item.raw_service.lower() in text
            ),
            fingerprints[0] if fingerprints else None,
        )
        if fp is None:
            continue
        if assessment.cve_id in used_cves:
            continue
        used_cves.add(assessment.cve_id)
        shortlist.append({
            "cve_id": assessment.cve_id,
            "candidate_id": assessment.candidate_id,
            "source": candidate.source,
            "title": record.title,
            "score": assessment.score,
            "verdict": assessment.verdict,
            "trust_score": assessment.trust_score,
            "estimated_cost": assessment.estimated_cost,
            "service": fp.raw_service,
            "vendor": fp.vendor,
            "product": fp.product,
            "version": fp.version,
            "port": fp.port,
            "target_ip": fp.target_ip,
            "path": candidate.path,
            "locator": candidate.locator,
            "references": record.references[:5],
            "commands": snippet.commands[:5] if snippet else [],
            "dependencies": snippet.dependencies[:5] if snippet else [],
            "placeholders": snippet.placeholders[:8] if snippet else [],
            "required_placeholders": snippet.required_placeholders[:8] if snippet else [],
            "working_directory": snippet.working_directory if snippet else "",
            "setup_commands": snippet.setup_commands[:5] if snippet else [],
            "verify_commands": snippet.verify_commands[:3] if snippet else [],
            "success_indicators": snippet.success_indicators[:8] if snippet else [],
            "failure_indicators": snippet.failure_indicators[:8] if snippet else [],
            "reasons": assessment.reasons,
        })
        if len({item["cve_id"] for item in shortlist}) >= top_cves:
            break
    return shortlist
