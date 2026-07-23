"""
Structured retrieval stack for vulnerability and exploit discovery.
"""

from src.retrieval.applicability import (
    assess_candidates,
    build_shortlist,
    flatten_assessment_map,
)
from src.retrieval.authoritative import collect_authoritative_records
from src.retrieval.fingerprint import apply_cpe_updates, build_fingerprints
from src.retrieval.models import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
    RetrievalBundle,
)
from src.retrieval.poc_sources import collect_poc_candidates
from src.retrieval.procedure import extract_procedure_snippets

__all__ = [
    "ApplicabilityAssessment",
    "AuthoritativeRecord",
    "PocCandidate",
    "ProcedureSnippet",
    "ProductFingerprint",
    "RetrievalBundle",
    "apply_cpe_updates",
    "assess_candidates",
    "build_fingerprints",
    "build_shortlist",
    "collect_authoritative_records",
    "collect_poc_candidates",
    "extract_procedure_snippets",
    "flatten_assessment_map",
]
