"""
src/pipeline/collectors.py
──────────────────────────
Method-specific candidate collectors.

Each collector returns zero or more :class:`ExploitCandidate` records for one
CVE. Trust is set conservatively; only ``trusted`` and ``lab_approved``
candidates may execute. Unknown / unofficial GitHub results remain
``discovery_only``.

Pinning rules (enforced in v1):

  * Nuclei templates are pinned to a repository commit; template ID and
    classification are preserved. Nuclei updates are disabled by callers.
    Code / headless / self-contained / AI-generated / unsigned templates remain
    disabled.
  * Metasploit modules pin module name and revision; the simplest reproducible
    integration is a generated resource script driven by ``MSF_CFGROOT_CONFIG``.
  * ExploitDB and NSE scripts are read from locally indexed sources; their
    binary hashes and versions are captured.
"""

from __future__ import annotations

import glob
import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from src.pipeline.candidates import (
    ExploitCandidate, Provenance, ProcedureStep, derive_candidate_id,
    hash_artifact,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_text(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _binary_path(name: str) -> str | None:
    return shutil.which(name)


# ── PoC collector (trusted public) ───────────────────────────────────────────


@dataclass
class PublicPocSpec:
    """A trusted public PoC reference that ships inside the benchmark manifest."""

    cve_id: str
    repo: str                          # "owner/name" (no scheme)
    commit: str                        # pinned SHA
    entry_point: str                   # path inside the repo
    capability: str = "code_execution"
    license: str = "unknown"


def collect_public_poc(spec: PublicPocSpec, *, working_dir: str = "") -> ExploitCandidate:
    """Pin a public PoC to a specific commit and capture its hash.

    The local artifact is fetched only if missing; otherwise we re-hash from
    the existing checkout.
    """
    repo_path = os.path.join(working_dir, "_poc_cache", spec.repo.replace("/", "__"))
    if not os.path.exists(repo_path) or not _pinned_at_commit(repo_path, spec.commit):
        if working_dir:
            _fetch_pinned(repo_path, spec.repo, spec.commit, working_dir)
    entry_path = os.path.join(repo_path, spec.entry_point) if working_dir else ""
    sha = _file_sha256(entry_path) if entry_path and os.path.exists(entry_path) else ""
    prov = Provenance(
        revision=spec.commit, sha256=sha,
        references=[f"https://github.com/{spec.repo}"],
        license=spec.license,
        trust="trusted" if spec.license.lower() not in {"unknown", "private", ""} else "discovery_only",
        source_kind="github", advisory_ref=f"https://github.com/{spec.repo}@{spec.commit}",
    )
    procedure = [ProcedureStep(stage="execute",
                                 argv=["python3", spec.entry_point],
                                 timeout_seconds=60)]
    cand = ExploitCandidate(
        candidate_id=derive_candidate_id(kind="poc", cve_id=spec.cve_id,
                                            locator=spec.entry_point, provenance=prov),
        cve_id=spec.cve_id, kind="poc", source=spec.repo,
        locator=spec.entry_point, provenance=prov, procedure=procedure,
        capability=spec.capability, side_effect_class="remote_exploit",
        working_dir=repo_path, artifact_hash=sha,
    )
    return cand


def _pinned_at_commit(repo_path: str, commit: str) -> bool:
    head = os.path.join(repo_path, ".git", "HEAD")
    if not os.path.exists(head):
        return False
    out = subprocess.run(["git", "-C", repo_path, "rev-parse", "HEAD"],
                            check=False, capture_output=True, text=True, timeout=5).stdout.strip()
    return out.lower() == commit.lower()


def _fetch_pinned(repo_path: str, repo: str, commit: str, working_dir: str) -> None:
    os.makedirs(os.path.dirname(repo_path), exist_ok=True)
    subprocess.run(["git", "init", "-q", repo_path], check=False)
    subprocess.run(["git", "-C", repo_path, "remote", "add", "origin",
                    f"https://github.com/{repo}.git"], check=False)
    subprocess.run(["git", "-C", repo_path, "fetch", "-q", "--depth", "1", "origin", commit],
                    check=False, timeout=60)


# ── ExploitDB collector ─────────────────────────────────────────────────────


@dataclass
class ExploitDbSpec:
    cve_id: str
    edb_id: str
    local_path: str                   # path inside exploitdb/exploits
    capability: str = "code_execution"
    language: str = "unknown"

    def to_evidence(self) -> str:
        return f"exploitdb:{self.edb_id}"


def collect_exploitdb(spec: ExploitDbSpec) -> ExploitCandidate:
    """Index a local ExploitDB entry; trust is *lab_approved* (research use)."""
    sha = _file_sha256(spec.local_path) if os.path.exists(spec.local_path) else ""
    references = [f"https://www.exploit-db.com/exploits/{spec.edb_id}"]
    prov = Provenance(
        revision=f"edb-{spec.edb_id}", sha256=sha,
        references=references, license="unknown",
        trust="lab_approved",          # research-lab use only; not redistributed
        source_kind="exploitdb", advisory_ref=references[0],
    )
    if spec.language == "python":
        argv = ["python3", spec.local_path]
    elif spec.language in {"c", "cpp"}:
        argv = ["sh", "-c", f"cd {os.path.dirname(spec.local_path)} && make"]
    else:
        argv = ["sh", spec.local_path]
    return ExploitCandidate(
        candidate_id=derive_candidate_id(kind="exploitdb", cve_id=spec.cve_id,
                                            locator=f"edb:{spec.edb_id}", provenance=prov),
        cve_id=spec.cve_id, kind="exploitdb", source="exploitdb",
        # The EDB id, not an installation-specific path, is the stable locator.
        locator=f"edb:{spec.edb_id}", provenance=prov,
        procedure=[ProcedureStep(stage="execute", argv=argv, timeout_seconds=60)],
        capability=spec.capability, side_effect_class="remote_exploit",
        artifact_hash=sha, working_dir=os.path.dirname(spec.local_path),
        extra={"artifact_path": spec.local_path, "language": spec.language},
    )


# ── Metasploit collector ─────────────────────────────────────────────────────


@dataclass
class MetasploitSpec:
    cve_id: str
    module_name: str                  # e.g. exploit/multi/http/path_traversal
    options: dict[str, str] = field(default_factory=dict)
    rank: str = "manual"
    check_supported: bool = True
    capability: str = "code_execution"


def render_metasploit_resource_script(module: str, options: Mapping[str, str]) -> str:
    """Produce a run-local Metasploit resource script that drives the module.

    Per the handoff, the simplest reproducible integration is a resource
    script invoked via ``MSF_CFGROOT_CONFIG`` rather than a new RPC service.
    """
    lines = [f"use {module}", "set verbose true"]
    for k, v in options.items():
        lines.append(f"set {k} {v}")
    if options.get("PAYLOAD"):
        lines.append(f"set PAYLOAD {options['PAYLOAD']}")
    lines.append("check")
    lines.append("exploit -j")
    lines.append("sleep 5")
    lines.append("sessions -l")
    lines.append("exit")
    return "\n".join(lines) + "\n"


def collect_metasploit(spec: MetasploitSpec) -> ExploitCandidate:
    """Capture a Metasploit module reference; the renderer writes a run-local
    resource script and configuration root at execution time."""
    references = [
        f"https://www.rapid7.com/db/modules/{spec.module_name}",
        "https://docs.rapid7.com/metasploit/modules/",
    ]
    prov = Provenance(
        revision=spec.module_name, sha256="",
        references=references, license="BSD-3-Clause",
        trust="trusted", source_kind="metasploit",
        advisory_ref=references[0],
    )
    script = render_metasploit_resource_script(spec.module_name, spec.options)
    procedure = [
        ProcedureStep(stage="setup", argv=["msfconsole", "-q", "-r", "<MSF_RC>"],
                       timeout_seconds=30),
        ProcedureStep(stage="execute", argv=["msfconsole", "-q", "-r", "<MSF_RC>"],
                       timeout_seconds=120),
        ProcedureStep(stage="verify", argv=["msfconsole", "-q", "-r", "<MSF_RC_VERIFY>"],
                       timeout_seconds=30),
    ]
    return ExploitCandidate(
        candidate_id=derive_candidate_id(kind="metasploit", cve_id=spec.cve_id,
                                            locator=spec.module_name, provenance=prov),
        cve_id=spec.cve_id, kind="metasploit", source="metasploit",
        locator=spec.module_name, provenance=prov, procedure=procedure,
        capability=spec.capability, side_effect_class="remote_exploit",
        placeholders=["RHOSTS", "RHOST", "LHOST", "LPORT", "PAYLOAD"],
        extra={"resource_script": script, "options": dict(spec.options),
               "rank": spec.rank, "check_supported": spec.check_supported},
    )


# ── Nuclei collector ─────────────────────────────────────────────────────────


@dataclass
class NucleiSpec:
    cve_id: str
    template_id: str                  # e.g. CVE-2021-41773
    template_path: str                # local pinned template path
    classification: str               # e.g. cve, rce, sqli
    pinned_commit: str                # nuclei-templates repo commit
    capability: str = "detection"

    UNSAFE_CLASSIFICATIONS = {"code", "headless", "self-contained", "ai"}


def collect_nuclei(spec: NucleiSpec) -> ExploitCandidate:
    """Index a Nuclei template.

    Unsafe classifications (code, headless, self-contained, AI) are
    automatically rejected regardless of caller configuration. Frozen runs
    must pass ``update=false`` and ``disable-code/headless`` to ``nuclei`` at
    execution time.
    """
    if spec.classification.lower() in NucleiSpec.UNSAFE_CLASSIFICATIONS:
        raise ValueError(
            f"Unsafe Nuclei classification '{spec.classification}' is disabled by default."
        )
    sha = _file_sha256(spec.template_path) if os.path.exists(spec.template_path) else ""
    references = [
        "https://docs.projectdiscovery.io/templates/structure",
        "https://docs.projectdiscovery.io/opensource/nuclei/running",
    ]
    prov = Provenance(
        revision=spec.pinned_commit, sha256=sha,
        references=references + [f"https://github.com/projectdiscovery/nuclei-templates@{spec.pinned_commit}"],
        license="MIT",
        trust="trusted",
        source_kind="nuclei",
        advisory_ref=f"nuclei:{spec.template_id}",
    )
    argv = [
        "nuclei", "-update=false", "-duc", "-nc", "-t", spec.template_path,
        "-json-export", "<NUCLEI_OUTPUT>", "-disable-update-check",
    ]
    return ExploitCandidate(
        candidate_id=derive_candidate_id(kind="nuclei", cve_id=spec.cve_id,
                                            locator=spec.template_id, provenance=prov),
        cve_id=spec.cve_id, kind="nuclei", source="nuclei",
        locator=spec.template_id, provenance=prov,
        procedure=[ProcedureStep(stage="execute", argv=argv, timeout_seconds=60)],
        capability=spec.capability, side_effect_class="read_only",
        placeholders=["<NUCLEI_OUTPUT>"],
        artifact_hash=sha,
    )


# ── Nmap NSE collector ──────────────────────────────────────────────────────


@dataclass
class NmapNseSpec:
    cve_id: str
    script_name: str                  # e.g. http-vuln-cve2021-41773
    script_path: str                  # local NSE path
    script_args: list[str] = field(default_factory=list)
    capability: str = "detection"


def collect_nmap_nse(spec: NmapNseSpec) -> ExploitCandidate:
    if not spec.script_path:
        raise ValueError("NmapNseSpec.script_path is required")
    if not (os.path.exists(spec.script_path) or _binary_path("nmap")):
        raise ValueError(f"NSE script path missing: {spec.script_path}")
    sha = _file_sha256(spec.script_path) if os.path.exists(spec.script_path) else ""
    prov = Provenance(
        revision=os.path.basename(spec.script_path), sha256=sha,
        references=["https://nmap.org/nsedoc/"],
        license="GPL-2.0", trust="trusted",
        source_kind="nmap", advisory_ref=f"nmap:{spec.script_name}",
    )
    argv = ["nmap", "--script", spec.script_name, *spec.script_args, "<RHOST>"]
    return ExploitCandidate(
        candidate_id=derive_candidate_id(kind="nmap_nse", cve_id=spec.cve_id,
                                            locator=spec.script_name, provenance=prov),
        cve_id=spec.cve_id, kind="nmap_nse", source="nmap", locator=spec.script_name,
        provenance=prov,
        procedure=[ProcedureStep(stage="execute", argv=argv, timeout_seconds=120)],
        capability=spec.capability, side_effect_class="read_only",
        artifact_hash=sha,
    )


# ── Vendor / native collector ────────────────────────────────────────────────


@dataclass
class VendorRecipeSpec:
    cve_id: str
    vendor: str
    product: str
    steps: list[ProcedureStep]
    references: list[str] = field(default_factory=list)
    license: str = "vendor-documented"
    capability: str = "code_execution"


def collect_vendor_recipe(spec: VendorRecipeSpec) -> ExploitCandidate:
    prov = Provenance(
        revision=f"{spec.vendor}-{spec.product}", sha256="",
        references=list(spec.references), license=spec.license,
        trust="trusted", source_kind="vendor",
        advisory_ref=spec.references[0] if spec.references else "",
    )
    return ExploitCandidate(
        candidate_id=derive_candidate_id(kind="vendor_recipe", cve_id=spec.cve_id,
                                            locator=f"{spec.vendor}/{spec.product}", provenance=prov),
        cve_id=spec.cve_id, kind="vendor_recipe", source=spec.vendor,
        locator=f"{spec.vendor}/{spec.product}",
        provenance=prov, procedure=list(spec.steps),
        capability=spec.capability, side_effect_class="remote_exploit",
    )


@dataclass
class NativeToolSpec:
    cve_id: str
    tool_name: str
    argv: list[str]
    capability: str = "detection"
    references: list[str] = field(default_factory=list)


def collect_native_tool(spec: NativeToolSpec) -> ExploitCandidate:
    if not _binary_path(spec.tool_name):
        # Still record the candidate but mark trust as discovery_only; the
        # runner will block execution.
        trust = "discovery_only"
    else:
        trust = "trusted"
    prov = Provenance(
        revision=_binary_path(spec.tool_name) or spec.tool_name, sha256="",
        references=list(spec.references), license="unknown",
        trust=trust, source_kind="native",
        advisory_ref=spec.references[0] if spec.references else "",
    )
    return ExploitCandidate(
        candidate_id=derive_candidate_id(kind="native_tool", cve_id=spec.cve_id,
                                            locator=spec.tool_name, provenance=prov),
        cve_id=spec.cve_id, kind="native_tool", source=spec.tool_name,
        locator=spec.tool_name, provenance=prov,
        procedure=[ProcedureStep(stage="execute", argv=spec.argv, timeout_seconds=60)],
        capability=spec.capability, side_effect_class="read_only",
    )


# ── Index helpers (locally indexed method sources) ──────────────────────────


def index_exploitdb(root: str) -> list[ExploitDbSpec]:
    """Walk a local exploitdb checkout and produce per-CVE specs."""
    specs: list[ExploitDbSpec] = []
    if not os.path.isdir(root):
        return specs
    for path in glob.glob(os.path.join(root, "**", "*.py"), recursive=True):
        text = _file_text(path)
        m = re.search(r"CVE-(\d{4})-(\d{4,7})", text, re.IGNORECASE)
        if not m:
            continue
        edb_id_match = re.search(r"EDB-ID[:=\s]*(\d+)", text)
        specs.append(ExploitDbSpec(
            cve_id=f"CVE-{m.group(1)}-{m.group(2)}",
            edb_id=edb_id_match.group(1) if edb_id_match else os.path.basename(path),
            local_path=path,
            language="python",
        ))
    return specs


def index_nse_scripts(root: str) -> list[NmapNseSpec]:
    """Walk a local NSE script directory."""
    specs: list[NmapNseSpec] = []
    if not os.path.isdir(root):
        return specs
    for path in glob.glob(os.path.join(root, "**", "*.nse"), recursive=True):
        text = _file_text(path)
        m = re.search(r"CVE-(\d{4})-(\d{4,7})", text, re.IGNORECASE)
        if not m:
            continue
        specs.append(NmapNseSpec(
            cve_id=f"CVE-{m.group(1)}-{m.group(2)}",
            script_name=os.path.basename(path).replace(".nse", ""),
            script_path=path,
        ))
    return specs


def collect_for_cve(cve_id: str, *, specs: Iterable[Any]) -> list[ExploitCandidate]:
    """Filter candidate specs for one CVE and convert to ExploitCandidates."""
    out: list[ExploitCandidate] = []
    for spec in specs:
        if getattr(spec, "cve_id", "") != cve_id:
            continue
        kind = getattr(spec, "kind_marker", None) or _kind_of(spec)
        if kind == "poc":
            out.append(collect_public_poc(spec))
        elif kind == "exploitdb":
            out.append(collect_exploitdb(spec))
        elif kind == "metasploit":
            out.append(collect_metasploit(spec))
        elif kind == "nuclei":
            out.append(collect_nuclei(spec))
        elif kind == "nmap_nse":
            out.append(collect_nmap_nse(spec))
        elif kind == "vendor_recipe":
            out.append(collect_vendor_recipe(spec))
        elif kind == "native_tool":
            out.append(collect_native_tool(spec))
        elif kind == "guided_procedure":
            # guided_procedure candidates are created by the PlannerAgent,
            # not collected from specs.  Skip here.
            continue
    return out


def collect_from_records(
    records: Iterable[Any],
    *,
    specs: Iterable[Any] = (),
    candidates: Iterable[ExploitCandidate] = (),
    max_cves: int = 5,
) -> list[ExploitCandidate]:
    """Collect configured method candidates for the first retrieved CVEs."""
    cve_ids: list[str] = []
    for rec in records:
        cve_id = str(getattr(rec, "cve_id", "") or "").upper()
        if cve_id and cve_id not in cve_ids:
            cve_ids.append(cve_id)
        if len(cve_ids) >= max_cves:
            break
    out: list[ExploitCandidate] = []
    seen: set[str] = set()
    existing = list(candidates or [])
    for cve_id in cve_ids:
        for cand in [c for c in existing if c.cve_id.upper() == cve_id]:
            if cand.candidate_id not in seen:
                out.append(cand)
                seen.add(cand.candidate_id)
        for cand in collect_for_cve(cve_id, specs=specs):
            if cand.candidate_id not in seen:
                out.append(cand)
                seen.add(cand.candidate_id)
    return out


def _kind_of(spec: Any) -> str:
    name = type(spec).__name__.lower()
    if "publicpoc" in name or "pocspec" in name:
        return "poc"
    if "exploitdbspec" in name:
        return "exploitdb"
    if "metasploitspec" in name:
        return "metasploit"
    if "nucleispec" in name:
        return "nuclei"
    if "nmapnsespec" in name:
        return "nmap_nse"
    if "vendorrecipespec" in name:
        return "vendor_recipe"
    if "nativetoolspec" in name:
        return "native_tool"
    if "guidedprocedurespec" in name:
        return "guided_procedure"
    return "unknown"
