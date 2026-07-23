# Baseline Metadata

**Tag:** baseline-poc-only-v1  
**Commit:** 72a46ec5f206e6a5255277d813f5c8d3b59e9f87  
**Date:** 2026-07-23T16:39:13Z  
**Branch:** main

## Environment

### Python
- **Version:** 3.12.12
- **Package Manager:** Poetry (installed)

### Security Tools
| Tool | Version | Notes |
|------|---------|-------|
| Nuclei | Framework (GOOGLE_API_KEY required for search) | Installed |
| Metasploit | 6.4.129-dev-37ff9f8530 | Platform: x86_64-unknown-linux-gnu |
| Nmap | 7.99 | Platform: x86_64-unknown-linux-gnu |
| Searchsploit | Installed | No --version flag; part of exploitdb package |
| Vulnx | Installed | No --version flag; Python package |

### Platform
- **OS:** Linux (x86_64-unknown-linux-gnu)

## Test Results

| Metric | Value |
|--------|-------|
| Total Tests | 179 |
| Passing | 179 |
| Failing | 0 |
| Errors | 0 |

**Test Discovery:** All test modules discoverable without import errors (lazy import fix applied to `utils/llm_factory.py`)

## Framework State

### Current Graph
```
recon → recon verifier → retrieval/evidence/hypothesis/critic → planner/skeptic/risk officer → execution → execution verifier → maintain access
```

### Operational Mode
- Fully autonomous (no human approval gates)
- PoC-only candidate model with local file path assumption
- Single vulnx backend for CVE retrieval
- Planner debate mechanism (planner/skeptic/risk officer)
- Unrestricted LLM shell fallback enabled
- Text marker-based success verification (uid=, root@, pwned, flags)

### Configuration
- **Model Provider:** vertexai (default)
- **Models Configured:** openai, deepseek, gemini, vertexai, ollama, vllm
- **Economic Mode:** Enabled
- **Max Candidates:** 3
- **Per Candidate Max Attempts:** 3
- **Command Timeout:** 120s
- **Verify Timeout:** 20s

## Key Issues Identified

### Fingerprinting Defects
- Protocol versions (HTTP/1.1) misidentified as application versions
- Dates, status codes, ports misidentified as versions
- Generic service aliases create false vendor/product identities
- Inferred CPEs can overwrite observed CPEs
- Unknown versions receive partial scores making weak candidates appear applicable

### Retrieval Defects
- Single vulnx backend (no CVE List V5, NVD adapters)
- Rate limit or outage eliminates live retrieval
- Local KEV file only enriches already-retrieved CVEs
- Raw source records and normalized records not preserved separately
- Stale `max_year: 2025` configuration

### Candidate Defects
- PocCandidate assumes local file path
- GitHub results cloned without commit/license/hash/advisory provenance
- Shallow repository scanning treats examples as executable instructions
- Only one candidate survives per CVE
- Trust scoring reflects CVE source rather than exploit artifact provenance
- Command/module methods cannot become normal candidates

### Planning Defects
- Planner/skeptic/risk officer debate consumes multiple LLM calls
- Reorders candidates that already have deterministic scores
- Does not address root causes: incorrect identity, weak applicability, incomplete procedures, unreliable proof

### Execution and Verification Defects
- Preflight rejects command-only candidates without file
- Scope checking primarily detects literal foreign IPv4 addresses
- Does not comprehensively cover hostnames, IPv6, URLs, redirects, callbacks
- Unrestricted LLM fallback can invent new shell commands
- Execution/verification depends on textual markers (uid=, root@, pwned, flags)
- Execution command can be replayed as verification if no verification procedure exists
- Maintain access mostly rechecks stored output
- Neither establishes nor evaluates persistence

### Metrics Defects
- End-to-end success from agent/executor state rather than external oracle
- Applicability precision uses plan difficulty labels
- "Useful" steps based on nonempty output
- Cost uses flat combined token rate
- Invalid-command rate uses episode counts instead of executed-command counts
- Hallucination inferred from invalidity and repetition
- Correct-CVE@k omitted from aggregate processing
- Success markers can create false positives on patched controls

## Changes in This Baseline

1. **Initialized as standalone git repository**
   - Was previously untracked in parent repo at `/home/dwyn/Research/test`
   - Created dedicated `.git` for pentest-agent_new

2. **Added comprehensive .gitignore**
   - Excludes credentials: `.env`, `*.key`, `*.pem`, `google-key.json`, `service_account*.json`
   - Excludes active config: `configs/config.yaml` (tracks `.example` template instead)
   - Excludes runtime artifacts: `data/`, `logs/`, `planning_output/`, `recon_memory/`, `recon_state.json`
   - Excludes scan outputs: `*.gnmap`, `*.nmap`, `*.xml`
   - Excludes IDE/linter caches, virtual environments

3. **Created configs/config.yaml.example**
   - Template with redacted secrets
   - Removed `max_year: 2025` from cvemap configuration
   - Replaced ngrok URLs with localhost placeholders
   - Tracks configuration structure without exposing credentials

4. **Fixed utils/llm_factory.py lazy imports**
   - Removed eager imports at module level
   - Moved provider-specific imports inside `create_llm()` methods
   - Prevents test discovery failures when optional packages not installed
   - Changed from 8 test import errors to 0 errors

## Next Milestones

Per the research handoff document, the implementation plan follows five milestones:

### M1: Common Evaluation Foundation
- Add run manifest, unique atomic directories
- Event ledger for structured metrics
- Resource-budget enforcement
- Oracle interface for independent verification
- External evaluator (baseline and improved variants use same ground truth)
- Full endpoint/scope validation
- Do not change retrieval behavior until measurement layer has golden tests

### M2: Fingerprinting and Source Adapters
- Separate observations from inferences
- Fix protocol/date/status version extraction
- Stop generic services from creating vendor/product identities
- Add independent CVE List V5 and NVD adapters
- Add cached KEV/EPSS enrichment
- Add live, snapshot, and replay modes
- Preserve raw and normalized source records separately

### M3: Candidate Interface and Collection
- Add ExploitCandidate interface and legacy reader adapter
- Add pinned Metasploit, Nuclei, NSE, ExploitDB, vendor/native collectors
- Implement deterministic IDs, hashes, trust states, license/reference metadata
- Preserve two method alternatives per CVE

### M4: Queue and Execution
- Introduce deterministic applicability and ranking
- Add method-specific renderers (Metasploit resource scripts, Nuclei templates, NSE scripts)
- Permit command/module candidates without local artifact paths
- Delete unrestricted LLM command generation
- Apply manifest scope validation to every procedure stage
- Continue to next applicable method after classified failure
- Replace "maintain access" with oracle proof recheck or remove

### M5: Metrics, Benchmark, and Documentation
- Recompute metrics solely from events and benchmark truth
- Add benchmark manifests, clean/noisy environments, patched controls, oracle adapters
- Add statistical-report generator and per-target result tables
- Update graph documentation, autonomous-operation disclosure, lab-only policy
- Freeze prompts, source snapshots, tools, templates, benchmark manifests before final runs

## Experimental Configuration

### Fixed Execution Configuration (for future variants)
- **Model:** VertexAI gemini-2.5-flash (exact deployed identifier to be recorded at freeze)
- **Temperature:** 0
- **Provider Fallback:** None
- **Repetitions:** 3 independent runs
- **Time Limit:** 20 minutes per target
- **Tool Call Limit:** 50
- **Command Limit:** 40 executed commands
- **CVE Limit:** 5 per service
- **Candidate Limit:** 3 executed candidates
- **Attempt Limit:** 3 bounded attempts per candidate
- **Identical limits across all variants**

### Experimental Variants (planned)
1. Frozen current PoC-only workflow
2. Current workflow + official fresh CVE sources
3. Current workflow + heterogeneous methods using frozen legacy CVE snapshot
4. Full source + arsenal improvement

### Benchmark Composition (planned)
- 10 vulnerable legacy targets (disclosed ≤2023)
- 10 vulnerable recent targets (2024–July 2026)
- At least 5 recent targets from 2025–2026
- 5 patched or non-vulnerable controls
- Network and web services only
- Clean and noisy conditions for each vulnerable target
- Mirrored noisy controls where feasible

## Verification

To verify this baseline:

```bash
# Check out the tag
git checkout baseline-poc-only-v1

# Run tests
python -m unittest discover tests/

# Expected: 179 tests, all passing

# Verify config template exists
ls configs/config.yaml.example

# Verify credentials are not tracked
git ls-files | grep -E "\.(env|key|pem)$|google-key\.json"
# Expected: no output

# Verify active config is not tracked
git ls-files | grep "configs/config.yaml$"
# Expected: no output (only .example should be tracked)
```

---

**Note:** This baseline documents the state before implementing the evidence-driven pipeline improvements. All subsequent milestones will build on this foundation while maintaining traceability to the original PoC-only implementation.
