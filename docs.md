# PentestAgent — Technical Documentation

> **Research-grade autonomous penetration testing framework built on LangGraph.**
> Replaces naive LLM guessing with evidence-grounded reasoning, structured 3-tier memory, and strict multi-agent quality verification.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Graph Topology](#2-graph-topology)
3. [3-Tier Memory System](#3-3-tier-memory-system)
4. [Phase 1 — Reconnaissance](#4-phase-1--reconnaissance)
5. [Phase 2 — Hypothesis Generation](#5-phase-2--hypothesis-generation)
6. [Phase 3 — Planning (Debate Mechanism)](#6-phase-3--planning-debate-mechanism)
7. [Phase 4 — Execution](#7-phase-4--execution)
8. [Phase 5 — Maintaining Access](#8-phase-5--maintaining-access)
9. [Verifier Quality Gates](#9-verifier-quality-gates)
10. [CVE Scoring Pipeline](#10-cve-scoring-pipeline)
11. [Observability — Structured Logging & Metrics](#11-observability--structured-logging--metrics)
12. [Setup & Installation](#12-setup--installation)
13. [Configuration Reference](#13-configuration-reference)
14. [CLI Reference](#14-cli-reference)
15. [Shell Execution Model](#15-shell-execution-model)
16. [Project Structure](#16-project-structure)

---

## 1. Architecture Overview

PentestAgent is a **stateful, multi-agent system** where every component communicates through a shared `PentestState` TypedDict. There is no ad-hoc messaging between agents — all coordination happens through LangGraph's state graph.

### Key Design Principles

| Problem (Common in LLM Agents) | Solution in PentestAgent |
|---|---|
| Context loss over long sessions | 3-tier memory (WorldState + Episodic + Decision) with compact summary injection |
| LLM hallucinating CVE matches | Evidence-chain hypothesis generation with programmatic version range checks |
| Repeated/looping actions | Episodic memory O(1) dedup + Verifier repetition detection |
| Unchecked exploit execution | Multi-agent Debate (Planner→Skeptic→Risk Officer) + Human approval gate |
| No cost/quality accountability | 3-tier memory verifier, evidence-grounded retrieval pipeline, 15-metric evaluation system, structured JSONL logging |

---

## 2. Graph Topology

The orchestration runs as a `StateGraph` compiled by LangGraph with disk-backed checkpointing.

```
START → recon → recon_verifier → hypothesis → hypothesis_verifier
            ↑         │ block              ↑            │ need_recon
            └─────────┘                    └────────────┘
                                                  │ pass
                                          [planning sub-graph]
                                           planner → skeptic
                                               ↑        │
                                               └─ risk_officer
                                                      │ APPROVE
                                              finalize_planning
                                                      │
                                          ━━━ HUMAN APPROVAL ━━━
                                                      │
                                                 execution → execution_verifier
                                                      ↑             │ continue
                                                      └─────────────┘
                                                                │ success
                                                       maintain_access → END
                                                                │ exhausted
                                                               END
```

### Node Summary

| Node | File | Role |
|------|------|------|
| `recon` | `src/agents/recon.py` | Discovery via shell tools; incremental WorldState update |
| `recon_verifier` | `src/agents/verifier.py` | Programmatic + LLM consistency check |
| `hypothesis` | `src/agents/hypothesis.py` | Evidence-grounded CVE hypothesis generation |
| `hypothesis_verifier` | `src/agents/verifier.py` | Filters weak/unsupported hypotheses |
| `planner` | `src/agents/planning.py` | Proposes exploit plan using CVE/exploit search tools |
| `skeptic` | `src/agents/planning.py` | Critiques plan; detects rabbit holes via episodic memory |
| `risk_officer` | `src/agents/planning.py` | APPROVE/REJECT verdict; forces forward after 2 rounds |
| `finalize_planning` | `src/agents/planning.py` | Parallel exploit search + scoring pipeline |
| `execution` | `src/agents/execution.py` | LLM-driven exploit execution with shell tool |
| `execution_verifier` | `src/agents/verifier.py` | Success marker detection + step cap |
| `maintain_access` | `src/agents/maintain_access.py` | Re-verifies access using the stored session artifact |

### Checkpointing & Resume

The graph uses `_DiskBackedSaver` (a thin wrapper over LangGraph's `MemorySaver` that pickles state to `data/checkpoints/<thread_id>.pkl`). Any run can be **resumed from the exact checkpoint** after a crash or manual stop by reusing the same `--thread-id`.

---

## 3. 3-Tier Memory System

All memory lives in `src/memory/` and is serialised into `PentestState` as plain dicts for LangGraph compatibility.

### WorldState (`memory/world_state.py`)

Structured graph of `Host → Service → Version` with per-claim confidence scores and evidence chains.

```python
WorldState
  └── hosts: dict[ip → HostInfo]
        └── services: list[ServiceInfo]
              ├── port, name, version, banner
              ├── confidence: float   # 0.0–1.0
              └── evidence: list[str] # raw tool outputs

  ├── credentials: list[Credential]
  └── sessions: list[Session]        # populated by maintain_access
```

- **Incremental updates**: WorldState is updated after **every** nmap/probe tool call during recon (not just at done=true). The `_parse_nmap_services()` helper in `recon.py` extracts services from raw stdout via regex.
- **Confidence-gated**: Verifiers and hypothesis agent query `get_services_above_confidence(threshold)` to skip noise.
- **`to_summary()`**: Emits a compact text representation injected into LLM prompts.

### Episodic Memory (`memory/episodic.py`)

Append-only log of every action, tool call, and verifier check.

```python
Episode
  ├── step, timestamp, phase
  ├── action_type: "tool_call" | "llm_inference" | "verifier_check"
  ├── command, args, output_summary
  ├── outcome: "success" | "fail" | "timeout" | "blocked" | "error"
  ├── tokens_used: int
  └── was_repeat: bool   # O(1) set lookup
```

Key methods:
- `log(ep)` — auto-marks `was_repeat` via command+args dedup set
- `count_repeats()` — drives M13 Repeated Action Rate
- `count_recoveries()` — drives M15 Recovery Rate
- `to_context_summary(max_entries=15)` — compact text for prompt injection

### Decision Memory (`memory/decision.py`)

Records *why* each decision was made, enabling contradiction detection and ablation analysis.

```python
Decision
  ├── step, phase, question, chosen
  ├── alternatives: list[str]
  ├── reasoning: str
  ├── evidence_refs: list[int]   # episodic step indices
  ├── confidence: float
  └── outcome: "pending" | "validated" | "invalidated"
```

The Skeptic reads `decision_memory` to flag if the Planner is re-proposing a CVE that was already marked `invalidated`.

---

## 4. Phase 1 — Reconnaissance

**File**: `src/agents/recon.py`

The recon agent is a LangGraph node that loops: `LLM call → tool execution → WorldState update`.

### Flow

1. LLM is bound to `run_shell` tool (nmap, curl, nc, etc.)
2. Each tool response is parsed by `_parse_nmap_services()` → services upserted into WorldState immediately
3. When the LLM outputs `{"done": true, "port_services": {...}}`, the node builds a final WorldState merge and marks `recon_complete = True`
4. Graph routes to `recon_verifier`

### Incremental WorldState Parsing

```python
# After each tool call (not just at done=true):
ws = _update_world_state_from_output(ws, target_ip, tool_result, cmd)
```

The regex `_PORT_RE` extracts `port/proto  state  service  [banner/version]` from standard nmap output. Version numbers are pulled from the banner via `_VERSION_RE`.

### Token Tracking

After every LLM call: `tokens_in, tokens_out = extract_token_usage(response)`. Supports `usage_metadata` (OpenAI/Anthropic), `response_metadata` (Ollama/vLLM), and falls back to character-count estimation.

---

## 5. Phase 2 — Hypothesis Generation

**File**: `src/agents/hypothesis.py`

### Pipeline (per service)

```
Service (WorldState)
  → search_cve(name + version)
  → get_cve_detail(cve_id)
  → _version_in_range(svc.version, detail)
  → _extract_prerequisites(description, llm)  ← LLM call
  → _check_prerequisites_against_world_state(prereq_data, ws, port, ip)
  → _compute_confidence(...)
  → VulnHypothesis
```

### Prerequisite Compatibility Checker

`_check_prerequisites_against_world_state()` verifies each extracted prerequisite against known world-state facts:

| Prerequisite | World State Check |
|---|---|
| `auth_required` | Checks `ws.credentials` — marks `met` if credentials known, `unknown` otherwise |
| `remote_exploitable` | Checks `ws.hosts[ip].services[port].accessibility == "open"` |
| OS requirement | Matches prerequisite text against `ws.hosts[ip].os_hint` using keyword sets (`_WINDOWS_HINTS`, `_LINUX_HINTS`) |

- If any prerequisite is `unmet` (confirmed OS mismatch), confidence is penalised × 0.5.
- `prerequisites_status` dict is stored in each `VulnHypothesis` for traceability.

### Confidence Formula

```python
confidence = (
    service_confidence * 0.40 +
    version_in_range   * 0.30 +
    has_exploit_code   * 0.20 +  # False here; updated to 0.9× by planning
    prereq_bonus       * 0.10    # prereqs_met / prereqs_total
)
# OS mismatch penalty: × 0.5
```

`execution_readiness` starts at `confidence × 0.5` and is updated to `confidence × 0.9` by `finalize_planning_node` when actual exploit code is found.

---

## 6. Phase 3 — Planning (Debate Mechanism)

**File**: `src/agents/planning.py`

### Planner

Uses `PLANNING_TOOLS` (`search_cve`, `get_cve_detail`, `search_exploitdb`, `search_github`, `filter_cves_by_version`) to build an exploit plan. Outputs `current_proposal` dict into state.

### Skeptic (with Rabbit Hole Detection)

The Skeptic receives not only the Planner's proposal but also a **failed attempts summary** built from episodic and decision memory:

```python
def _build_failed_attempts_summary(state) -> str:
    # Reads: em.by_phase("execution") → failed outcomes
    # Reads: dm._decisions → invalidated CVE decisions
    # Reports: repeat count warning
```

The Skeptic prompt instructs it to flag any CVE/exploit that appears in the failed summary as a **rabbit hole**.

### Risk Officer

Issues `APPROVE` or `REJECT` based on the debate. Auto-approves after 2 rounds to prevent infinite loops.

### Resource Limits

The framework applies internal resource guards (token count, step count, LLM-request count, retry count) to prevent runaway execution.

- **Soft pressure**: resource usage is injected into planner prompts and candidate ranking
- **Replan threshold**: debate is skipped once step/token utilization crosses the configured threshold
- **Hard caps**: if a hard cap is reached, planning finalizes the best available shortlist deterministically

### finalize_planning_node

After APPROVE:
1. Runs parallel exploit searches (GitHub + ExploitDB) for all CVEs
2. Calls the CVE scoring pipeline (`get_exp_info`)
3. Merges scores into `exploit_plan` via `merge_scores()`
4. **Updates `execution_readiness`** in `vuln_hypotheses`: any hypothesis whose CVE has confirmed exploit code gets `readiness = confidence × 0.9`, `has_exploit_code = True`

---

## 7. Phase 4 — Execution

**File**: `src/agents/execution.py`

Loops: `LLM call → tool call → episodic memory log → execution_verifier`.

- Uses `run_shell` in `execution` mode with permissive command execution
- `[BLOCKED]` tool results → `total_invalid_commands += 1`
- All token usage tracked via `extract_token_usage(response)`
- Structured log emitted per LLM call and per tool call via `slog`
- Hard caps are enforced before additional retries or LLM fallbacks; exhausted runs end with an explicit limit-exhausted reason

### Human-in-the-Loop Gate

The graph is compiled with `interrupt_before=["execution"]`. The CLI presents the exploit plan and requires explicit `y` approval before any exploit is run.

---

## 8. Phase 5 — Maintaining Access

**File**: `src/agents/maintain_access.py`

**Passive-only** session verification after a successful exploit.

### Flow

1. Runs lightweight probes (`id`, `whoami`, `hostname`) through the established channel
2. `_is_session_alive(output)` checks for session alive/dead markers
3. `_detect_privilege(output)` parses `uid=0(root)` / `uid=N(username)` patterns
4. Updates `WorldState.sessions` with a verified `Session` object
5. Optional lightweight LLM summary of session context (uses `verifier` model)
6. Sets `session_verified`, `session_alive`, `session_privilege_level` in state

Session info stored in WorldState:
```python
Session(
    session_type = "shell" | "ssh" | "meterpreter",
    target_ip    = ...,
    privilege_level = "root" | "www-data" | "<username>",
    is_alive     = True,
)
```

---

## 9. Verifier Quality Gates

**File**: `src/agents/verifier.py`

Three verifier nodes act as strict quality gates that can send the agent backward or forward.

### Recon Verifier

1. **Programmatic check**: `_check_recon_sufficiency(ws)` — needs ≥1 service with confidence ≥ 0.5 and at least one version identified
2. **Repetition check**: `_check_repetition(em, "recon")` — if stuck, force proceed
3. **LLM consistency check** *(new)*: If programmatic check passes, queries the LLM (using `config.verifier.model`) with the WorldState summary to detect banner mismatches or impossible version combinations. Conflicts are logged as informational (do not block).

### Hypothesis Verifier

- Blocks hypotheses with `evidence_chain < 2` items or `confidence < 0.3`
- Forces forward if agent is stuck or max blocks reached

### Execution Verifier

- Scans recent episodic output for **success markers** (`uid=0`, `flag{`, `Meterpreter session`, `$` shell prompt, etc.)
- Returns `"end"` (→ `maintain_access`) on success
- Returns `"exhausted"` (→ `END`) when step limit hit
- Returns `"execution"` to continue looping

---

## 10. CVE Scoring Pipeline

**Files**: `src/scoring/calculator.py`, `src/rag/doc_handler.py`

The scoring pipeline evaluates exploit repositories for each candidate CVE.

### Modes

| Mode | Description | Trade-off |
|------|-------------|-----------|
| `economic_mode=True` | Single direct-score LLM query per repo | Faster, ~30% cheaper |
| `economic_mode=False` | Multi-feature analysis (vul_type, exp_maturity, isRemote, attack_complexity) | More accurate |

### Score Computation

```
final_score = _get_final_score(functionality_score, complexity_score)
            × source_weight   # ExploitDB=1.1, GitHub=1.0, Google=0.85
            + trending_score × weight
```

Classification: `easy` (>50), `medium` (>35), `hard` (≤35)

### CVE Search Tools (`src/tools/cve_search.py`)

| Tool | Description |
|------|-------------|
| `search_cve` | Query `cvemap`/`vulnx` by CVE ID or product name |
| `get_cve_detail` | Fetch CVSS, EPSS, affected products, PoC refs |
| `search_exploitdb` | Local `searchsploit` search, copies files to output_dir |
| `search_github` | GitHub search + clone highest-scoring repos |
| `filter_cves_by_version` | Filter CVE list by target version range |

---

## 11. Observability — Structured Logging & Metrics

### Structured JSONL Logger (`src/utils/structured_logger.py`)

Every node emits JSON events to `logs/structured.jsonl` (append-only, one object per line):

```jsonc
// Node event (LLM call)
{"event": "node", "node": "recon", "step": 3, "tokens_in": 420, "tokens_out": 180, "duration_ms": 1840, "outcome": "ok"}

// Tool event
{"event": "tool", "node": "execution", "tool": "run_shell", "command": "curl http://...", "outcome": "success", "blocked": false}

// Phase lifecycle
{"event": "phase", "phase": "planning", "type": "complete", "cves": 4, "exploits": 2, "cves_with_code": 1}

// Run summary
{"event": "run_summary", "target_ip": "10.0.0.1", "execution_success": true, "total_tokens": 18420, ...}
```

Use `get_structured_logger()` singleton anywhere. Use `extract_token_usage(response)` to extract `(tokens_in, tokens_out)` from any LangChain response object.

### Metrics Collector (`src/utils/metrics_collector.py`)

After each `run` command, metrics are automatically exported to `data/runs/<thread_id>-metrics.json`.

#### The 15 Evaluation Metrics

| # | Metric | Key in JSON | Source |
|---|--------|-------------|--------|
| M1 | Overall Success Rate | `M1_osr` | `execution_success` |
| M2 | Step-wise Success Rate | `M2_ssr` | Phase completion flags |
| M3 | Service ID Accuracy | `M3_service_id_accuracy` | Ground truth comparison |
| M4 | Correct-CVE@k | `M4_correct_cve_at_5` | Ground truth comparison |
| M5 | Exploit Applicability Precision | `M5_exploit_applicability_precision` | Exploit plan scoring |
| M6 | Attack Path Efficiency | `M6_attack_path_efficiency` | Episodic memory |
| M7 | Total LLM Requests | `M7_total_llm_requests` | `total_llm_requests` |
| M8 | Token Consumption | `M8_tokens_in/out/total` | `total_tokens_in/out` |
| M9 | Cost per Target (USD) | `M9_cost_usd` | M8 × price/1k |
| M10 | Cost per Success (USD) | `M10_cost_per_success_usd` | M9 if M1=1 |
| M11 | Time-to-Access (sec) | `M11_time_to_access_sec` | `phase_timestamps` |
| M12 | Invalid Command Rate | `M12_invalid_command_rate` | `total_invalid_commands` |
| M13 | Repeated Action Rate | `M13_repeated_action_rate` | `EpisodicMemory.count_repeats()` |
| M14 | Hallucination Failure Rate | `M14_hallucination_failure_rate` | Heuristic (blocked + repeats) |
| M15 | Recovery Rate | `M15_recovery_rate` | `EpisodicMemory.count_recoveries()` |

In addition to M1-M15, exported metrics include a `budget_report` block with utilization, exhaustion cause, and evidence-gain-per-1k-tokens as an engineering/debugging feature.

#### Ground Truth Format (for M3/M4)

```json
{
  "target_ip": "10.0.0.1",
  "correct_services": {
    "80": {"name": "apache", "version": "2.4.49"},
    "22": {"name": "openssh", "version": "8.2"}
  },
  "correct_cves": ["CVE-2021-41773", "CVE-2021-42013"],
  "flag": "HTB{some_flag}",
  "notes": "VulHub lab: Apache path traversal"
}
```

Pass via `--ground-truth path/to/gt.json` on the CLI.

#### Aggregating Multiple Runs

```python
from src.utils.metrics_collector import MetricsCollector

MetricsCollector.aggregate_runs(
    ["data/runs/run1-metrics.json", "data/runs/run2-metrics.json"],
    "data/runs/summary.json"
)
# Outputs mean ± std for every numeric metric
```

---

## 12. Setup & Installation

### Prerequisites

- Python 3.10+
- System tools: `nmap`, `curl`, `searchsploit` (from `exploitdb`)
- ProjectDiscovery tools: `cvemap` / `vulnx` (for CVE lookup)
- At least one LLM backend (API key or local Ollama/vLLM)

### Installation

```bash
# 1. Clone
git clone <repo_url> pentest-agent && cd pentest-agent

# 2. Install Python dependencies
pip install -r requirements.txt
# or with Poetry:
poetry install

# 3. Configure environment
cp .env.example .env
# Edit .env: add API keys
```

### Environment Variables

```env
OPENAI_API_KEY=sk-...
DEEPSEEK_API_KEY=sk-...
GOOGLE_API_KEY=...
# For local backends (Ollama/vLLM), no key needed — set base_url in config.yaml
```

---

## 13. Configuration Reference

**File**: `configs/config.yaml`

```yaml
models:
  openai:
    provider: openai
    model: gpt-4o-mini
    temperature: 0
    timeout: 300
    api_key: ${OPENAI_API_KEY}

  deepseek:
    provider: deepseek
    model: deepseek-chat
    api_key: ${DEEPSEEK_API_KEY}

  ollama:
    provider: ollama
    model: qwen3.5:9b
    base_url: "http://localhost:11434"
    api_key: "ollama"

  vllm:
    provider: openai          # vLLM exposes OpenAI-compatible API
    model: qwen3.6-27b
    base_url: "https://your-vllm-endpoint/v1/"
    api_key: "sk-placeholder"

runtime:
  recon:
    model: "vllm"             # Model used by recon agent
    target_ip: "10.0.0.1"
    recon_max_steps: 12

  verifier:
    model: "vllm"             # Model used by LLM recon verifier
                              # Set to "deepseek" to save tokens

  planning:
    economic_mode: true       # true = cheaper single-query scoring
    model: "vllm"
    output_dir: "../data/exp_info"
    cvemap:
      max_entry: 10
      max_year: 2013
      min_year: 2015

  execution:
    model: "vllm"
    target_ip: "10.0.0.1"
    attacker_ip: "127.0.0.1"
    execution_max_steps: 30
```

To switch models: edit `runtime.<phase>.model` to any key defined in `models:`.

---

## 14. CLI Reference

```
python main.py <command> [options]
```

### `run` — Full Pipeline

```bash
python main.py run \
  --target 10.0.0.1 \
  --attacker 10.0.0.2 \
  --recon-steps 12 \
  --exec-steps 30 \
  --thread-id my-pentest-001 \
  --ground-truth ./labs/target1-gt.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | required | Target IP address |
| `--attacker` | `""` | Attacker/callback IP |
| `--thread-id` | auto UUID | Thread ID for checkpoint resume |
| `--recon-steps` | `12` | Max recon iterations |
| `--exec-steps` | `30` | Max execution iterations |
| `--ground-truth` | `""` | Path to ground-truth JSON (enables M3/M4) |

> **Human approval gate**: The agent pauses before execution and prints the exploit plan. Type `y` to proceed or `N` to abort.

### `recon` — Reconnaissance Only

```bash
python main.py recon --target 10.0.0.1 --recon-steps 15
```

### `plan` — Planning Only

```bash
python main.py plan --app apache --version 2.4.49 --target 10.0.0.1
```

### `execute` — Execution Only

```bash
python main.py execute \
  --target 10.0.0.1 \
  --port 80 \
  --attacker 10.0.0.2 \
  --doc-dir ./data/exp_source/CVE-2021-41773 \
  --exec-steps 20
```

### Resume a Previous Run

```bash
# Thread ID is printed at the start of every run
python main.py run --target 10.0.0.1 --thread-id 550e8400-e29b-41d4-a716-446655440000
```

### Aggregate Metrics Across Runs

```python
from src.utils.metrics_collector import MetricsCollector

MetricsCollector.aggregate_runs(
    ["data/runs/run-A-metrics.json", "data/runs/run-B-metrics.json"],
    "data/runs/aggregated.json",
)
```

---

## 15. Shell Execution Model

**File**: `src/tools/shell.py`

Shell execution is intentionally permissive.

### Runtime Behavior

```
command_string
  → empty / placeholder check
  → subprocess.run(..., shell=True)
```

The only built-in rejection is an empty or placeholder command such as `None`.
Operational safety relies on the human approval gate before exploitation and operator control of the runtime environment.

---

## 16. Project Structure

```
pentest-agent/
├── main.py                     # CLI entry point
├── configs/
│   └── config.yaml             # All configuration (models, runtime, scoring weights)
├── src/
│   ├── state.py                # PentestState TypedDict — shared agent state
│   ├── graph.py                # LangGraph StateGraph — orchestration topology
│   ├── config.py               # AppConfig singleton (loads config.yaml)
│   ├── agents/
│   │   ├── recon.py            # Phase 1: Reconnaissance + incremental WorldState
│   │   ├── hypothesis.py       # Phase 2: Evidence-grounded CVE hypothesis
│   │   ├── planning.py         # Phase 3: Planner + Skeptic + Risk Officer + finalize
│   │   ├── execution.py        # Phase 4: Exploit execution
│   │   ├── maintain_access.py  # Phase 5: Passive session verification
│   │   └── verifier.py         # Quality gates (recon, hypothesis, execution)
│   ├── memory/
│   │   ├── world_state.py      # WorldState: Host/Service/Credential/Session graph
│   │   ├── episodic.py         # EpisodicMemory: append-only action log
│   │   └── decision.py         # DecisionMemory: decision audit trail
│   ├── tools/
│   │   ├── shell.py            # run_shell @tool with permissive execution
│   │   └── cve_search.py       # CVE/exploit search tools (cvemap, ExploitDB, GitHub)
│   ├── scoring/
│   │   ├── calculator.py       # CVE exploit scoring (full + economic mode)
│   │   └── merge.py            # Merge per-CVE scores into ranked plan
│   ├── rag/
│   │   └── doc_handler.py      # LlamaIndex-based exploit repo analysis
│   └── utils/
│       ├── structured_logger.py # Structured JSONL event logger + token extractor
│       ├── metrics_collector.py # 15-metric evaluation system + aggregation
│       ├── tool_compat.py       # Fallback JSON→tool_calls parser for non-native backends
│       ├── json_parser.py       # Shared JSON extraction utility
│       └── logging_config.py   # Rotating file + console logging setup
├── data/
│   ├── checkpoints/            # Per-thread pickle checkpoints (auto-created)
│   ├── exp_info/               # CVE scoring output (features, classifications)
│   └── runs/                   # Per-run metrics JSON exports
└── logs/
    ├── pentest-agent.log       # Standard rotating log
    └── structured.jsonl        # Structured JSONL event stream
```
