# Pipeline

The improved evidence-driven research pipeline described in the implementation
handoff. The legacy PoC-only workflow remains archived under the
`baseline-poc-only-v1` git tag for traceability.

## Modules

| Module                       | Responsibility                                                       |
| ---------------------------- | -------------------------------------------------------------------- |
| `manifest.py`                | `RunManifest`, atomic `RunContext`, scope/limits, secret redaction   |
| `budget.py`                  | Hard resource gates per `ResourceLimits`                             |
| `ledger.py`                  | Append-only event ledger; allowed outcomes and failure classes       |
| `scope.py`                   | Full endpoint validation (IPv4/IPv6/hostname/URL/redirect/callback)  |
| `oracle.py`                  | `BenchmarkOracle` (independent proof) and `TextualMarkerChecker`      |
| `evaluator.py`               | Drives a variant runner through independent oracle adjudication      |
| `evidence.py`                | Service fingerprinting with observation/inference separation         |
| `sources.py`                 | CVE List V5, NVD, Vulnx, KEV, EPSS adapters; snapshot mode           |
| `candidates.py`              | `ExploitCandidate` interface + legacy `PocCandidate` reader           |
| `collectors.py`              | Method collectors: PoC, ExploitDB, Metasploit, Nuclei, Nmap NSE, etc. |
| `queue.py`                   | Deterministic applicability, ranking, and per-CVE shortlist          |
| `renderers.py`               | Structured argv-array renderers (no free-form shell)                 |
| `runner.py`                  | Top-level pipeline runner                                            |
| `benchmark.py`               | Benchmark manifests, metrics-from-events, reporting                  |

## Run modes

* **live** – real HTTP / filesystem reads; raw responses preserved.
* **snapshot** – only reads from a fixed source/candidate snapshot dir.
* **replay** – no retrieval or execution; reproduces metrics from stored events.

## Test layout

Tests live under `tests/pipeline/` and follow the milestone naming:

* `test_m1_foundation.py` – manifest / ledger / budget / scope / oracle / evaluator
* `test_m2_evidence_sources.py` – evidence normalization + source adapters
* `test_m3_candidates.py` – `ExploitCandidate` interface and collectors
* `test_m4_queue_runner.py` – queue, renderers, runner
* `test_m5_metrics_benchmark.py` – metrics-from-events + benchmark manifests
* `test_m5_acceptance.py` – handoff completion gates

## Hard limits (from the preregistration)

| Resource                  | Limit       |
| ------------------------- | ----------- |
| Runtime per target        | 20 minutes  |
| Tool calls                | 50          |
| Executed commands         | 40          |
| CVEs per service          | 5           |
| Methods per CVE           | 2           |
| Executed candidates       | 3           |
| Attempts per candidate    | 3           |

Provider, model, and temperature are frozen for primary comparisons.

## Outcome taxonomy

Allowed semantic outcomes (defined in `ledger.ALLOWED_OUTCOMES`):

* `vulnerability_confirmed`
* `task_proof_obtained` — only this counts toward the primary metric.
* `execution_failed`
* `not_applicable`
* `not_executable`
* `blocked_by_policy`
