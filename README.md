# PentestAgent

## Overview

**PentestAgent** is an LLM-driven penetration testing framework that automates intelligence gathering, vulnerability analysis, and exploitation on disposable research targets. The framework is **fully autonomous** and operates against owned or explicitly authorised lab environments only.

The research pipeline (current default) is an evidence-driven graph:

```
recon -> frozen retrieval/catalog -> planner -> critic -> verifier ->
executor -> deterministic runner -> verifier/recovery -> independent oracle
```

The active LangGraph default now runs this pipeline directly:
`recon -> pipeline_prepare -> pipeline_retrieve -> pipeline_queue ->
pipeline_planner -> pipeline_critic -> pipeline_verifier -> pipeline_execute`.
The legacy PoC-only graph is kept only
for variant 1 baseline runs under the `baseline-poc-only-v1` git tag.

The framework is modular:

- **Reconnaissance** collects structured observations per service.
- **Evidence normalization** rejects protocol / date / status codes as
  versions, separates observed from inferred CPEs, and assigns an
  applicability grade.
- **CVE source collection** uses independent adapters (CVE List V5, NVD,
  CISA KEV, FIRST EPSS). A failed or rate-limited backend never fails the
  others.
- **Candidate collection** indexes Metasploit, Nuclei, Nmap NSE, ExploitDB,
  trusted public PoCs, vendor recipes, and native tools. Only trusted or
  manifest-approved lab candidates may execute.
- **Deterministic queue** ranks candidates and enforces a hard
  max-5-CVEs-per-service / max-2-methods-per-CVE shortlist.
- **Policy preflight** validates every endpoint (IPv4, IPv6, hostname, URL,
  scheme, port, redirect, callback) against the manifest scope.
- **Method execution** renders structured argv arrays; no free-form shell.
- **Multi-agent gate** makes Planner, Restore Planner, Critic, Verifier, and
  Executor model-backed roles; deterministic scope, budget, and proof checks
  remain authoritative.
- **Independent oracle** consumes benchmark evidence directly; agent
  explanations never prove success.

For the original paper description, see [PentestAgent on arXiv](https://arxiv.org/abs/2411.05185).

> **Lab-only policy.** This framework is for disposable research
> environments only. Do not point it at production systems or networks you
> do not own. No persistence, credential harvesting, lateral movement, or
> evasion testing is included.

---

## 🔧 Installation & Setup

> **Note:** We recommend deploying this project on a **Kali Linux** environment for better compatibility with penetration testing tools and workflows.

### 1. Clone the Repository

```
git clone https://github.com/nbshenxm/pentest-agent.git
cd pentest-agent
```

------

### 2. Set Environment Variables

Several environment variables need to be filled in. If you are not familiar with environment variables, set them in the `.env` file.

**Required:**
- `PDCP_API_KEY`: ProjectDiscovery API key for accessing CVE data and vulnerability information.
- `GITLAB_TOKEN`: GitLab token for ExploitDB access. 
- `GITHUB_KEY`: GitHub token for searching repositories and issues.
- `INDEX_STORAGE_DIR`: Directory to store vector indexes for RAG.
- `PLANNING_OUTPUT_DIR`: Directory to save planning results.
- `LOG_DIR`: Directory to store logs.

**Optional:**
- `http_proxy`, `https_proxy`: If using a proxy or VPN.

------

### 3. Install Python Dependencies

Python version: **3.12**

Use a virtual environment:

```
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

or with Conda:

```
conda create -n pentest python=3.12
conda activate pentest
python -m pip install -r requirements.txt
```

------

### 4. Install CVEMAP

[CVEMAP](https://github.com/projectdiscovery/cvemap) is needed to fetch CVE-related information. Follow their [installation](https://github.com/projectdiscovery/cvemap?tab=readme-ov-file#installation) instructions.

------

## ⚙️ Configuration

### File: `configs/config.yaml`

#### **(1) models**
 
Specify the LLM provider, model name, temperature, and API key.

#### **(2) cve**

Set the model used for parsing CVE entries and its generation temperature.

#### **(3) cve_scoring**

Scoring criteria for evaluating CVEs:

- Vulnerability type
- Exploit maturity
- Remote exploitability
- Attack complexity
- Source weighting (ExploitDB, GitHub, Google)

#### **(4) runtime**

**Reconnaissance Agent:**

- `current_topic`: Topic identifier for current CVE task.
- `target_ip`: IP address of the target host.

**Planning Agent:**

- `model`: LLM Model used for searching exploits and analyzing vulnerability data.
- `keyword`, `app`, `version`: Target application details.
- `vuln_type`: Type of vulnerability to focus on.
- `cvemap_fuzzy_search`: Enable fuzzy search for CVE matching.
- `output_dir`: Directory to save analysis results.

**Execution Agent:**

- `current_topic`: Task/topic identifier.
- `doc_dir`: Directory containing exploit scripts or documents.
- `target_ip`, `target_port`: IP and port of target host.
- `attacker_ip`: IP of attacker's machine.
- `command_to_execute`: Payload to validate exploitation.
- `model`: LLM Model used for exploit execution guidance.
------

## 🚀 Running the Framework

### New evidence-driven pipeline (recommended)

```python
from src.pipeline.runner import PipelineRunner, ReconObservation
from src.pipeline.manifest import Scope, new_manifest
from src.pipeline.ledger import EventLedger
from src.pipeline.budget import ResourceBudget, ResourceLimits
from src.pipeline.oracle import TargetTruth, ProofSpec

manifest = new_manifest("lab-target-1", variant="4", condition="clean",
                          scope=Scope(allowed_networks=["10.0.0.0/24"],
                                       allowed_ports=[80, 443, 4444],
                                       callback_endpoints=["10.0.0.99"]))
ledger = EventLedger(manifest.run_id)
budget = ResourceBudget(ResourceLimits(**manifest.limits))
manifest.oracle_spec = {"cve_id": "CVE-2021-41773",
                          "capability": "code_execution",
                          "truth": TargetTruth("lab-target-1",
                                                applicable_cves=["CVE-2021-41773"],
                                                proof_specs={"CVE-2021-41773":
                                                                  ProofSpec(capability="code_execution",
                                                                              accepted_evidence=["uid=0"])})}

runner = PipelineRunner(manifest=manifest, ledger=ledger, budget=budget,
                          scope=Scope.from_dict(manifest.scope))
result = runner.run(
    recon_obs=[ReconObservation(target_ip="10.0.0.5", port=80,
                                  service_name="apache",
                                  banner="Apache/2.4.49 (Unix)")],
    candidates=[...],  # populate from src.pipeline.collectors
)
```

### Public benchmark bridge

The external `../Data` harness supplies only `public_task.yml`. Run the
current framework through the generic bridge; the harness owns proof upload
and evaluator completion:

```bash
python -m src.pipeline.data_bridge \
  --public-task ../Data/.../public_task.yml --run-dir ./data/bridge-run \
  --model-profile qwen3_coder_30b
```

Use `--variant baseline` for the frozen PoC-only comparison. Configure the
Qwen, GPT-OSS, and optional Gemini profiles in `configs/config.yaml` from the
tracked `configs/config.yaml.example` template.

### Legacy PoC-only baseline

The legacy workflow is not wired into the default graph. Use it only for
variant 1 PoC-only baseline runs:

```
git checkout baseline-poc-only-v1
python main.py run --target 10.0.0.1 --attacker 10.0.0.2
```

### Run modes

The pipeline supports three explicit retrieval modes:

* `live`: real HTTP / filesystem reads; raw responses are preserved.
* `snapshot`: only reads from a fixed source/candidate snapshot directory.
* `replay`: no retrieval, no execution; reproduces metrics from stored events.

### Evaluation variants

1. Frozen legacy PoC-only graph baseline.
2. Active graph with official fresh CVE sources.
3. Active graph with heterogeneous methods on a frozen snapshot.
4. Full active graph with live, snapshot, and replay modes.

Reports include source freshness latency, validated-vulnerability discovery,
method diversity, repeated-method rate, fallback rescue rate,
oracle-confirmed proof, and false positives on patched controls.

------

## 📊 Benchmark & Evaluation

### Infrastructure

We adopt [Vulhub](https://github.com/vulhub/vulhub) for evaluating the system. Vulhub provides Docker-based vulnerable environments with real-world CVEs.

### Target Selection

We select vulnerabilities based on the following criteria:

- Must have a valid CVE ID
- Must include a CVSS v3.x score
- Additional labels include:
  - CWE ID
  - Exploitability sub-score
  - Difficulty levels derived from the CVSS vector

### Our results
It's been a while since we performed our evaluation. We are working on including some new scenarios in addition to the VulHub in the benchmark, as well as evaluating PentestAgent on a variety of advanced LLM backbones. We will publish our results on the benchmark these works are finished.

------

## 🤝 Contribution

Feel free to open an issue if you:

- Encounter any bugs
- Have suggestions for improvement
- Would like to contribute features or benchmarks

We welcome community contributions!
