# PentestAgent

## Overview

**PentestAgent** is a novel LLM-driven penetration testing framework to automate intelligence gathering, vulnerability analysis, and exploitation stages, reducing manual intervention.

The framework is modular and consists of the following components:

- **Reconnaissance Agent**: Gathers intelligence about the target system.
- **Hypothesis + Planning Agents**: Build evidence-grounded CVE hypotheses, debate exploit paths via Planner→Skeptic→Risk Officer, and rank candidates using evidence-grounded scoring.
- **Execution Agent**: Attempts to execute selected exploits in a controlled environment.
- **Verifier + Maintain Access Agents**: Gate quality between phases and re-verify the same access path after exploitation.

For further is information, please refer to our [paper](https://arxiv.org/abs/2411.05185).

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

The recommended entry point is `main.py`, which orchestrates the LangGraph pipeline and prompts for approval before execution.

### Full Pipeline

```
python main.py run --target 10.0.0.1 --attacker 10.0.0.2
```

### Recon Only

```
python main.py recon --target 10.0.0.1
```

### Planning Only

```
python main.py plan --app phpmailer --version 5.2.17
```

### Execution Only

```
python main.py execute --target 10.0.0.1 --doc-dir ./data/exp_info/CVE-2021-41773
```

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
