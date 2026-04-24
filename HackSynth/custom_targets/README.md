# HackSynth Custom Targets

This module extends HackSynth to support custom penetration testing targets beyond CTF challenges.

## Quick Start

```bash
# Run custom targets
python run_custom.py -t custom_targets/examples/webapp_targets.json -c configs/custom/webapp_testing.json

# Run single target interactively
python run_custom.py -t custom_targets/examples/network_targets.json -c configs/custom/network_scanning.json --target local_network_scan --interactive

# Run without Neptune logging
python run_custom.py -t targets.json -c config.json --no-neptune
```

## Custom Target Format

Targets are defined in JSON files with the following structure:

```json
{
    "target_name": {
        "name": "Human-readable name",
        "description": "What to do / objective",
        "target": "IP address, URL, or network range",
        "type": "webapp|network|host|custom",
        "success_criteria": {
            "type": "contains|regex|file_exists|port_open|command|manual|llm_judge|multi",
            "value": "pattern or command",
            "description": "What indicates success"
        },
        "files": ["optional_urls_to_download"],
        "hints": ["optional hints for the agent"]
    }
}
```

## Success Criteria Types

### 1. `contains` (Default)
Simple string matching in output or history. Compatible with CTF flags.

```json
{
    "type": "contains",
    "value": "FLAG{secret}"
}
```

### 2. `regex`
Regular expression pattern matching.

```json
{
    "type": "regex",
    "value": "(password|secret)[:\\s]+\\w+"
}
```

### 3. `file_exists`
Check if a file exists in the container.

```json
{
    "type": "file_exists",
    "value": "/tmp/proof.txt"
}
```

### 4. `port_open`
Check if a port is open on the target.

```json
{
    "type": "port_open",
    "value": "22",
    "target": "192.168.1.1",
    "timeout": 5
}
```

### 5. `command`
Run a command and check for exit code 0.

```json
{
    "type": "command",
    "value": "whoami | grep -q root"
}
```

### 6. `manual`
Human verifies success interactively.

```json
{
    "type": "manual",
    "value": "Verify that reconnaissance is complete",
    "description": "Check all services documented"
}
```

### 7. `llm_judge`
LLM evaluates if the objective was achieved.

```json
{
    "type": "llm_judge",
    "value": "The agent has gained root access to the system",
    "description": "LLM confirms root shell obtained"
}
```

### 8. `multi`
Combine multiple criteria with AND/OR logic.

```json
{
    "type": "multi",
    "value": [
        {"type": "contains", "value": "root"},
        {"type": "regex", "value": "#\\s*$"}
    ],
    "operator": "and"
}
```

## Configuration Files

Config files in `configs/custom/` define agent behavior:

| Config | Use Case |
|--------|----------|
| `webapp_testing.json` | Web application security testing |
| `network_scanning.json` | Network reconnaissance and enumeration |
| `exploitation.json` | Host exploitation and privilege escalation |
| `general.json` | Generic penetration testing |

### Config Options

```json
{
    "neptune": {
        "project": "workspace/project",
        "name": "Experiment Name"
    },
    "llm": {
        "model_id": "gpt-4o",
        "model_local": false,
        "temperature": 0.8,
        "top_p": 0.9,
        "max_new_tokens": 2500,
        "prompt_chaining": true
    },
    "attackbox": "attackbox_kali_custom",
    "docker_image": "kalilinux/kali-rolling",
    "network_mode": null,
    "extra_tools": ["custom-tool"],
    "timeout_duration": 30,
    "max_tries": 30,
    "new_observation_length_limit": 1000,
    "target_text": "Template with {target}, {description}",
    "planner": {
        "system_prompt": "Planner system prompt",
        "user_prompt": "Template with {summarized_history}"
    },
    "summarizer": {
        "system_prompt": "Summarizer system prompt",
        "user_prompt": "Template with {summarized_history}, {new_observation}"
    }
}
```

## Docker Attackbox

The framework automatically installs tools based on attackbox name:

| Attackbox Name Contains | Tools Installed |
|------------------------|-----------------|
| `webapp`, `web` | nikto, gobuster, sqlmap, wfuzz, etc. |
| `network`, `scan` | nmap, masscan, enum4linux, smbclient, etc. |
| `exploit`, `custom` | metasploit, hydra, john, hashcat, etc. |

### Custom Docker Image

Specify a custom image in config:

```json
{
    "docker_image": "my-custom-kali:latest",
    "extra_tools": ["additional-tool"]
}
```

## Example Workflows

### Web Application Testing

```bash
# 1. Start a vulnerable web app (e.g., OWASP Juice Shop)
docker run -d -p 3000:3000 bkimminich/juice-shop

# 2. Create target file
cat > my_targets.json << 'EOF'
{
    "juice_shop": {
        "description": "Find and exploit SQL injection in login",
        "target": "http://localhost:3000",
        "type": "webapp",
        "success_criteria": {
            "type": "regex",
            "value": "authentication.*success|admin@juice"
        }
    }
}
EOF

# 3. Run the agent
python run_custom.py -t my_targets.json -c configs/custom/webapp_testing.json --no-neptune
```

### Network Scanning

```bash
# Create target file for network scan
cat > network_target.json << 'EOF'
{
    "internal_scan": {
        "description": "Enumerate all hosts and services on 10.0.0.0/24",
        "target": "10.0.0.0/24",
        "type": "network",
        "success_criteria": {
            "type": "regex",
            "value": "Host.*is up.*open"
        }
    }
}
EOF

# Run with network config (longer timeouts)
python run_custom.py -t network_target.json -c configs/custom/network_scanning.json --no-neptune
```

### Interactive Mode

Use `--interactive` for manual intervention:

```bash
python run_custom.py -t targets.json -c config.json --interactive

# Every 5 steps, you can:
# - Press Enter or 'y' to continue
# - Type 'n' to stop
# - Type 'success' to mark as successful
# - Type 'hint' to provide a hint to the agent
```

## Backward Compatibility

Targets with a `flag` field (CTF format) are automatically supported:

```json
{
    "ctf_challenge": {
        "description": "Find the flag",
        "target": "challenge.ctf.com",
        "flag": "CTF{secret_flag}"
    }
}
```

This is equivalent to:

```json
{
    "success_criteria": {
        "type": "contains",
        "value": "CTF{secret_flag}"
    }
}
```

## API Usage

```python
from custom_targets import SuccessCriteria, check_success

# Simple check
success, message = check_success(
    {"type": "regex", "value": r"root@"},
    command_output="root@target:~#",
    summarized_history=""
)

# With container for file/command checks
from docker_setup import create_container
container = create_container({"attackbox": "test"})

success, message = check_success(
    {"type": "file_exists", "value": "/etc/passwd"},
    command_output="",
    container=container
)
```

## Files Structure

```
custom_targets/
├── __init__.py
├── success_criteria.py      # Success criteria module
├── README.md               # This file
└── examples/
    ├── webapp_targets.json  # Web app testing examples
    ├── network_targets.json # Network scanning examples
    └── host_targets.json    # Host exploitation examples

configs/custom/
├── webapp_testing.json     # Web testing config
├── network_scanning.json   # Network scanning config
├── exploitation.json       # Exploitation config
└── general.json           # General pentest config
```
