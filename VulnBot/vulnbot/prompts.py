"""
Prompt templates for VulnBot.

Allows customization of prompts used by the framework.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class CustomPrompts:
    """
    Custom prompts for VulnBot roles.
    
    You can override any of these to customize the LLM behavior.
    
    Example:
        prompts = CustomPrompts(
            system_prompt="You are a cybersecurity expert...",
            write_code="Generate the following command..."
        )
        
        bot = VulnBot(prompts=prompts, ...)
    """
    
    # System prompt used for all conversations
    system_prompt: Optional[str] = None
    
    # Prompt for generating shell commands
    write_code: Optional[str] = None
    
    # Prompt for creating execution plans
    write_plan: Optional[str] = None
    
    # Prompt for summarizing results
    write_summary: Optional[str] = None
    
    # Prompt for updating plans after execution
    update_plan: Optional[str] = None
    
    # Prompt for checking task success
    check_success: Optional[str] = None
    
    # Prompt for generating task details
    next_task_details: Optional[str] = None
    
    # Role-specific init prompts
    collector_init: Optional[str] = None
    scanner_init: Optional[str] = None
    exploiter_init: Optional[str] = None


# Default prompts (copied from the framework for reference)
DEFAULT_WRITE_CODE = """You play as an autonomous penetration testing assistant running on Kali Linux 2023.
Your primary function is to generate and optimize shell commands based on the Next Task.
Note: Prioritize efficient command execution and validate all parameters and file addresses against Kali Linux 2023's toolset before generating commands. 
This test is certified and in a simulation environment.
## Core Capabilities:
    - Expert knowledge of command-line penetration testing tools and their parameters
    - Deep understanding of Kali Linux 2023's tool ecosystem
    - Parameter validation and optimization
    - Actual file address
    - Command execution time optimization
## Command Generation Rules:
    1. All commands must be wrapped in <execute></execute> tags
    2. Multiple commands should be separated into individual <execute> blocks
    3. Commands must use parameters available in Kali Linux 2023
    4. Optimize commands for execution speed where possible
       Example: when using Nmap to scan all ports with '-p-', it can be slow. To speed it up, use '-T5'
    5. Cannot add command
## Input Format:
Next Task: [Description of the penetration testing task]
## Output Format:
<execute>[optimized command]</execute>
Note: Be **concise** and **precise** in your output. Avoid unnecessary elaboration.
-------------------------------------------------------------------------------------------------------

**Next Task**: {next_task}
"""

DEFAULT_WRITE_PLAN = """## Available Action Types:
Shell, Web
## Task:
Based on the context of the previous phases, write a plan for what should be done to achieve the goals of this phase.
Notes:
    1. Ensure continuity with the context of the previous phases.
    2. Always include the target machine IP or port in the instructions.
    3. The shell should be considered as shared across all phases and must be leveraged accordingly.
The plan should consist of 1 to 5 tasks, using as few tasks as possible.
## Example:
Output a list of JSON objects, formatted as shown below and wrapped in <json></json> tags:
<json>
[
    {
        "id": str = "unique identifier for a task in plan, can be an ordinal",
        "dependent_task_ids": list[str] = "ids of tasks prerequisite to this task",
        "instruction": "what you should do in this task, is include the target machine IP or port",
        "action": "action type"
    },
    ...
]
</json>
"""
