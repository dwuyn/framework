"""
Success Criteria Module for HackSynth Custom Targets

Supports multiple success detection types for penetration testing scenarios
beyond simple CTF flag detection.
"""

import re
import socket
from typing import Callable, Optional, Union
from dataclasses import dataclass
from enum import Enum


class CriteriaType(Enum):
    """Types of success criteria for custom targets"""
    CONTAINS = "contains"           # String found in output
    REGEX = "regex"                 # Regex pattern matches
    FILE_EXISTS = "file_exists"     # File exists in container
    PORT_OPEN = "port_open"         # Port responds on target
    COMMAND_SUCCESS = "command"     # Command returns exit code 0
    MANUAL = "manual"               # Human confirms success
    LLM_JUDGE = "llm_judge"         # LLM evaluates success
    MULTI = "multi"                 # Multiple criteria (AND/OR)
    CUSTOM = "custom"               # Custom callback function


@dataclass
class SuccessCriteria:
    """
    Defines success criteria for a penetration testing target.
    
    Examples:
        # Simple string match (like CTF flag)
        SuccessCriteria(type=CriteriaType.CONTAINS, value="FLAG{secret}")
        
        # Regex pattern
        SuccessCriteria(type=CriteriaType.REGEX, value=r"password[:\\s]+\\w+")
        
        # Port is open
        SuccessCriteria(type=CriteriaType.PORT_OPEN, value="22", target="192.168.1.1")
        
        # Multiple criteria with AND
        SuccessCriteria(
            type=CriteriaType.MULTI,
            value=[
                {"type": "contains", "value": "root"},
                {"type": "contains", "value": "#"}
            ],
            operator="and"
        )
    """
    type: CriteriaType
    value: Union[str, list, Callable]
    description: str = ""
    target: str = ""  # For network-based checks
    operator: str = "and"  # For MULTI type: "and" or "or"
    timeout: int = 5  # For network checks


class SuccessChecker:
    """Evaluates success criteria against command outputs"""
    
    def __init__(self, container=None, llm_pipeline=None):
        self.container = container
        self.llm_pipeline = llm_pipeline
        self._manual_callback = None
    
    def set_manual_callback(self, callback: Callable[[str, str], bool]):
        """Set callback for manual verification"""
        self._manual_callback = callback
    
    def check(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str = ""
    ) -> tuple[bool, str]:
        """
        Check if success criteria is met.
        
        Returns:
            tuple: (success: bool, message: str)
        """
        handlers = {
            CriteriaType.CONTAINS: self._check_contains,
            CriteriaType.REGEX: self._check_regex,
            CriteriaType.FILE_EXISTS: self._check_file_exists,
            CriteriaType.PORT_OPEN: self._check_port_open,
            CriteriaType.COMMAND_SUCCESS: self._check_command_success,
            CriteriaType.MANUAL: self._check_manual,
            CriteriaType.LLM_JUDGE: self._check_llm_judge,
            CriteriaType.MULTI: self._check_multi,
            CriteriaType.CUSTOM: self._check_custom,
        }
        
        handler = handlers.get(criteria.type)
        if not handler:
            return False, f"Unknown criteria type: {criteria.type}"
        
        return handler(criteria, command_output, summarized_history)
    
    def _check_contains(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Check if value string is contained in output or history"""
        value = str(criteria.value)
        if value in command_output or value in summarized_history:
            return True, f"Found '{value}' in output"
        return False, f"'{value}' not found"
    
    def _check_regex(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Check if regex pattern matches in output or history"""
        pattern = str(criteria.value)
        combined = command_output + "\n" + summarized_history
        
        match = re.search(pattern, combined, re.IGNORECASE | re.MULTILINE)
        if match:
            return True, f"Regex matched: '{match.group()}'"
        return False, f"Pattern '{pattern}' not matched"
    
    def _check_file_exists(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Check if file exists in container"""
        if not self.container:
            return False, "No container available for file check"
        
        filepath = str(criteria.value)
        result = self.container.exec_run(f"test -f {filepath} && echo EXISTS")
        
        if b"EXISTS" in result.output:
            return True, f"File '{filepath}' exists"
        return False, f"File '{filepath}' not found"
    
    def _check_port_open(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Check if port is open on target"""
        try:
            port = int(criteria.value)
            target = criteria.target or "127.0.0.1"
            timeout = criteria.timeout
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return True, f"Port {port} is open on {target}"
            return False, f"Port {port} is closed on {target}"
        except Exception as e:
            return False, f"Port check failed: {str(e)}"
    
    def _check_command_success(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Run a command and check if it succeeds (exit code 0)"""
        if not self.container:
            return False, "No container available for command check"
        
        cmd = str(criteria.value)
        result = self.container.exec_run(cmd)
        
        if result.exit_code == 0:
            return True, f"Command '{cmd}' succeeded"
        return False, f"Command '{cmd}' failed with exit code {result.exit_code}"
    
    def _check_manual(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Ask human to verify success"""
        if self._manual_callback:
            result = self._manual_callback(command_output, summarized_history)
            if result:
                return True, "Manually confirmed success"
            return False, "Manual verification: not successful"
        
        # Default: interactive prompt
        print("\n" + "="*50)
        print("MANUAL VERIFICATION REQUIRED")
        print("="*50)
        print(f"Criteria: {criteria.description or criteria.value}")
        print(f"\nRecent output:\n{command_output[:500]}")
        print("="*50)
        
        response = input("Was the objective achieved? [y/N]: ").strip().lower()
        if response in ('y', 'yes'):
            return True, "Manually confirmed success"
        return False, "Manual verification: not successful"
    
    def _check_llm_judge(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Use LLM to judge if objective was achieved"""
        if not self.llm_pipeline:
            return False, "No LLM available for judgment"
        
        objective = str(criteria.value)
        
        prompt = f"""You are evaluating whether a penetration testing objective has been achieved.

Objective: {objective}

Recent command output:
{command_output[:1000]}

History summary:
{summarized_history[:1000]}

Has the objective been achieved? Answer with ONLY 'YES' or 'NO' followed by a brief explanation."""
        
        messages = [
            {"role": "system", "content": "You are a penetration testing expert evaluating attack success."},
            {"role": "user", "content": prompt}
        ]
        
        try:
            # Support both local and OpenAI models
            if hasattr(self.llm_pipeline, 'chat'):
                # OpenAI
                response = self.llm_pipeline.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=messages,
                    max_tokens=100
                )
                answer = response.choices[0].message.content
            else:
                # Local model
                output = self.llm_pipeline(
                    messages,
                    max_new_tokens=100,
                    do_sample=False
                )
                answer = output[0]["generated_text"]
            
            if answer.upper().startswith("YES"):
                return True, f"LLM judged success: {answer}"
            return False, f"LLM judged not successful: {answer}"
        except Exception as e:
            return False, f"LLM judgment failed: {str(e)}"
    
    def _check_multi(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Check multiple criteria with AND/OR logic"""
        sub_criteria_list = criteria.value
        if not isinstance(sub_criteria_list, list):
            return False, "Multi criteria requires a list of criteria"
        
        results = []
        messages = []
        
        for sub_criteria_dict in sub_criteria_list:
            sub_criteria = parse_criteria(sub_criteria_dict)
            success, msg = self.check(sub_criteria, command_output, summarized_history)
            results.append(success)
            messages.append(msg)
        
        if criteria.operator.lower() == "or":
            success = any(results)
            logic = "OR"
        else:
            success = all(results)
            logic = "AND"
        
        return success, f"Multi ({logic}): {'; '.join(messages)}"
    
    def _check_custom(
        self,
        criteria: SuccessCriteria,
        command_output: str,
        summarized_history: str
    ) -> tuple[bool, str]:
        """Use custom callback function"""
        if not callable(criteria.value):
            return False, "Custom criteria requires a callable"
        
        try:
            result = criteria.value(command_output, summarized_history, self.container)
            if isinstance(result, tuple):
                return result
            return bool(result), "Custom check completed"
        except Exception as e:
            return False, f"Custom check failed: {str(e)}"


def parse_criteria(criteria_dict: dict) -> SuccessCriteria:
    """
    Parse a criteria dictionary into a SuccessCriteria object.
    
    Args:
        criteria_dict: Dictionary with 'type', 'value', and optional fields
        
    Returns:
        SuccessCriteria object
    """
    criteria_type = CriteriaType(criteria_dict.get("type", "contains"))
    
    return SuccessCriteria(
        type=criteria_type,
        value=criteria_dict.get("value", ""),
        description=criteria_dict.get("description", ""),
        target=criteria_dict.get("target", ""),
        operator=criteria_dict.get("operator", "and"),
        timeout=criteria_dict.get("timeout", 5)
    )


def check_success(
    criteria_dict: dict,
    command_output: str,
    summarized_history: str = "",
    container=None,
    llm_pipeline=None
) -> tuple[bool, str]:
    """
    Convenience function to check success criteria.
    
    Args:
        criteria_dict: Dictionary defining the success criteria
        command_output: Recent command output
        summarized_history: Agent's summarized history
        container: Docker container (optional, for file/command checks)
        llm_pipeline: LLM pipeline (optional, for LLM judgment)
        
    Returns:
        tuple: (success: bool, message: str)
    """
    criteria = parse_criteria(criteria_dict)
    checker = SuccessChecker(container=container, llm_pipeline=llm_pipeline)
    return checker.check(criteria, command_output, summarized_history)
