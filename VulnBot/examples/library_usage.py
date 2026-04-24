#!/usr/bin/env python3
"""
VulnBot Library Usage Examples

This file demonstrates how to use VulnBot as a Python library.
"""

from vulnbot import VulnBot, VulnBotConfig
from vulnbot.core import ModelConfig, KaliConfig, RAGConfig


# =============================================================================
# Example 1: Quick Start - Minimal Configuration
# =============================================================================
def example_quick_start():
    """Minimal configuration to get started."""
    
    bot = VulnBot(
        model_config={
            "api_key": "sk-your-openai-key",
            "llm_model_name": "gpt-4",
        },
        kali_config={
            "hostname": "192.168.1.100",
            "username": "kali",
            "password": "kali",
        },
        max_interactions=5,
    )
    
    result = bot.run("Perform penetration test on target 10.0.2.5")
    print(f"Success: {result.success}")
    print(f"Phases completed: {result.phases_completed}")


# =============================================================================
# Example 2: Full Configuration with Dataclasses
# =============================================================================
def example_full_config():
    """Using dataclass-based configuration for full control."""
    
    config = VulnBotConfig(
        model=ModelConfig(
            api_key="sk-your-openai-key",
            base_url="https://api.openai.com/v1",
            llm_model="openai",
            llm_model_name="gpt-4-turbo",
            temperature=0.5,
            context_length=128000,
            timeout=180,
        ),
        kali=KaliConfig(
            hostname="192.168.1.100",
            port=22,
            username="kali",
            password="kali",
        ),
        rag=RAGConfig(
            enabled=False,  # Set True to enable RAG
        ),
        max_interactions=10,
        mode="auto",
    )
    
    bot = VulnBot(config=config)
    result = bot.run("Pentest the web application at 10.0.2.5:80")
    
    return result


# =============================================================================
# Example 3: Using Ollama (Local LLM)
# =============================================================================
def example_ollama():
    """Using Ollama for local LLM inference."""
    
    bot = VulnBot(
        model_config={
            "base_url": "http://localhost:11434",  # Ollama default
            "llm_model": "ollama",
            "llm_model_name": "llama3.1:70b",  # or mixtral, codellama, etc.
            "temperature": 0.7,
        },
        kali_config={
            "hostname": "192.168.1.100",
            "username": "kali",
            "password": "kali",
        },
    )
    
    result = bot.run("Scan target 10.0.2.5 for open ports and services")
    return result


# =============================================================================
# Example 4: With Callbacks for Monitoring
# =============================================================================
def example_with_callbacks():
    """Using callbacks to monitor progress."""
    
    def on_phase_start(phase_name: str):
        print(f"🚀 Starting phase: {phase_name}")
    
    def on_phase_complete(phase_name: str, result):
        print(f"✅ Completed phase: {phase_name}")
    
    def on_task_execute(task: str, command: str):
        print(f"⚡ Executing: {command}")
    
    bot = VulnBot(
        model_config={
            "api_key": "sk-your-key",
            "llm_model_name": "gpt-4",
        },
        kali_config={
            "hostname": "192.168.1.100",
            "username": "kali",
            "password": "kali",
        },
        on_phase_start=on_phase_start,
        on_phase_complete=on_phase_complete,
        on_task_execute=on_task_execute,
    )
    
    result = bot.run("Enumerate services on 10.0.2.5")
    return result


# =============================================================================
# Example 5: Context Manager for Proper Cleanup
# =============================================================================
def example_context_manager():
    """Using context manager ensures proper cleanup."""
    
    with VulnBot(
        model_config={
            "api_key": "sk-your-key",
            "llm_model_name": "gpt-4",
        },
        kali_config={
            "hostname": "192.168.1.100",
            "username": "kali",
            "password": "kali",
        },
    ) as bot:
        # Run reconnaissance only
        result = bot.run_single_phase(
            "Discover all hosts on 10.0.2.0/24",
            role="collector"
        )
        
        # Execute a specific command
        output = bot.execute_command("nmap -sP 10.0.2.0/24")
        print(output)
        
        # Direct LLM chat
        response = bot.chat("What ports should I check on a web server?")
        print(response)


# =============================================================================
# Example 6: Run Specific Phases
# =============================================================================
def example_specific_phases():
    """Run only specific phases of the pentest."""
    
    bot = VulnBot(
        model_config={
            "api_key": "sk-your-key",
            "llm_model_name": "gpt-4",
        },
        kali_config={
            "hostname": "192.168.1.100",
            "username": "kali",
            "password": "kali",
        },
        max_interactions=3,
    )
    
    # Run only the collector phase (reconnaissance)
    recon_result = bot.run_single_phase(
        "Identify all services on target 10.0.2.5",
        role="collector"
    )
    print(f"Recon complete: {recon_result.success}")
    
    # Then run scanner phase
    scan_result = bot.run_single_phase(
        "Based on services found, scan for vulnerabilities on 10.0.2.5",
        role="scanner"
    )
    print(f"Scan complete: {scan_result.success}")
    
    bot.close()


# =============================================================================
# Example 7: Configuration from Environment Variables
# =============================================================================
def example_env_config():
    """Load configuration from environment variables."""
    import os
    
    bot = VulnBot(
        model_config={
            "api_key": os.environ.get("OPENAI_API_KEY"),
            "base_url": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            "llm_model_name": os.environ.get("LLM_MODEL", "gpt-4"),
        },
        kali_config={
            "hostname": os.environ.get("KALI_HOST", "localhost"),
            "port": int(os.environ.get("KALI_PORT", "22")),
            "username": os.environ.get("KALI_USER", "kali"),
            "password": os.environ.get("KALI_PASS", "kali"),
        },
    )
    
    return bot


# =============================================================================
# Example 8: Using Azure OpenAI
# =============================================================================
def example_azure_openai():
    """Using Azure OpenAI endpoint."""
    
    bot = VulnBot(
        model_config={
            "api_key": "your-azure-api-key",
            "base_url": "https://your-resource.openai.azure.com/openai/deployments/gpt-4",
            "llm_model": "openai",
            "llm_model_name": "gpt-4",
        },
        kali_config={
            "hostname": "192.168.1.100",
            "username": "kali",
            "password": "kali",
        },
    )
    
    return bot


if __name__ == "__main__":
    # Run the quick start example (modify as needed)
    print("VulnBot Library Examples")
    print("=" * 50)
    print("\nSee the function definitions for various usage patterns.")
    print("\nAvailable examples:")
    print("  - example_quick_start(): Minimal configuration")
    print("  - example_full_config(): Full dataclass config")
    print("  - example_ollama(): Using local Ollama LLM")
    print("  - example_with_callbacks(): Progress monitoring")
    print("  - example_context_manager(): Safe resource cleanup")
    print("  - example_specific_phases(): Run individual phases")
    print("  - example_env_config(): Environment variable config")
    print("  - example_azure_openai(): Azure OpenAI endpoint")
