"""
VulnBot - Autonomous Penetration Testing Multi-Agent Framework

A Python library for running automated penetration tests using LLM-powered agents.

Example:
    from vulnbot import VulnBot
    
    bot = VulnBot(
        model_config={
            "api_key": "sk-...",
            "base_url": "https://api.openai.com/v1",
            "llm_model": "openai",
            "llm_model_name": "gpt-4",
            "temperature": 0.7,
        },
        kali_config={
            "hostname": "192.168.1.100",
            "port": 22,
            "username": "kali",
            "password": "kali",
        }
    )
    
    bot.run("Perform penetration test on target 10.0.2.5")
"""

from vulnbot.core import VulnBot, VulnBotConfig

__version__ = "0.1.0"
__all__ = ["VulnBot", "VulnBotConfig"]
