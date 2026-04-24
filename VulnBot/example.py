#!/usr/bin/env python3
"""
Minimal example for using VulnBot as a Python library.

Usage:
    export OPENAI_API_KEY="your-api-key"
    export KALI_HOST="192.168.1.100"
    export KALI_USER="kali"
    export KALI_PASS="kali"
    python example.py
"""

import os

from vulnbot import VulnBot


def main() -> None:
    target = "Enumerate services and potential web vulnerabilities on 10.0.2.5"

    with VulnBot(
        model_config={
            "api_key": os.environ.get("OPENAI_API_KEY", ""),
            "base_url": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            "llm_model": os.environ.get("LLM_PROVIDER", "openai"),
            "llm_model_name": os.environ.get("LLM_MODEL_NAME", "gpt-4"),
            "temperature": 0.2,
        },
        kali_config={
            "hostname": os.environ.get("KALI_HOST", "127.0.0.1"),
            "port": int(os.environ.get("KALI_PORT", "22")),
            "username": os.environ.get("KALI_USER", "kali"),
            "password": os.environ.get("KALI_PASS", "kali"),
        },
        max_interactions=3,
        mode="auto",
    ) as bot:
        result = bot.run(target)

        print(f"Session ID: {result.session_id}")
        print(f"Success: {result.success}")
        print(f"Phases completed: {result.phases_completed}")
        if result.error:
            print(f"Error: {result.error}")


if __name__ == "__main__":
    main()
