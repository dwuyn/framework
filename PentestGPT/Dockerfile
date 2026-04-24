# PentestGPT Docker Image
# Lightweight penetration testing environment with PentestGPT

FROM ubuntu:24.04

LABEL description="PentestGPT - AI-Powered Penetration Testing Assistant"
LABEL version="1.0.0"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Update and install system dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    # Build essentials
    build-essential \
    software-properties-common \
    ca-certificates \
    gnupg \
    # Python
    python3.12 \
    python3-pip \
    python3-venv \
    python3-dev \
    # Essential pentesting tools
    nmap \
    netcat-openbsd \
    curl \
    wget \
    git \
    sudo \
    # Network utilities
    net-tools \
    dnsutils \
    whois \
    # VPN (for HackTheBox/TryHackMe connectivity)
    openvpn \
    # Text processing
    jq \
    ripgrep \
    # Terminal
    tmux \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js v20 (required for Claude Code CLI)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Remove EXTERNALLY-MANAGED marker to allow pip/poetry in Docker
# Also remove system Python packages that conflict with Poetry dependencies
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
    apt-get remove -y python3-cryptography && \
    apt-get autoremove -y

# Install Claude Code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Install Claude Code Router globally (for OpenRouter support)
RUN npm install -g @musistudio/claude-code-router

# Create non-root user
RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up working directories (including ccr config)
RUN mkdir -p /workspace /app /home/pentester/.claude /home/pentester/.claude-code-router && \
    chown -R pentester:pentester /workspace /app /home/pentester/.claude /home/pentester/.claude-code-router

# Switch to pentester user
USER pentester
WORKDIR /app

# Install Poetry for Python dependency management
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    echo 'export PATH="/home/pentester/.local/bin:$PATH"' >> /home/pentester/.bashrc

ENV PATH="/home/pentester/.local/bin:$PATH"

# Copy project files
COPY --chown=pentester:pentester pyproject.toml README.md /app/
COPY --chown=pentester:pentester pentestgpt/ /app/pentestgpt/
COPY --chown=pentester:pentester scripts/entrypoint.sh /home/pentester/entrypoint.sh
COPY --chown=pentester:pentester scripts/ccr-config-template.json /app/scripts/ccr-config-template.json

# Install Python dependencies as root to system Python
# Allow pip to override system packages in Docker
ENV PIP_BREAK_SYSTEM_PACKAGES=1
USER root
RUN poetry config virtualenvs.create false && \
    poetry install --only main && \
    chmod +x /home/pentester/entrypoint.sh

# Switch back to pentester user for runtime
USER pentester

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default working directory for penetration tests
WORKDIR /workspace

# Use entrypoint script for auth setup
ENTRYPOINT ["/home/pentester/entrypoint.sh"]

# Default command - interactive bash
# Users can run: pentestgpt --target X
CMD ["/bin/bash"]
