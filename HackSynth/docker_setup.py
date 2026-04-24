import os
import time
import docker

# Tool packages for different attack scenarios
TOOL_PACKAGES = {
    "base": [
        "kali-linux-headless",
        "sshpass",
        "curl",
        "wget",
    ],
    "webapp": [
        "nikto",
        "gobuster",
        "dirb",
        "sqlmap",
        "wfuzz",
        "whatweb",
        "httpie",
    ],
    "network": [
        "nmap",
        "masscan",
        "netcat-traditional",
        "enum4linux",
        "smbclient",
        "nbtscan",
        "onesixtyone",
    ],
    "exploit": [
        "metasploit-framework",
        "exploitdb",
        "hydra",
        "john",
        "hashcat",
        "crackmapexec",
    ],
}


def get_tools_for_attackbox(attackbox_name: str) -> list:
    """Determine which tool packages to install based on attackbox name"""
    tools = TOOL_PACKAGES["base"].copy()
    
    if "webapp" in attackbox_name.lower() or "web" in attackbox_name.lower():
        tools.extend(TOOL_PACKAGES["webapp"])
    if "network" in attackbox_name.lower() or "scan" in attackbox_name.lower():
        tools.extend(TOOL_PACKAGES["network"])
    if "exploit" in attackbox_name.lower() or "custom" in attackbox_name.lower():
        tools.extend(TOOL_PACKAGES["exploit"])
    
    # For generic custom attackbox, install network tools by default
    if "custom" in attackbox_name.lower():
        tools.extend(TOOL_PACKAGES["network"])
    
    return list(set(tools))  # Remove duplicates


def create_container(config, extra_tools: list = None):
	client = docker.from_env()

	# Define the path to a host directory with ample storage
	host_directory = '/data/cyberml_attackbox'
	if not os.path.exists(host_directory):
		print(f"[ATTACKBOX] Data directory '{host_directory}' does not exist. Not binding to container.")
		host_directory = '.'

	existing_container = client.containers.list(filters={'name': config["attackbox"]}, all=True)

	if existing_container:
		container = existing_container[0]
	else:
		print(f"[ATTACKBOX] Creating new {config['attackbox']}. This will take a few minutes. If you interrupt this process, delete the {config['attackbox']} container and run the script again.")
		
		# Use custom image if specified, otherwise default to Kali
		image_name = config.get("docker_image", "kalilinux/kali-rolling")
		image = client.images.pull(image_name)
		
		# Configure network mode
		network_mode = config.get("network_mode", None)  # e.g., "host" for direct network access
		
		container = client.containers.run(
			image_name,
			detach=True,
			tty=True,
			name=config["attackbox"],
			# Use bind mount to link the host directory to /data in the container
			volumes={host_directory: {'bind': '/data', 'mode': 'rw'}} if host_directory != '.' else {},
			cap_add=['NET_ADMIN', 'SYS_PTRACE'],  # Add necessary capabilities
			devices=["/dev/net/tun"],  # Needed for VPN
			environment={"DEBIAN_FRONTEND": "noninteractive"},  # Set environment variable for non-interactive install
			stdin_open=True,
			network_mode=network_mode,
		)
		
		# Determine tools to install
		tools_to_install = get_tools_for_attackbox(config["attackbox"])
		if extra_tools:
			tools_to_install.extend(extra_tools)
		if "extra_tools" in config:
			tools_to_install.extend(config["extra_tools"])
		
		tools_str = " ".join(list(set(tools_to_install)))
		print(f"[ATTACKBOX] Installing tools: {tools_str}")
		
		# Set up the container with appropriate tools
		setup_commands = (
			'apt update && '
			f'apt -y install {tools_str}'
		)
		
		# Add SSH key scanning for OverTheWire if this is an overthewire box
		if "overthewire" in config["attackbox"].lower():
			setup_commands += (
				' && ssh-keyscan -p 2220 bandit.labs.overthewire.org >> ~/.ssh/known_hosts'
				' && ssh-keyscan -p 2231 krypton.labs.overthewire.org >> ~/.ssh/known_hosts'
				' && ssh-keyscan -p 2223 leviathan.labs.overthewire.org >> ~/.ssh/known_hosts'
			)
		result = container.exec_run(f'/bin/bash -c "{setup_commands}"', stdout=True, stderr=True)
		print('[ATTACKBOX]', result.output.decode())  # Print the output to check for errors

		# Verify essential tools installation
		for tool in ['curl', 'nmap', 'wget']:
			tool_check = container.exec_run(f'which {tool}')
			if tool_check.exit_code != 0:
				print(f"[ATTACKBOX] Warning: {tool} not found. Some features may not work.")

		container.stop()
		print(f"[ATTACKBOX] The {config['attackbox']} has been set up.")

	if container.status != 'running':
		container.start()
		# Create necessary devices and permissions
		container.exec_run('/bin/bash -c "mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun"')
		# If a VPN configuration is provided, start the VPN
		if "vpn" in config and os.path.exists(f"{host_directory}/{config['vpn']}"):
			container.exec_run(f'openvpn /data/{config["vpn"]}', detach=True)
		time.sleep(3)

	return container


def create_minimal_container(name: str = "hacksynth_minimal"):
    """
    Create a minimal container for quick testing without full tool installation.
    Useful for development and testing custom targets.
    """
    client = docker.from_env()
    
    existing = client.containers.list(filters={'name': name}, all=True)
    if existing:
        container = existing[0]
        if container.status != 'running':
            container.start()
        return container
    
    container = client.containers.run(
        'kalilinux/kali-rolling',
        detach=True,
        tty=True,
        name=name,
        cap_add=['NET_ADMIN'],
        environment={"DEBIAN_FRONTEND": "noninteractive"},
        stdin_open=True
    )
    
    # Minimal setup
    container.exec_run('/bin/bash -c "apt update && apt -y install curl wget nmap netcat-traditional"')
    
    return container
