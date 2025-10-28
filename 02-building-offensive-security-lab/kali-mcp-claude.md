# Kali MCP Server with Claude Desktop: AI-Powered Penetration Testing Lab

## Table of Contents
1. [Introduction](#introduction)
2. [What is MCP (Model Context Protocol)?](#what-is-mcp)
3. [Prerequisites](#prerequisites)
4. [Lab Architecture](#lab-architecture)
5. [Setup Instructions](#setup-instructions)
6. [Configuration](#configuration)
7. [Available Tools](#available-tools)
8. [Practical Exercises](#practical-exercises)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)
11. [References](#references)

## Introduction

The Kali MCP Server represents a breakthrough in AI-assisted penetration testing by combining the power of Kali Linux with Claude's natural language understanding through the Model Context Protocol (MCP). This lab guide will walk you through setting up a complete environment where you can use natural language commands to execute penetration testing tools.

### What You'll Learn
- How to deploy Kali Linux in a Docker container with MCP integration
- Configure Claude Desktop to communicate with Kali tools
- Execute penetration testing commands using natural language
- Automate common security testing workflows
- Integrate AI into your offensive security toolkit

### Key Benefits
- **Natural Language Control**: Execute complex commands without memorizing syntax
- **Automation**: Streamline repetitive penetration testing tasks
- **Cross-Platform**: Run on Linux, macOS, or Windows
- **Isolated Environment**: Safe containerized testing environment
- **50+ Pre-loaded Tools**: Access to essential Kali Linux tools

## What is MCP (Model Context Protocol)?

The Model Context Protocol (MCP) is an open protocol that standardizes how applications provide context to Large Language Models (LLMs). In this setup:

- **MCP Server**: Runs inside the Kali Linux container, exposing security tools
- **MCP Client**: Claude Desktop acts as the client, sending natural language requests
- **Protocol**: JSON-RPC based communication over stdio (standard input/output)

```
┌─────────────────┐         MCP Protocol        ┌──────────────────┐
│  Claude Desktop │ ◄────────────────────────► │  Kali Container  │
│   (MCP Client)  │      (JSON-RPC/stdio)       │   (MCP Server)   │
└─────────────────┘                             └──────────────────┘
         │                                               │
         │                                               │
         ▼                                               ▼
   Natural Language                              Security Tools
   "Scan 192.168.1.1"                           nmap, nikto, etc.
```

## Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows with WSL2
- **RAM**: Minimum 8GB (16GB recommended)
- **Disk Space**: At least 10GB free space
- **Processor**: 64-bit processor with virtualization support

### Software Requirements
1. **Docker Desktop** (latest version)
   - Download: https://www.docker.com/products/docker-desktop
   - Ensure Docker daemon is running

2. **Claude Desktop** (latest version)
   - Download: https://claude.ai/download
   - Requires an Anthropic account

3. **Git** (for cloning repositories)
   - Download: https://git-scm.com/downloads

4. **Text Editor** (VS Code, Sublime, or similar)
   - For editing configuration files

### Knowledge Prerequisites
- Basic understanding of Docker concepts
- Familiarity with command-line interfaces
- Basic knowledge of penetration testing concepts
- Understanding of networking fundamentals

## Lab Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Host System                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Claude Desktop Application                │ │
│  │  - MCP Client                                          │ │
│  │  - Natural Language Interface                          │ │
│  │  - Configuration: claude_desktop_config.json           │ │
│  └────────────────┬───────────────────────────────────────┘ │
│                   │ stdio communication                      │
│                   │                                          │
│  ┌────────────────▼───────────────────────────────────────┐ │
│  │           Docker Container: kali-mcp                   │ │
│  │  ┌──────────────────────────────────────────────────┐  │ │
│  │  │         MCP Server (Python)                      │  │ │
│  │  │  - JSON-RPC handler                              │  │ │
│  │  │  - Tool registry                                 │  │ │
│  │  │  - Command executor                              │  │ │
│  │  └──────────────┬───────────────────────────────────┘  │ │
│  │                 │                                        │ │
│  │  ┌──────────────▼───────────────────────────────────┐  │ │
│  │  │         Kali Linux Tools Layer                   │  │ │
│  │  │  - Network Scanning: nmap, masscan               │  │ │
│  │  │  - Web Testing: nikto, sqlmap, gobuster          │  │ │
│  │  │  - Exploitation: metasploit, hydra               │  │ │
│  │  │  - Wireless: aircrack-ng, reaver                 │  │ │
│  │  │  - Password: john, hashcat                       │  │ │
│  │  │  - And 40+ more tools                            │  │ │
│  │  └──────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Network Configuration
- Container runs in bridge mode
- Exposed ports: 3000, 3389, 5900, 4444
- Can access host network for scanning (with proper configuration)

## Setup Instructions

### Step 1: Create Project Directory

```bash
# Create a dedicated directory for the lab
mkdir -p ~/kali-mcp-lab
cd ~/kali-mcp-lab
```

### Step 2: Create the Dockerfile

Create a file named `Dockerfile` with the following content:

```dockerfile
FROM kalilinux/kali-rolling:latest

# Fix Kali repositories and update
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list

# Update and install essential packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    vim \
    sudo \
    ssh \
    net-tools \
    iputils-ping \
    nmap \
    nikto \
    sqlmap \
    metasploit-framework \
    john \
    hashcat \
    aircrack-ng \
    wireshark \
    burpsuite \
    gobuster \
    dirb \
    hydra \
    masscan \
    enum4linux \
    smbclient \
    dnsenum \
    fierce \
    wafw00f \
    whatweb \
    wpscan \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Create the MCP server script
RUN cat > /app/mcp_server.py << 'EOF'
#!/usr/bin/env python3
import asyncio
import json
import subprocess
import logging
import sys
import os
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KaliMCPServer:
    def __init__(self):
        self.tools = {
            'nmap_scan': {
                'func': self.nmap_scan,
                'cmd': 'nmap',
                'params': ['target', 'scan_type'],
                'description': 'Network discovery and security auditing'
            },
            'nikto_scan': {
                'func': self.nikto_scan,
                'cmd': 'nikto',
                'params': ['target'],
                'description': 'Web server scanner'
            },
            'sqlmap_scan': {
                'func': self.sqlmap_scan,
                'cmd': 'sqlmap',
                'params': ['url', 'additional_params'],
                'description': 'SQL injection detection and exploitation'
            },
            'gobuster_scan': {
                'func': self.gobuster_scan,
                'cmd': 'gobuster',
                'params': ['url', 'wordlist'],
                'description': 'Directory and file brute-forcing'
            },
            'hydra_bruteforce': {
                'func': self.hydra_bruteforce,
                'cmd': 'hydra',
                'params': ['target', 'service', 'username', 'password_list'],
                'description': 'Network logon cracker'
            },
            'masscan_scan': {
                'func': self.masscan_scan,
                'cmd': 'masscan',
                'params': ['target', 'ports'],
                'description': 'Fast port scanner'
            },
            'whatweb_scan': {
                'func': self.whatweb_scan,
                'cmd': 'whatweb',
                'params': ['target'],
                'description': 'Web technology identifier'
            },
            'dnsenum_scan': {
                'func': self.dnsenum_scan,
                'cmd': 'dnsenum',
                'params': ['domain'],
                'description': 'DNS enumeration tool'
            },
            'network_info': {
                'func': self.network_info,
                'cmd': 'ip',
                'params': [],
                'description': 'Display network configuration'
            },
            'execute_command': {
                'func': self.execute_custom_command,
                'cmd': 'custom',
                'params': ['command'],
                'description': 'Execute custom shell command'
            }
        }

    async def execute_command(self, command: str, timeout: int = 300) -> Dict[str, Any]:
        """Execute shell command with timeout"""
        try:
            logger.info(f"Executing: {command}")
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return {
                'success': True,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'return_code': process.returncode
            }
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            return {'success': False, 'error': str(e), 'stdout': '', 'stderr': ''}

    async def nmap_scan(self, target: str, scan_type: str = 'basic', **kwargs) -> Dict[str, Any]:
        commands = {
            'basic': f'nmap {target}',
            'syn': f'nmap -sS {target}',
            'version': f'nmap -sV {target}',
            'os': f'nmap -O {target}',
            'aggressive': f'nmap -A {target}',
            'vuln': f'nmap --script vuln {target}'
        }
        command = commands.get(scan_type, commands['basic'])
        return await self.execute_command(command, timeout=300)

    async def nikto_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        command = f'nikto -h {target}'
        return await self.execute_command(command, timeout=600)

    async def sqlmap_scan(self, url: str, additional_params: str = '', **kwargs) -> Dict[str, Any]:
        command = f'sqlmap -u "{url}" --batch {additional_params}'
        return await self.execute_command(command, timeout=300)

    async def gobuster_scan(self, url: str, wordlist: str = '/usr/share/wordlists/dirb/common.txt', **kwargs) -> Dict[str, Any]:
        command = f'gobuster dir -u {url} -w {wordlist} -q'
        return await self.execute_command(command, timeout=300)

    async def hydra_bruteforce(self, target: str, service: str, username: str, password_list: str, **kwargs) -> Dict[str, Any]:
        command = f'hydra -l {username} -P {password_list} {target} {service}'
        return await self.execute_command(command, timeout=600)

    async def masscan_scan(self, target: str, ports: str = '1-65535', **kwargs) -> Dict[str, Any]:
        command = f'masscan {target} -p{ports} --rate=1000'
        return await self.execute_command(command, timeout=300)

    async def whatweb_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        command = f'whatweb {target}'
        return await self.execute_command(command, timeout=120)

    async def dnsenum_scan(self, domain: str, **kwargs) -> Dict[str, Any]:
        command = f'dnsenum {domain}'
        return await self.execute_command(command, timeout=300)

    async def network_info(self, **kwargs) -> Dict[str, Any]:
        command = 'ip addr show && echo "=== ROUTING ===" && ip route show'
        return await self.execute_command(command)

    async def execute_custom_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """Execute custom shell command"""
        return await self.execute_command(command)

    def run_stdio(self):
        """Main MCP stdio loop"""
        logger.info(f"Starting Kali MCP Server with {len(self.tools)} tools")
        
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                    
                line = line.strip()
                if not line:
                    continue
                
                request = json.loads(line)
                
                if request.get('method') == 'initialize':
                    response = {
                        'jsonrpc': '2.0',
                        'id': request.get('id'),
                        'result': {
                            'protocolVersion': '2024-11-05',
                            'capabilities': {'tools': {'listChanged': True}},
                            'serverInfo': {'name': 'kali-mcp-server', 'version': '1.0.0'}
                        }
                    }
                
                elif request.get('method') == 'notifications/initialized':
                    continue
                
                elif request.get('method') == 'tools/list':
                    tools_list = []
                    for tool_name, tool_info in self.tools.items():
                        properties = {}
                        required = []
                        
                        for param in tool_info['params']:
                            properties[param] = {
                                'type': 'string',
                                'description': f'{param} parameter for {tool_name}'
                            }
                            if param in ['target', 'url', 'domain', 'command']:
                                required.append(param)
                        
                        tools_list.append({
                            'name': tool_name,
                            'description': f'{tool_info["description"]} - Command: {tool_info["cmd"]}',
                            'inputSchema': {
                                'type': 'object',
                                'properties': properties,
                                'required': required
                            }
                        })
                    
                    response = {
                        'jsonrpc': '2.0',
                        'id': request.get('id'),
                        'result': {'tools': tools_list}
                    }
                
                elif request.get('method') == 'tools/call':
                    tool_name = request['params']['name']
                    arguments = request['params'].get('arguments', {})
                    
                    if tool_name in self.tools:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            result = loop.run_until_complete(self.tools[tool_name]['func'](**arguments))
                        finally:
                            loop.close()
                        
                        response = {
                            'jsonrpc': '2.0',
                            'id': request.get('id'),
                            'result': {
                                'content': [{
                                    'type': 'text',
                                    'text': f"Tool: {tool_name}\nCommand: {self.tools[tool_name]['cmd']}\nSuccess: {result.get('success')}\n\nOutput:\n{result.get('stdout', '')[:10000]}\n\nErrors:\n{result.get('stderr', '')[:5000]}"
                                }]
                            }
                        }
                    else:
                        response = {
                            'jsonrpc': '2.0',
                            'id': request.get('id'),
                            'error': {'code': -32601, 'message': f'Tool not found: {tool_name}'}
                        }
                
                else:
                    response = {
                        'jsonrpc': '2.0',
                        'id': request.get('id'),
                        'result': {'content': [{'type': 'text', 'text': f'Kali MCP Server with {len(self.tools)} tools ready'}]}
                    }
                
                print(json.dumps(response), flush=True)
                
            except json.JSONDecodeError:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error: {e}")
                print(json.dumps({
                    'jsonrpc': '2.0',
                    'id': 1,
                    'error': {'code': -32603, 'message': str(e)}
                }), flush=True)

if __name__ == "__main__":
    server = KaliMCPServer()
    if len(sys.argv) > 1 and sys.argv[1] == '--stdio':
        server.run_stdio()
    else:
        print(f"Kali MCP Server with {len(server.tools)} tools available")
        print("Use --stdio flag for MCP mode")
EOF

# Make executable
RUN chmod +x /app/mcp_server.py

# Create startup script
RUN cat > /app/start_services.sh <<'EOF'
#!/bin/bash
set -euo pipefail
echo "Starting Kali MCP services..."
service postgresql start || true
if command -v msfdb >/dev/null 2>&1; then
  echo "Initializing Metasploit database..."
  msfdb init || true
fi
service ssh start || true
echo "All services started"
cd /app
python3 mcp_server.py --stdio
EOF

RUN chmod +x /app/start_services.sh

# Expose ports
EXPOSE 3000 3389 5900 4444

# Set default command
CMD ["/app/start_services.sh"]
```

### Step 3: Build the Docker Image

```bash
# Build the image (this will take 10-15 minutes)
docker build -t kali-mcp:latest .

# Verify the image was created
docker images | grep kali-mcp
```

### Step 4: Create Docker Compose File (Optional but Recommended)

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  kali-mcp:
    image: kali-mcp:latest
    container_name: kali-mcp-server
    stdin_open: true
    tty: true
    ports:
      - "3000:3000"
      - "4444:4444"
    volumes:
      - ./shared:/shared
      - ./wordlists:/wordlists
    networks:
      - kali-network
    restart: unless-stopped

networks:
  kali-network:
    driver: bridge
```

### Step 5: Test the Container

```bash
# Run the container interactively to test
docker run -it --rm kali-mcp:latest /bin/bash

# Inside the container, test tools
nmap --version
nikto -Version
sqlmap --version

# Exit the container
exit
```

## Configuration

### Configure Claude Desktop

1. **Locate the Claude Desktop configuration file:**

**macOS:**
```bash
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```bash
~/.config/Claude/claude_desktop_config.json
```

2. **Edit the configuration file:**

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--name", "kali-mcp-instance",
        "kali-mcp:latest"
      ]
    }
  }
}
```

3. **For more advanced configuration with persistent storage:**

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--name", "kali-mcp-instance",
        "-v", "/path/to/shared:/shared",
        "-v", "/path/to/wordlists:/wordlists",
        "--network", "host",
        "kali-mcp:latest"
      ],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Step 6: Restart Claude Desktop

1. Completely quit Claude Desktop
2. Restart the application
3. Look for the hammer icon (🔨) in the interface - this indicates MCP tools are available

### Verify the Connection

In Claude Desktop, type:
```
List all available Kali tools
```

You should see a list of available penetration testing tools.

## Available Tools

### Network Scanning Tools

#### 1. **nmap_scan**
- **Description**: Network discovery and security auditing
- **Parameters**:
  - `target`: IP address or hostname
  - `scan_type`: basic, syn, version, os, aggressive, vuln
- **Example**: "Scan 192.168.1.1 with nmap using version detection"

#### 2. **masscan_scan**
- **Description**: Fast port scanner
- **Parameters**:
  - `target`: IP address or CIDR range
  - `ports`: Port range (default: 1-65535)
- **Example**: "Use masscan to scan 192.168.1.0/24 for ports 80 and 443"

### Web Application Testing Tools

#### 3. **nikto_scan**
- **Description**: Web server scanner
- **Parameters**:
  - `target`: URL or IP address
- **Example**: "Run nikto against http://testsite.com"

#### 4. **sqlmap_scan**
- **Description**: SQL injection detection and exploitation
- **Parameters**:
  - `url`: Target URL with parameter
  - `additional_params`: Extra sqlmap flags
- **Example**: "Test http://testsite.com/page?id=1 for SQL injection"

#### 5. **gobuster_scan**
- **Description**: Directory and file brute-forcing
- **Parameters**:
  - `url`: Target URL
  - `wordlist`: Path to wordlist file
- **Example**: "Use gobuster to find hidden directories on http://testsite.com"

#### 6. **whatweb_scan**
- **Description**: Web technology identifier
- **Parameters**:
  - `target`: URL or IP address
- **Example**: "Identify web technologies on http://testsite.com"

### DNS and Domain Tools

#### 7. **dnsenum_scan**
- **Description**: DNS enumeration tool
- **Parameters**:
  - `domain`: Target domain name
- **Example**: "Enumerate DNS records for example.com"

### Password and Authentication Tools

#### 8. **hydra_bruteforce**
- **Description**: Network logon cracker
- **Parameters**:
  - `target`: IP address or hostname
  - `service`: Service name (ssh, ftp, http-post-form, etc.)
  - `username`: Username to test
  - `password_list`: Path to password list
- **Example**: "Use hydra to test SSH login on 192.168.1.10 with username admin"

### Utility Tools

#### 9. **network_info**
- **Description**: Display network configuration
- **Parameters**: None
- **Example**: "Show network configuration"

#### 10. **execute_command**
- **Description**: Execute custom shell command
- **Parameters**:
  - `command`: Shell command to execute
- **Example**: "Execute command: ls -la /tmp"

## Practical Exercises

### Exercise 1: Basic Network Reconnaissance

**Objective**: Perform basic reconnaissance on a target network

**Scenario**: You need to identify live hosts and open ports on a test network.

**Steps**:

1. **Start with a ping sweep** (using custom command):
```
Execute command: nmap -sn 192.168.1.0/24
```

2. **Identify web servers**:
```
Scan 192.168.1.0/24 with nmap to find hosts with port 80 or 443 open
```

3. **Perform service version detection**:
```
Scan 192.168.1.10 with nmap using version detection
```

4. **Check for common vulnerabilities**:
```
Scan 192.168.1.10 with nmap using vuln scan type
```

**Expected Output**: List of live hosts, open ports, service versions, and potential vulnerabilities

### Exercise 2: Web Application Security Assessment

**Objective**: Assess a web application for common vulnerabilities

**Scenario**: You've been asked to test a web application at http://testsite.local

**Steps**:

1. **Identify web technologies**:
```
Identify web technologies on http://testsite.local
```

2. **Scan for web vulnerabilities**:
```
Run nikto against http://testsite.local
```

3. **Discover hidden directories**:
```
Use gobuster to find hidden directories on http://testsite.local
```

4. **Test for SQL injection**:
```
Test http://testsite.local/login.php?id=1 for SQL injection
```

**Expected Output**: Technology stack, web server vulnerabilities, hidden paths, and SQL injection findings

### Exercise 3: DNS Enumeration

**Objective**: Gather information about a domain through DNS

**Scenario**: Perform reconnaissance on example.com

**Steps**:

1. **Enumerate DNS records**:
```
Enumerate DNS records for example.com
```

2. **Check for zone transfer**:
```
Execute command: dig axfr @ns1.example.com example.com
```

3. **Find subdomains**:
```
Execute command: dnsrecon -d example.com -t std
```

**Expected Output**: DNS records, subdomains, mail servers, and name servers

### Exercise 4: Password Security Testing

**Objective**: Test password strength on a service

**Scenario**: Test SSH authentication on a lab server

**Steps**:

1. **Create a small password list** (for testing only):
```
Execute command: echo -e "password\n123456\nadmin\ntest" > /tmp/passwords.txt
```

2. **Test SSH with hydra**:
```
Use hydra to test SSH login on 192.168.1.10 with username testuser and password list /tmp/passwords.txt
```

**Expected Output**: Successful/failed login attempts

**⚠️ Warning**: Only use on systems you own or have explicit permission to test!

### Exercise 5: Comprehensive Security Audit

**Objective**: Perform a complete security audit workflow

**Scenario**: Conduct a full assessment of a target system

**Steps**:

1. **Network discovery**:
```
Scan 192.168.1.0/24 with nmap to identify live hosts
```

2. **Port scanning**:
```
Use masscan to scan 192.168.1.10 for all ports
```

3. **Service enumeration**:
```
Scan 192.168.1.10 with nmap using aggressive scan type
```

4. **Web application testing**:
```
Run nikto against http://192.168.1.10
Use gobuster to find hidden directories on http://192.168.1.10
```

5. **Vulnerability assessment**:
```
Scan 192.168.1.10 with nmap using vuln scan type
```

6. **Generate report** (using custom command):
```
Execute command: nmap -sV -sC -A 192.168.1.10 -oA /shared/full_scan
```

**Expected Output**: Comprehensive security assessment report

## Security Considerations

### Legal and Ethical Guidelines

⚠️ **CRITICAL**: Only test systems you own or have explicit written permission to test!

1. **Authorization**: Always obtain written permission before testing
2. **Scope**: Stay within the defined scope of your engagement
3. **Data Handling**: Protect any sensitive data discovered during testing
4. **Reporting**: Document and report findings responsibly
5. **Laws**: Understand and comply with local cybersecurity laws

### Container Security

1. **Isolation**: The container provides isolation but is not a complete security boundary
2. **Network Access**: Be cautious when using `--network host` mode
3. **Privileged Mode**: Avoid running containers in privileged mode unless absolutely necessary
4. **Updates**: Regularly rebuild the image to include security updates

### Best Practices

1. **Dedicated Network**: Use a separate network for testing
2. **Logging**: Enable logging for all testing activities
3. **Rate Limiting**: Use appropriate rate limits to avoid DoS conditions
4. **Cleanup**: Remove test data and artifacts after testing
5. **Documentation**: Document all testing activities

### Data Protection

```bash
# Create encrypted volume for sensitive data
docker volume create --driver local \
  --opt type=tmpfs \
  --opt device=tmpfs \
  --opt o=size=1g,uid=1000 \
  kali-secure-data

# Use in docker-compose.yml
volumes:
  - kali-secure-data:/secure
```

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Claude Desktop doesn't show MCP tools

**Symptoms**: No hammer icon, tools not available

**Solutions**:
1. Verify configuration file location and syntax
2. Check Docker is running: `docker ps`
3. Test container manually: `docker run -it kali-mcp:latest /bin/bash`
4. Check Claude Desktop logs:
   - macOS: `~/Library/Logs/Claude/`
   - Windows: `%APPDATA%\Claude\logs\`
5. Completely restart Claude Desktop (not just close window)

#### Issue 2: Container fails to start

**Symptoms**: Error messages when starting container

**Solutions**:
```bash
# Check Docker logs
docker logs kali-mcp-instance

# Verify image exists
docker images | grep kali-mcp

# Rebuild image
docker build --no-cache -t kali-mcp:latest .

# Check for port conflicts
docker ps -a
```

#### Issue 3: Tools return errors

**Symptoms**: Commands fail or return unexpected results

**Solutions**:
```bash
# Enter container for debugging
docker exec -it kali-mcp-instance /bin/bash

# Test tool directly
nmap --version

# Check Python script
python3 /app/mcp_server.py

# View logs
docker logs kali-mcp-instance
```

#### Issue 4: Network connectivity issues

**Symptoms**: Cannot reach target hosts

**Solutions**:
```bash
# Test network from container
docker exec -it kali-mcp-instance ping 8.8.8.8

# Use host network mode (add to config)
"args": ["run", "-i", "--rm", "--network", "host", "kali-mcp:latest"]

# Check firewall rules
# macOS: System Preferences > Security & Privacy > Firewall
# Linux: sudo iptables -L
# Windows: Windows Defender Firewall
```

#### Issue 5: Performance issues

**Symptoms**: Slow scans or timeouts

**Solutions**:
```bash
# Increase container resources in Docker Desktop
# Settings > Resources > Advanced

# Use faster scan options
# Instead of: nmap -A target
# Use: nmap -sV --version-light target

# Limit scan scope
# Instead of: masscan 0.0.0.0/0
# Use: masscan 192.168.1.0/24
```

### Debug Mode

Enable debug logging:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e", "LOG_LEVEL=DEBUG",
        "kali-mcp:latest"
      ]
    }
  }
}
```

### Getting Help

1. **Check container logs**: `docker logs kali-mcp-instance`
2. **Verify MCP protocol version**: Ensure compatibility
3. **Test tools independently**: Run tools directly in container
4. **Community resources**:
   - Anthropic Discord: https://discord.gg/anthropic
   - MCP Documentation: https://modelcontextprotocol.io
   - Kali Forums: https://forums.kali.org

## Advanced Configuration

### Adding Custom Tools

Edit the Dockerfile to add more tools:

```dockerfile
RUN apt-get update && apt-get install -y \
    your-custom-tool \
    another-tool \
    && apt-get clean
```

Then add to `mcp_server.py`:

```python
'custom_tool': {
    'func': self.custom_tool_func,
    'cmd': 'custom-tool',
    'params': ['param1', 'param2'],
    'description': 'Your custom tool description'
}
```

### Persistent Storage

Create volumes for persistent data:

```yaml
volumes:
  - ./scans:/scans
  - ./reports:/reports
  - ./wordlists:/usr/share/wordlists
```

### Custom Wordlists

```bash
# Download common wordlists
mkdir -p ~/kali-mcp-lab/wordlists
cd ~/kali-mcp-lab/wordlists

# SecLists
git clone https://github.com/danielmiessler/SecLists.git

# Mount in docker-compose.yml
volumes:
  - ./wordlists:/wordlists:ro
```

### Network Modes

**Bridge Mode** (default):
```yaml
networks:
  - kali-network
```

**Host Mode** (direct host network access):
```yaml
network_mode: "host"
```

**Custom Network**:
```bash
docker network create --subnet=172.20.0.0/16 kali-test-net
```

## Performance Optimization

### Resource Limits

```yaml
services:
  kali-mcp:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

### Caching

```dockerfile
# Use build cache effectively
RUN apt-get update && apt-get install -y \
    tool1 tool2 tool3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
```

## Integration Examples

### Example 1: Automated Vulnerability Scan

```
Claude, I need you to:
1. Scan 192.168.1.10 with nmap to identify open ports
2. For each web port found, run nikto
3. Use gobuster to find hidden directories
4. Summarize all findings
```

### Example 2: Network Mapping

```
Help me map the network 192.168.1.0/24:
1. Find all live hosts
2. Identify operating systems
3. List all open ports and services
4. Create a network diagram (describe the topology)
```

### Example 3: Web App Assessment

```
Assess the security of http://testapp.local:
1. Identify the technology stack
2. Find hidden directories and files
3. Test for SQL injection in all parameters
4. Check for common web vulnerabilities
5. Provide a prioritized list of findings
```

## Learning Resources

### Official Documentation
- **MCP Protocol**: https://modelcontextprotocol.io
- **Kali Linux**: https://www.kali.org/docs/
- **Docker**: https://docs.docker.com

### Recommended Reading
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "Penetration Testing" by Georgia Weidman
- "Metasploit: The Penetration Tester's Guide" by David Kennedy

### Practice Platforms
- **HackTheBox**: https://www.hackthebox.eu
- **TryHackMe**: https://tryhackme.com
- **WebSploit Labs**: https://websploit.org
- **DVWA**: Damn Vulnerable Web Application
- **Metasploitable**: Intentionally vulnerable Linux VM

### Video Tutorials
- Kali Linux tutorials on YouTube
- Offensive Security training videos
- NetworkChuck's ethical hacking series

## Conclusion

The Kali MCP Server with Claude Desktop represents a powerful combination of traditional penetration testing tools and modern AI capabilities. This setup allows you to:

- Execute complex security assessments using natural language
- Automate repetitive testing tasks
- Learn penetration testing concepts interactively
- Build sophisticated security testing workflows

### Next Steps

1. **Practice**: Work through all exercises in this guide
2. **Expand**: Add more tools to your container
3. **Automate**: Create custom workflows for common tasks
4. **Share**: Contribute improvements back to the community
5. **Learn**: Continue studying penetration testing methodologies

### Key Takeaways

✅ Always obtain proper authorization before testing
✅ Use isolated environments for practice
✅ Document all findings and activities
✅ Stay updated with the latest security tools and techniques
✅ Practice responsible disclosure

## References

1. **Original Article**: [Penetration Testing Made Simple: Kali MCP with Docker and Claude Desktop](https://medium.com/@sasisachins2003/penetration-testing-made-simple-kali-mcp-with-docker-and-claude-desktop-6d50a6a60300)

2. **Model Context Protocol**:
   - Official Site: https://modelcontextprotocol.io
   - GitHub: https://github.com/modelcontextprotocol

3. **Kali Linux**:
   - Official Site: https://www.kali.org
   - Documentation: https://www.kali.org/docs/
   - Tools List: https://www.kali.org/tools/

4. **Docker**:
   - Official Site: https://www.docker.com
   - Documentation: https://docs.docker.com

5. **Anthropic Claude**:
   - Claude Desktop: https://claude.ai/download
   - Documentation: https://docs.anthropic.com

6. **Security Resources**:
   - OWASP: https://owasp.org
   - NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
   - SANS Institute: https://www.sans.org

---

**Disclaimer**: This lab is for educational purposes only. Always ensure you have proper authorization before conducting any security testing. Unauthorized access to computer systems is illegal and unethical.

**Version**: 1.0  
**Last Updated**: October 2025  
**Author**: Based on work by Sasisachins and the MCP community  
**License**: Educational Use Only

