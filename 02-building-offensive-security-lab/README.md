# Building Your Own Offensive Security Lab

## Introduction

A well-configured offensive security lab is essential for practicing penetration testing techniques safely and legally. This module covers how to build your own lab environment using WebSploit Labs and other tools.

## Why Build a Lab?

- **Safe Environment**: Practice attacks without legal or ethical concerns
- **Hands-On Learning**: Apply theoretical knowledge in practical scenarios
- **Skill Development**: Develop and refine your penetration testing skills
- **Tool Familiarity**: Learn to use various security tools effectively
- **Reproducible Testing**: Test and validate exploits in controlled conditions

### Video Courses
Enhance your practical skills with these video courses designed to deepen your understanding of cybersecurity:

- Building the Ultimate Cybersecurity Lab and Cyber Range (video) [Available on O'Reilly](https://learning.oreilly.com/course/building-the-ultimate/9780138319090/)
- Build Your Own AI Lab (video) Hands-on guide to home and cloud-based AI labs. Learn to set up and optimize labs to research and experiment in a secure environment. [Available on O'Reilly](https://learning.oreilly.com/course/build-your-own/9780135439616)


## WebSploit Labs

[WebSploit Labs](https://websploit.org) provides a comprehensive platform for learning offensive security techniques with pre-configured vulnerable environments.

## Kali MCP Server

Integrate AI-powered penetration testing into your workflow with the Kali MCP Server. This setup combines Kali Linux tools with Claude Desktop through the Model Context Protocol (MCP), enabling you to execute security testing commands using natural language.

### Features
- **50+ Pre-loaded Tools**: Access to essential Kali Linux tools (nmap, nikto, sqlmap, metasploit, etc.)
- **Natural Language Interface**: Execute complex commands without memorizing syntax
- **Docker-based**: Isolated, reproducible environment
- **AI-Assisted Testing**: Let Claude help plan and execute security assessments

### Quick Start
```bash
# Build the Kali MCP container
docker build -t kali-mcp:latest .

# Configure Claude Desktop
# Edit: ~/Library/Application Support/Claude/claude_desktop_config.json
```

📚 **[Complete Kali MCP Lab Guide](./kali-mcp-claude.md)** - Detailed setup instructions, exercises, and best practices

### Example Usage
Once configured, you can interact with Kali tools through Claude:
- "Scan 192.168.1.1 with nmap to find open ports"
- "Run nikto against http://testsite.com"
- "Use gobuster to find hidden directories on http://example.com"

### Resources
- [Original Article by Sasisachins](https://medium.com/@sasisachins2003/penetration-testing-made-simple-kali-mcp-with-docker-and-claude-desktop-6d50a6a60300)
- [Model Context Protocol Documentation](https://modelcontextprotocol.io)
- [Kali Linux Official Documentation](https://www.kali.org/docs/)

