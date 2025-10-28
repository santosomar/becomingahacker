# Active Reconnaissance, Scanning, and Fuzzing

## Introduction

Active reconnaissance involves directly interacting with target systems to gather information. Unlike passive reconnaissance, active techniques send packets to the target and can be detected. This module covers scanning techniques, service enumeration, and fuzzing methodologies.

## Active vs. Passive Reconnaissance

| Passive | Active |
|---------|--------|
| No direct interaction | Direct interaction with target |
| Harder to detect | Can be logged and detected |
| Limited information | Detailed technical information |
| Lower risk | Higher risk of detection |

## Port Scanning

### What is Port Scanning?

Port scanning identifies open ports and services running on target systems. It's one of the most fundamental active reconnaissance techniques.

### Common Port States

- **Open**: Service is listening and accepting connections
- **Closed**: Port is accessible but no service is listening
- **Filtered**: Firewall or filter is blocking access
- **Unfiltered**: Port is accessible but state is unknown

### Nmap - The Network Mapper

Nmap is the industry-standard tool for network discovery and security auditing.

#### Basic Scans

```bash
# Basic scan
nmap target.com

# Scan specific ports
nmap -p 80,443 target.com

# Scan port range
nmap -p 1-1000 target.com

# Scan all ports
nmap -p- target.com

# Fast scan (100 most common ports)
nmap -F target.com
```

#### Scan Types

```bash
# TCP SYN scan (stealth scan)
nmap -sS target.com

# TCP Connect scan
nmap -sT target.com

# UDP scan
nmap -sU target.com

# Version detection
nmap -sV target.com

# OS detection
nmap -O target.com

# Aggressive scan (OS, version, script, traceroute)
nmap -A target.com
```

#### Timing and Performance

```bash
# Timing templates (0=paranoid, 5=insane)
nmap -T4 target.com

# Parallel scanning
nmap --min-parallelism 100 target.com

# Adjust timing
nmap --max-rtt-timeout 100ms target.com
```

#### NSE (Nmap Scripting Engine)

```bash
# Run default scripts
nmap -sC target.com

# Run specific script
nmap --script=http-enum target.com

# Run script category
nmap --script=vuln target.com

# Multiple scripts
nmap --script=http-* target.com
```

### Other Scanning Tools

- **Masscan**: Fastest port scanner (entire Internet in 6 minutes)
- **RustScan**: Modern, fast port scanner
- **Unicornscan**: Asynchronous network scanner
- **Zmap**: Fast single-packet network scanner

## Service Enumeration

### Banner Grabbing

```bash
# Netcat banner grab
nc target.com 80
HEAD / HTTP/1.0

# Telnet banner grab
telnet target.com 25

# Nmap banner grab
nmap -sV --script=banner target.com
```

### Protocol-Specific Enumeration

#### HTTP/HTTPS

```bash
# Nikto web scanner
nikto -h http://target.com

# WhatWeb
whatweb target.com

# HTTP methods
nmap --script=http-methods target.com
```

#### SMB (Windows File Sharing)

```bash
# SMB enumeration
nmap --script=smb-enum-* target.com

# Enum4linux
enum4linux -a target.com

# SMBMap
smbmap -H target.com
```

#### DNS

```bash
# DNS zone transfer
dig axfr @nameserver target.com

# DNS enumeration
nmap --script=dns-* target.com

# DNSenum
dnsenum target.com
```

#### SMTP

```bash
# SMTP user enumeration
nmap --script=smtp-enum-users target.com

# SMTP commands
smtp-user-enum -M VRFY -U users.txt -t target.com
```

## Vulnerability Scanning

### Nessus

Commercial vulnerability scanner with comprehensive coverage:
- Network vulnerabilities
- Web application flaws
- Configuration issues
- Compliance checks

### OpenVAS

Open-source vulnerability scanner:
- Free alternative to Nessus
- Regular vulnerability feed updates
- Comprehensive scanning capabilities

### Nuclei

Fast, template-based vulnerability scanner:

```bash
# Basic scan
nuclei -u https://target.com

# Scan with specific templates
nuclei -u https://target.com -t cves/

# Scan multiple targets
nuclei -l targets.txt
```

## Fuzzing

### What is Fuzzing?

Fuzzing involves sending malformed, unexpected, or random data to application inputs to discover vulnerabilities, crashes, or unexpected behavior.

### Web Application Fuzzing

#### Directory and File Discovery

```bash
# Gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Ffuf
ffuf -u http://target.com/FUZZ -w wordlist.txt

# Dirbuster (GUI)
dirbuster

# Feroxbuster (recursive)
feroxbuster -u http://target.com
```

#### Parameter Fuzzing

```bash
# Wfuzz - parameter discovery
wfuzz -c -z file,params.txt http://target.com/?FUZZ=test

# Arjun - parameter discovery
arjun -u http://target.com

# Parameter pollution
ffuf -u "http://target.com?FUZZ=value" -w params.txt
```

#### Subdomain Fuzzing

```bash
# Ffuf subdomain enumeration
ffuf -u http://FUZZ.target.com -w subdomains.txt

# Gobuster DNS mode
gobuster dns -d target.com -w subdomains.txt

# Amass
amass enum -d target.com
```

### API Fuzzing

```bash
# Wfuzz API endpoint discovery
wfuzz -c -z file,api-endpoints.txt http://target.com/api/FUZZ

# Ffuf with JSON
ffuf -u http://target.com/api/FUZZ -w endpoints.txt -H "Content-Type: application/json"
```

### Protocol Fuzzing

- **Boofuzz**: Network protocol fuzzing framework
- **Peach Fuzzer**: Comprehensive fuzzing platform
- **AFL (American Fuzzy Lop)**: Coverage-guided fuzzer
- **Radamsa**: General-purpose fuzzer

## Network Mapping

### Topology Discovery

```bash
# Traceroute
traceroute target.com

# Nmap traceroute
nmap --traceroute target.com

# MTR (My Traceroute)
mtr target.com
```

### Network Visualization

- **Maltego**: Visual link analysis
- **Zenmap**: Nmap GUI with topology mapping
- **Netdiscover**: Network address discovery

## Evasion Techniques

### Firewall and IDS Evasion

```bash
# Fragment packets
nmap -f target.com

# Decoy scanning
nmap -D RND:10 target.com

# Source port manipulation
nmap --source-port 53 target.com

# Randomize hosts
nmap --randomize-hosts target.com

# Slow scan
nmap -T0 target.com
```

## Best Practices

- **Get Authorization**: Always have written permission
- **Scope Awareness**: Stay within defined boundaries
- **Rate Limiting**: Don't overwhelm target systems
- **Documentation**: Record all scanning activities
- **Time Awareness**: Consider business hours and impact
- **Stealth vs. Speed**: Balance detection risk with efficiency
- **Verify Results**: Confirm findings manually

## Common Wordlists

```bash
# SecLists (comprehensive)
/usr/share/seclists/

# Dirb
/usr/share/dirb/wordlists/

# Dirbuster
/usr/share/wordlists/dirbuster/

# Rockyou (passwords)
/usr/share/wordlists/rockyou.txt
```

## Legal and Ethical Considerations

- **Authorization**: Never scan without permission
- **Scope**: Respect defined boundaries
- **Impact**: Consider system stability and availability
- **Laws**: Understand CFAA and local regulations
- **Responsible Disclosure**: Report findings appropriately

## Practical Exercises

1. Perform a comprehensive Nmap scan on your lab environment
2. Enumerate services and identify versions
3. Fuzz a web application for hidden directories
4. Create a network topology map
5. Practice evasion techniques against your own firewall

## Resources

- [Nmap Documentation](https://nmap.org/docs.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)

## Next Steps

With reconnaissance complete, you'll move into exploiting specific types of systems, starting with web applications.

