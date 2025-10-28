# Passive Reconnaissance and Open Source Intelligence (OSINT)

## Introduction

Passive reconnaissance is the process of gathering information about a target without directly interacting with their systems. OSINT (Open Source Intelligence) involves collecting and analyzing publicly available information to build a comprehensive understanding of the target.

## What is Passive Reconnaissance?

Passive reconnaissance is the first phase of a penetration test where you gather information without alerting the target. Unlike active reconnaissance, passive techniques don't send packets directly to the target's systems, making them harder to detect.

## Why OSINT Matters

- **Legal and Safe**: All information is publicly available
- **Undetectable**: Target systems are not directly accessed
- **Comprehensive**: Reveals information targets may not realize is public
- **Foundation**: Provides context for later testing phases
- **Attack Surface Mapping**: Identifies potential entry points

## OSINT Categories

### 1. Domain and Network Information

- **WHOIS Lookups**: Domain registration details, registrant information
- **DNS Records**: Subdomains, mail servers, nameservers
- **IP Ranges**: Network blocks owned by the organization
- **ASN Information**: Autonomous System Numbers and routing

### 2. Web Presence

- **Website Analysis**: Technologies, frameworks, CMS platforms
- **Cached Pages**: Historical versions via Wayback Machine
- **Metadata**: EXIF data in images, document properties
- **Robots.txt**: Directories and files the site wants hidden

### 3. Social Media Intelligence

- **Employee Information**: LinkedIn profiles, job postings
- **Company Updates**: Twitter, Facebook, Instagram posts
- **Professional Networks**: GitHub, Stack Overflow, forums
- **Personal Information**: Potential social engineering targets

### 4. Email and Credential Intelligence

- **Email Formats**: Common patterns (firstname.lastname@company.com)
- **Breach Databases**: Compromised credentials from data breaches
- **Email Validation**: Verify email addresses exist
- **Password Patterns**: Common password policies

### 5. Physical and Location Intelligence

- **Google Maps**: Office locations, physical security
- **Satellite Imagery**: Building layouts, entry points
- **Street View**: Physical access points, security cameras
- **Public Records**: Business registrations, property records

## Essential OSINT Tools

### Domain and DNS Tools

- **whois**: Domain registration information
- **nslookup/dig**: DNS queries and record enumeration
- **DNSdumpster**: DNS reconnaissance and mapping
- **Sublist3r**: Subdomain enumeration
- **Amass**: In-depth DNS enumeration and network mapping
- **SecurityTrails**: Historical DNS data

### Search Engines and Aggregators

- **Google Dorking**: Advanced search operators for finding sensitive information
- **Shodan**: Search engine for Internet-connected devices
- **Censys**: Internet-wide scanning and analysis
- **ZoomEye**: Cyberspace search engine
- **FOFA**: Cyberspace mapping

### Social Media and People Search

- **theHarvester**: Email, subdomain, and people name harvesting
- **Maltego**: Visual link analysis and data mining
- **SpiderFoot**: Automated OSINT collection
- **Recon-ng**: Full-featured reconnaissance framework
- **LinkedIn**: Professional networking and employee research

### Breach and Credential Databases

- **Have I Been Pwned**: Check if emails appear in breaches
- **DeHashed**: Search engine for leaked databases
- **Intelligence X**: Search engine for leaked data
- **Breach Directory**: Searchable breach database

### Web Analysis Tools

- **Wayback Machine**: Historical website snapshots
- **BuiltWith**: Technology stack identification
- **Wappalyzer**: Web technology profiler
- **WhatWeb**: Website fingerprinting
- **Netcraft**: Web server and hosting information

## Google Dorking Examples

```
# Find specific file types
site:target.com filetype:pdf
site:target.com filetype:xlsx

# Find login pages
site:target.com inurl:login
site:target.com inurl:admin

# Find exposed directories
site:target.com intitle:"index of"

# Find specific text in pages
site:target.com intext:"confidential"

# Find subdomains
site:*.target.com

# Exclude specific content
site:target.com -www

# Find cached versions
cache:target.com
```

## OSINT Methodology

### 1. Define Objectives

- What information do you need?
- What is the scope of the engagement?
- What are the legal boundaries?

### 2. Collect Information

- Start broad, then narrow down
- Use multiple sources for verification
- Document all findings with timestamps
- Maintain chain of custody for evidence

### 3. Analyze and Correlate

- Connect disparate pieces of information
- Identify patterns and relationships
- Validate information accuracy
- Prioritize actionable intelligence

### 4. Report Findings

- Organize information logically
- Highlight security implications
- Provide context and recommendations
- Protect sensitive information appropriately

## OSINT Framework

The [OSINT Framework](https://osintframework.com/) provides a comprehensive collection of OSINT tools organized by category:

- Domain/IP research
- Email addresses
- Social networks
- People search
- Phone numbers
- And much more

## Privacy and Legal Considerations

- **Stay Legal**: Only access publicly available information
- **Respect Privacy**: Consider ethical implications
- **Terms of Service**: Respect website ToS and robots.txt
- **Data Protection**: Comply with GDPR, CCPA, and other regulations
- **Authorization**: Ensure you have permission for the engagement

## Practical Exercise Ideas

1. Perform OSINT on your own organization (with permission)
2. Map out the digital footprint of a public company
3. Practice Google dorking on authorized targets
4. Create an OSINT report template
5. Build an automated OSINT collection workflow

## Best Practices

- **Document Everything**: Keep detailed notes with timestamps
- **Verify Information**: Cross-reference multiple sources
- **Stay Organized**: Use tools like CherryTree, Obsidian, or Notion
- **Respect Boundaries**: Don't cross into active reconnaissance
- **Be Patient**: OSINT takes time and thoroughness
- **Stay Updated**: New tools and techniques emerge regularly

## Resources

- [OSINT Framework](https://osintframework.com/)
- [Awesome OSINT](https://github.com/jivoi/awesome-osint)
- [OSINT Techniques](https://www.osinttechniques.com/)
- [Bellingcat's Online Investigation Toolkit](https://bit.ly/bcattools)
- [IntelTechniques OSINT Tools](https://inteltechniques.com/tools/)

## Next Steps

After gathering passive intelligence, you'll move to active reconnaissance, where you'll directly interact with target systems through scanning and fuzzing techniques.

