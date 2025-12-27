# Nmap

**Network discovery and security auditing tool**

## Purpose

Nmap is the industry-standard tool for network reconnaissance, service enumeration, and vulnerability discovery. From an Application Security perspective, Nmap serves critical functions in:

1. **Attack surface mapping** — Identify exposed services before penetration testing
2. **Service fingerprinting** — Detect outdated software versions with known vulnerabilities
3. **Network segmentation validation** — Verify internal services aren't internet-accessible
4. **Compliance verification** — Confirm only authorized ports/services are exposed (PCI-DSS 2.2.2)

**Critical AppSec Note:** Nmap is noisy and easily detected. Use it for authorized reconnaissance and external attack surface assessment, not stealth operations.

---

## Scan Types Explained

### TCP Scan Types

| Scan Type | Flag | How It Works | When to Use |
|-----------|------|--------------|-------------|
| **SYN Scan (Stealth)** | `-sS` | Sends SYN, waits for SYN-ACK, never completes handshake | Default scan, faster than full connect, requires root |
| **TCP Connect** | `-sT` | Completes full 3-way handshake | When you don't have root/admin privileges |
| **ACK Scan** | `-sA` | Sends ACK packets to determine firewall rules | Firewall/IDS rule mapping |
| **Window Scan** | `-sW` | Similar to ACK but checks TCP window field | Firewall detection on certain systems |
| **NULL Scan** | `-sN` | Sends packet with no flags set | Firewall evasion (unreliable) |
| **FIN Scan** | `-sF` | Sends FIN flag only | Firewall evasion (unreliable) |
| **Xmas Scan** | `-sX` | Sets FIN, PSH, URG flags | Firewall evasion (unreliable) |

### UDP Scan
```bash
# UDP scan (slow but critical for DNS, SNMP, DHCP discovery)
nmap -sU target.com
```

**Why UDP matters:**
- Many critical services run on UDP (DNS port 53, SNMP port 161)
- Often overlooked in security assessments
- Slower than TCP (requires timeouts for closed ports)

---

## Common Scan Commands

### Basic Network Discovery
```bash
# Quick ping sweep (discover live hosts)
nmap -sn 192.168.1.0/24

# Scan most common 1000 ports
nmap target.com

# Scan specific ports
nmap -p 22,80,443,3306 target.com

# Scan port range
nmap -p 1-1000 target.com

# Scan ALL ports (65535)
nmap -p- target.com
```

### Service Version Detection
```bash
# Detect service versions
nmap -sV target.com

# Aggressive version detection (more probes)
nmap -sV --version-intensity 5 target.com

# Light version detection (fewer probes, faster)
nmap -sV --version-intensity 0 target.com
```

**Why this matters:** Version detection reveals outdated software. For example:
```
22/tcp open ssh OpenSSH 5.3 (protocol 2.0)
```
→ OpenSSH 5.3 is from 2010, has multiple known CVEs

### Operating System Detection
```bash
# OS fingerprinting
nmap -O target.com

# Aggressive OS detection (more probes)
nmap -O --osscan-guess target.com
```

**Example output:**
```
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
```

### Combined Scans (Recommended for AppSec)
```bash
# Standard reconnaissance scan
nmap -sV -sC -O target.com

# Aggressive scan (version + OS + traceroute + scripts)
nmap -A target.com

# Full port scan with service detection
nmap -p- -sV -sC target.com
```

---

## NSE (Nmap Scripting Engine)

**NSE scripts extend Nmap's capabilities for vulnerability detection, exploitation, and enumeration.**

### Default Scripts
```bash
# Run default safe scripts
nmap -sC target.com

# Equivalent to:
nmap --script=default target.com
```

**Default scripts include:**
- Banner grabbing
- Service enumeration
- SSL/TLS certificate inspection
- HTTP title extraction

### Vulnerability Detection Scripts
```bash
# Scan for specific vulnerabilities
nmap --script=vuln target.com

# Check for SMB vulnerabilities (e.g., EternalBlue)
nmap --script=smb-vuln-ms17-010 target.com

# Check for SSL/TLS vulnerabilities
nmap --script=ssl-heartbleed,ssl-poodle,ssl-ccs-injection target.com

# HTTP vulnerability scripts
nmap --script=http-vuln-* target.com
```

### Authentication Scripts
```bash
# Brute-force SSH
nmap --script=ssh-brute --script-args userdb=users.txt,passdb=pass.txt target.com

# Brute-force FTP
nmap --script=ftp-brute target.com

# Check for default credentials
nmap --script=http-default-accounts target.com
```

### Enumeration Scripts
```bash
# SMB enumeration
nmap --script=smb-enum-shares,smb-enum-users target.com

# DNS enumeration
nmap --script=dns-brute domain.com

# SNMP enumeration
nmap --script=snmp-brute,snmp-info target.com
```

### Custom Script Execution
```bash
# Run specific script
nmap --script=/path/to/custom-script.nse target.com

# Run multiple scripts
nmap --script=http-title,http-headers target.com

# Run scripts from category
nmap --script=discovery target.com
```

**Script categories:**
- `auth` — Authentication bypass testing
- `brute` — Brute-force attacks
- `default` — Safe, commonly useful scripts
- `discovery` — Network/service discovery
- `dos` — Denial of service testing (use carefully)
- `exploit` — Active exploitation scripts
- `intrusive` — May crash services or consume significant resources
- `malware` — Malware detection
- `safe` — Won't affect target
- `version` — Advanced version detection
- `vuln` — Vulnerability detection

---

## Timing and Performance

### Timing Templates
```bash
# Paranoid (IDS evasion, extremely slow)
nmap -T0 target.com

# Sneaky (IDS evasion, very slow)
nmap -T1 target.com

# Polite (reduces bandwidth, slower)
nmap -T2 target.com

# Normal (default)
nmap -T3 target.com

# Aggressive (faster, assumes good network)
nmap -T4 target.com

# Insane (extremely fast, may miss hosts)
nmap -T5 target.com
```

**AppSec recommendation:** Use `-T4` for internal assessments, `-T2` or `-T3` for external scans to avoid detection/blocking.

### Parallel Scanning
```bash
# Increase parallelism (default: dynamically adjusted)
nmap --min-parallelism 100 target.com

# Scan multiple targets simultaneously
nmap target1.com target2.com target3.com

# Scan from file
nmap -iL targets.txt
```

---

## Output Formats

### Standard Output Formats
```bash
# Normal output (human-readable)
nmap -oN scan_results.txt target.com

# XML output (parseable, for tools)
nmap -oX scan_results.xml target.com

# Grepable output (one line per host)
nmap -oG scan_results.gnmap target.com

# All formats at once
nmap -oA scan_results target.com
```

**Which format to use:**
- `-oN` — For reports, documentation, human review
- `-oX` — For importing into Metasploit, Burp, or custom scripts
- `-oG` — For grep/awk parsing in shell scripts
- `-oA` — Save all three (recommended for thoroughness)

### Verbose Output
```bash
# Increase verbosity
nmap -v target.com

# Maximum verbosity
nmap -vv target.com

# Debug output (very detailed)
nmap -d target.com
```

---

## AppSec Workflows

### External Attack Surface Assessment
```bash
# Step 1: Discover live hosts
nmap -sn company-ip-range.txt -oA discovery

# Step 2: Port scan discovered hosts
nmap -iL live_hosts.txt -p- -sV -sC -oA full_scan

# Step 3: Vulnerability detection
nmap -iL live_hosts.txt --script=vuln -oA vuln_scan

# Step 4: Analyze results
grep "open" full_scan.gnmap | cut -d' ' -f2 | sort -u > open_hosts.txt
```

**Goal:** Identify publicly exposed services that shouldn't be internet-accessible (databases, admin panels, internal APIs).

### Internal Network Segmentation Testing
```bash
# From DMZ server, test if you can reach internal network
nmap -sn 10.0.0.0/8 -oA internal_discovery

# Expected: No response (proper segmentation)
# Actual: 50 hosts respond → segmentation failure
```

**Business Impact:** Failed network segmentation violates PCI-DSS 1.2.1, allowing attackers to pivot from compromised DMZ to internal systems.

### Service Version Inventory
```bash
# Inventory all service versions for patch management
nmap -sV -p- internal-network.txt -oX service_inventory.xml

# Parse with xmlstarlet or custom script to extract:
# - Service names
# - Version numbers
# - Associated CVEs (cross-reference with vulnerability databases)
```

**Use Case:** Identify outdated software across infrastructure (Apache 2.2, OpenSSL 1.0.1, PHP 5.6).

---

## Common Ports Reference

| Port | Service | AppSec Notes |
|------|---------|--------------|
| **20/21** | FTP | Check for anonymous access, plaintext credentials |
| **22** | SSH | Brute-force target, check for weak ciphers |
| **23** | Telnet | Insecure, plaintext credentials, should be disabled |
| **25** | SMTP | Open relay testing, user enumeration |
| **53** | DNS | Zone transfer testing, subdomain enumeration |
| **80** | HTTP | Web application testing, check for HTTPS redirect |
| **110/995** | POP3/POP3S | Email enumeration, credential testing |
| **143/993** | IMAP/IMAPS | Email access, credential testing |
| **161/162** | SNMP | Community string brute-force, system enumeration |
| **389/636** | LDAP/LDAPS | Directory enumeration, credential testing |
| **443** | HTTPS | SSL/TLS testing, web application testing |
| **445** | SMB | File sharing, EternalBlue, credential dumping |
| **1433** | MSSQL | Database access, xp_cmdshell exploitation |
| **3306** | MySQL | Database access, check for remote root |
| **3389** | RDP | Remote desktop, brute-force target |
| **5432** | PostgreSQL | Database access, privilege escalation |
| **5900** | VNC | Remote access, often weak/no authentication |
| **6379** | Redis | Often no authentication, RCE via SSRF |
| **8080/8443** | HTTP Alt | Web applications, admin panels |
| **27017** | MongoDB | NoSQL database, often no authentication |

---

## Firewall and IDS Evasion

### Fragment Packets
```bash
# Fragment packets to evade firewalls/IDS
nmap -f target.com

# Use specific MTU size
nmap --mtu 24 target.com
```

### Decoy Scanning
```bash
# Use decoy IPs to hide your real source
nmap -D RND:10 target.com

# Specify decoy IPs manually
nmap -D decoy1,decoy2,ME,decoy3 target.com
```

### Spoof Source IP/Port
```bash
# Spoof source IP (requires raw socket access)
nmap -S spoofed-ip target.com

# Use specific source port (useful for firewall bypass)
nmap --source-port 53 target.com
```

### Randomize Target Order
```bash
# Randomize host scanning order
nmap --randomize-hosts target-list.txt
```

**AppSec Note:** These techniques are primarily for penetration testing red team operations. In AppSec, you're typically authorized and don't need evasion. However, understanding these helps you defend against attackers using them.

---

## Interpreting Results

### Port States

| State | Meaning | Action |
|-------|---------|--------|
| **open** | Service actively accepting connections | Test for vulnerabilities |
| **closed** | Port is accessible but no service listening | Usually safe, document anyway |
| **filtered** | Firewall/filter blocking probes | May indicate hidden service |
| **unfiltered** | Accessible but can't determine if open/closed | Further testing needed |
| **open\|filtered** | Can't determine if open or filtered | Try other scan techniques |
| **closed\|filtered** | Can't determine if closed or filtered | Try other scan techniques |

### Example Scan Output Analysis
```
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp    open     http        Apache httpd 2.4.6
443/tcp   open     ssl/http    Apache httpd 2.4.6
3306/tcp  filtered mysql
8080/tcp  open     http-proxy  Squid http proxy 3.5.20
```

**Security findings:**
- Port 22: SSH open (expected for server management)
- Port 80: HTTP open — check if redirects to HTTPS (PCI-DSS 2.3)
- Port 443: HTTPS open (expected)
- **Port 3306: MySQL filtered from external network (GOOD)** — should never be internet-accessible
- Port 8080: Squid proxy — investigate if intentionally exposed

**Report to developers:**
> "MySQL port 3306 is filtered from external network, which is correct. However, Apache 2.4.6 is outdated (released 2013) and has multiple CVEs. Recommend upgrading to latest version to address known vulnerabilities including CVE-2017-15710, CVE-2017-15715."

---

## Integration with Other Tools

### Export to Metasploit
```bash
# Scan and save XML
nmap -sV -oX nmap_scan.xml target.com

# Import into Metasploit
msfconsole
msf6 > db_import nmap_scan.xml
msf6 > hosts
msf6 > services
```

### Parse with Python (python-nmap)
```python
import nmap

nm = nmap.PortScanner()
nm.scan('target.com', '1-1000')

for host in nm.all_hosts():
    print(f'Host: {host} ({nm[host].hostname()})')
    print(f'State: {nm[host].state()}')
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in ports:
            print(f'Port: {port}\tState: {nm[host][proto][port]["state"]}')
```

### Chain with Vulnerability Scanners
```bash
# Step 1: Nmap discovery
nmap -sV -oX services.xml target-range

# Step 2: Extract open ports
grep "open" services.gnmap | cut -d' ' -f2 > targets.txt

# Step 3: Run Nikto on discovered web servers
nikto -h targets.txt

# Step 4: Run OpenVAS/Nessus for deep vulnerability scanning
```

---

## Defense and Detection

### How to Detect Nmap Scans

**IDS/IPS signatures that detect Nmap:**
- Multiple SYN packets to sequential ports (port scanning)
- SYN packets with no corresponding ACK (SYN scan)
- Unusual TCP flag combinations (NULL, FIN, Xmas scans)
- Many connection attempts to closed ports
- OS fingerprinting probes (unusual packet characteristics)

### Protecting Against Nmap Reconnaissance
```bash
# Firewall: Rate limit connection attempts
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Fail2ban: Ban IPs after scanning behavior
[nmap-scan]
enabled = true
filter = nmap
action = iptables-multiport[name=nmap, port="all"]
logpath = /var/log/syslog
maxretry = 3
bantime = 3600
```

### Honeypot Detection

**Be aware:** Many organizations deploy honeypot ports (closed ports that log connection attempts).

**Example:**
```
# Nmap finds port 2222 open
# Actually a honeypot - triggers security alert
# Your IP is now flagged for manual review
```

**Best practice:** Only scan authorized targets during authorized assessment windows.

---

## Compliance and Legal Considerations

### Authorization Requirements

**CRITICAL:** Unauthorized port scanning may violate:
- **Computer Fraud and Abuse Act (CFAA)** in the US
- **Computer Misuse Act** in the UK
- **Similar laws in other jurisdictions**

**Always obtain written authorization before scanning:**
- External penetration tests: Signed contract with scope definition
- Internal assessments: Documented approval from IT/Security leadership
- Bug bounty programs: Follow program rules (many prohibit network scanning)

### PCI-DSS Requirements

**PCI-DSS 11.2.1:** Run internal and external network vulnerability scans at least quarterly.

**Nmap usage in PCI compliance:**
- Identify all systems in cardholder data environment (CDE)
- Verify only necessary services are enabled (Requirement 2.2.2)
- Confirm network segmentation (Requirement 1.2.1)
- Document all open ports and justify business need

---

## Interview Talking Points

**If asked about Nmap in an interview:**

> "Nmap is my go-to tool for attack surface mapping before any penetration test. I use it to identify exposed services, detect outdated software versions with known CVEs, and validate network segmentation. For example, if I'm testing an e-commerce platform, I'll scan the external IP range to confirm database ports like 3306 or 5432 aren't internet-accessible—those should be filtered. I also use NSE scripts for vulnerability detection, like checking for EternalBlue on SMB or testing SSL/TLS configurations. The key is interpreting results in business context: finding MySQL on port 3306 externally isn't just a technical issue—it's a PCI-DSS violation and potential data breach vector."

**Follow-up: "What's the difference between a SYN scan and a TCP connect scan?"**

> "A SYN scan sends a SYN packet and waits for SYN-ACK to determine if a port is open, but never completes the three-way handshake with an ACK. It's faster and stealthier because it doesn't create a full connection log entry on many systems. A TCP connect scan completes the full handshake, which is noisier and slower but doesn't require root privileges. In production AppSec assessments, I typically use SYN scans for efficiency, but TCP connect scans when working from restricted user accounts or when I want to test how the application handles full connections."

**Follow-up: "How do you avoid disrupting production systems during scanning?"**

> "I use timing templates carefully—usually `-T2` or `-T3` for production systems to avoid overwhelming network devices or triggering rate limits. I also avoid aggressive scripts in the `intrusive` or `dos` categories. Before scanning, I coordinate with DevOps to schedule during low-traffic windows and monitor application health during the scan. If I'm testing a legacy system, I'll start with a single host as a canary before scanning the entire range. The goal is finding vulnerabilities without becoming the incident we're trying to prevent."

---

## Quick Reference

### Essential Scans
```bash
# Quick host discovery
nmap -sn 192.168.1.0/24

# Standard reconnaissance
nmap -sV -sC -T4 target.com

# Full port scan with version detection
nmap -p- -sV target.com -oA full_scan

# Vulnerability scan
nmap --script=vuln target.com

# Aggressive scan (all features)
nmap -A -T4 target.com
```

### Useful One-Liners
```bash
# Find all web servers in network
nmap -p 80,443,8080,8443 192.168.1.0/24 --open

# Quick SSL/TLS check
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 target.com

# Find all hosts with SMB enabled
nmap -p 445 --script=smb-os-discovery 192.168.1.0/24

# Extract list of live hosts
nmap -sn 10.0.0.0/8 | grep "Nmap scan report" | cut -d' ' -f5
```

---

## Additional Resources

- **Official Documentation:** https://nmap.org/book/man.html
- **NSE Script Library:** https://nmap.org/nsedoc/
- **Nmap Network Scanning (Book):** https://nmap.org/book/
- **CVE Database:** https://cve.mitre.org/

---

## Testing Checklist

- [ ] Obtain written authorization
- [ ] Define scope (IP ranges, exclusions)
- [ ] Choose appropriate timing template
- [ ] Run host discovery scan
- [ ] Perform full port scan on live hosts
- [ ] Run service version detection
- [ ] Execute relevant NSE scripts
- [ ] Save all output formats (`-oA`)
- [ ] Analyze results for security findings
- [ ] Cross-reference versions with CVE databases
- [ ] Document findings with business impact
- [ ] Provide remediation recommendations

\
\