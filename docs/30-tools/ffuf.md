# ffuf (Fuzz Faster U Fool)

**High-performance web fuzzer for content discovery and attack surface mapping**

## Purpose

ffuf is a fast, flexible web fuzzer designed for discovering hidden content, enumerating parameters, and mapping attack surfaces. From an Application Security perspective, ffuf excels at:

1. **Endpoint discovery** — Find undocumented APIs, admin panels, legacy paths
2. **Parameter enumeration** — Identify hidden GET/POST parameters and headers
3. **Virtual host discovery** — Enumerate subdomains and vhosts not in DNS
4. **Attack surface mapping** — Catalog all accessible functionality before testing

**Why ffuf matters:** Applications often expose more functionality than documented. Hidden endpoints frequently lack the same security hardening as public-facing features, making them prime targets for IDOR, authentication bypass, and privilege escalation vulnerabilities.

---

## Installation
```bash
# Go install (recommended)
go install github.com/ffuf/ffuf/v2@latest

# Kali/Debian
sudo apt install ffuf

# Homebrew (macOS)
brew install ffuf
```

---

## Basic Usage

### Directory and File Enumeration
```bash
# Basic directory fuzzing
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# File extension fuzzing
ffuf -u http://target.com/FUZZ -w wordlist.txt -e .php,.html,.js,.txt

# Recursive enumeration (use carefully)
ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2
```

**What this discovers:**
```
[Status: 200, Size: 4567] http://target.com/admin
[Status: 200, Size: 890]  http://target.com/config.php
[Status: 200, Size: 1234] http://target.com/api
[Status: 403, Size: 290]  http://target.com/backup
```

**Security impact:**
- `/admin` — Administrative interface, test for authentication bypass
- `/config.php` — Configuration file, may leak credentials if accessible
- `/api` — Undocumented API, test for authorization flaws
- `/backup` — Forbidden but exists, indicates backup files may be present

### API Endpoint Discovery
```bash
# REST API enumeration
ffuf -u http://api.target.com/v1/FUZZ -w api-endpoints.txt

# Common API paths
ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

**Example findings:**
```
[Status: 200] http://api.target.com/v1/users
[Status: 200] http://api.target.com/v1/admin/users     ← Privilege escalation target
[Status: 200] http://api.target.com/v1/internal        ← Internal-only endpoint
[Status: 401] http://api.target.com/v1/debug           ← Debug endpoint (investigate auth)
```

**AppSec implication:** Internal or admin API endpoints may lack the same authorization controls as public endpoints.

---

## Advanced Fuzzing Techniques

### Parameter Discovery

#### GET Parameter Fuzzing
```bash
# Fuzz GET parameters
ffuf -u "http://target.com/search?FUZZ=test" -w parameters.txt

# Multiple parameter fuzzing
ffuf -u "http://target.com/api?FUZZ=value" -w params.txt -mc 200,500
```

**Why this matters:** Hidden parameters often bypass frontend validation.

**Example:**
```
# Documented parameter
http://target.com/profile?user=123

# Discovered via fuzzing
http://target.com/profile?user=123&debug=true          ← Debug mode enabled
http://target.com/profile?user=123&admin=1             ← Privilege escalation
http://target.com/profile?user=123&export=csv          ← Data exfiltration vector
```

#### POST Data Fuzzing
```bash
# Fuzz POST data
ffuf -u http://target.com/api/login -w params.txt \
     -X POST -d "username=admin&FUZZ=value" \
     -H "Content-Type: application/x-www-form-urlencoded"

# JSON POST fuzzing
ffuf -u http://api.target.com/endpoint -w params.txt \
     -X POST -d '{"FUZZ":"value"}' \
     -H "Content-Type: application/json"
```

#### Header Fuzzing
```bash
# Discover custom headers
ffuf -u http://target.com/ -w headers.txt \
     -H "FUZZ: value" -mc 200

# Common security headers to test
# X-Forwarded-For, X-Original-URL, X-Rewrite-URL, X-Debug, X-Admin
```

**Real-world example:**
```bash
# Discovered header bypasses authentication
curl -H "X-Internal-Request: true" http://target.com/admin
→ Returns admin panel without credentials
```

### Virtual Host (vhost) Discovery
```bash
# Enumerate vhosts on same IP
ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" \
     -w subdomains.txt -fs 1234

# Filter by response size to remove false positives
# -fs 1234 removes responses of 1234 bytes (default page)
```

**Why this matters:**
- Development/staging environments on same server
- Internal services accessible via vhost routing
- Legacy applications with different security posture

**Example discoveries:**
```
[Size: 5678] admin.target.com      ← Admin subdomain
[Size: 3456] dev.target.com        ← Development environment
[Size: 8901] internal.target.com   ← Internal services
```

### Subdomain Enumeration
```bash
# DNS-based subdomain discovery
ffuf -u http://FUZZ.target.com -w subdomains.txt

# Combine with filtering
ffuf -u http://FUZZ.target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302
```

---

## Filtering and Matching

### Response Filtering

| Flag | Purpose | Example |
|------|---------|---------|
| `-fc` | Filter HTTP status codes | `-fc 404,403` |
| `-fs` | Filter response size | `-fs 1234` |
| `-fw` | Filter word count | `-fw 100` |
| `-fl` | Filter line count | `-fl 20` |
| `-fr` | Filter regex pattern | `-fr "Page not found"` |

### Response Matching (Include Only)

| Flag | Purpose | Example |
|------|---------|---------|
| `-mc` | Match HTTP status codes | `-mc 200,500` |
| `-ms` | Match response size | `-ms 5000-6000` |
| `-mw` | Match word count | `-mw 50-100` |
| `-ml` | Match line count | `-ml 10-20` |
| `-mr` | Match regex pattern | `-mr "Welcome"` |

### Practical Filtering Examples
```bash
# Remove 404 and 403 responses
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404,403

# Filter out default error page (size 1234 bytes)
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 1234

# Only show responses with "admin" in content
ffuf -u http://target.com/FUZZ -w wordlist.txt -mr "admin"

# Only show 200 and 500 responses (success and errors)
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,500
```

**Why filtering matters:** Default scans generate thousands of false positives. Proper filtering reveals actual findings.

---

## Multiple Wordlists and Cluster Bombing

### Using Multiple Wordlists
```bash
# Two wordlists: usernames and passwords
ffuf -u http://target.com/login \
     -w users.txt:USER -w passwords.txt:PASS \
     -X POST -d "username=USER&password=PASS" \
     -fc 401

# Three positions: directories, files, extensions
ffuf -u http://target.com/FUZZ1/FUZZ2.FUZZ3 \
     -w dirs.txt:FUZZ1 -w files.txt:FUZZ2 -w exts.txt:FUZZ3
```

**Example use case:**
```bash
# Discover backup files across directories
ffuf -u http://target.com/FUZZ1/FUZZ2 \
     -w dirs.txt:FUZZ1 \
     -w backups.txt:FUZZ2

# Where backups.txt contains: backup, backup.zip, backup.tar.gz, db_backup.sql
# Discovers: /admin/backup.zip, /config/db_backup.sql
```

### Mode Selection
```bash
# Clusterbomb (all combinations) - DEFAULT
ffuf -u http://target.com/FUZZ1/FUZZ2 -w w1.txt:FUZZ1 -w w2.txt:FUZZ2 -mode clusterbomb

# Pitchfork (parallel iteration)
ffuf -u http://target.com/FUZZ1/FUZZ2 -w w1.txt:FUZZ1 -w w2.txt:FUZZ2 -mode pitchfork

# Sniper (one wordlist, one position at a time)
ffuf -u http://target.com/FUZZ -w wordlist.txt -mode sniper
```

**When to use each:**
- **Clusterbomb:** Brute-force credentials (user1+pass1, user1+pass2, user2+pass1, etc.)
- **Pitchfork:** Known username/password pairs (user1+pass1, user2+pass2, etc.)
- **Sniper:** Single target fuzzing (default, most common)

---

## Performance and Threading
```bash
# Adjust thread count (default: 40)
ffuf -u http://target.com/FUZZ -w wordlist.txt -t 100

# Add delay between requests (rate limiting)
ffuf -u http://target.com/FUZZ -w wordlist.txt -rate 50

# Add delay per thread
ffuf -u http://target.com/FUZZ -w wordlist.txt -p 0.1

# Silent mode (less output noise)
ffuf -u http://target.com/FUZZ -w wordlist.txt -s

# Timeout settings
ffuf -u http://target.com/FUZZ -w wordlist.txt -timeout 10
```

**Production considerations:**
- Use `-rate` to avoid overwhelming production systems
- Lower thread count (`-t 20`) for fragile legacy applications
- Increase timeout for slow-responding servers

---

## Output Formats
```bash
# JSON output (for automation/parsing)
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.json -of json

# CSV output (for spreadsheets)
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.csv -of csv

# HTML output (for reports)
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.html -of html

# Markdown output
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.md -of md

# All formats
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results -of all
```

---

## AppSec Workflows

### Workflow 1: External Attack Surface Mapping
```bash
# Step 1: Directory discovery
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -fc 404 -o dirs.json -of json

# Step 2: File discovery in found directories
cat dirs.json | jq -r '.results[].url' | while read dir; do
    ffuf -u "$dir/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -fc 404 -e .php,.html,.js,.txt
done

# Step 3: API endpoint enumeration
ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -mc 200,401,403 -o api_endpoints.json -of json

# Step 4: Parameter fuzzing on discovered endpoints
ffuf -u "https://target.com/api/users?FUZZ=test" -w parameters.txt -mc 200,500
```

**Goal:** Build complete inventory of accessible functionality for subsequent security testing.

### Workflow 2: IDOR Testing Preparation
```bash
# Discover endpoints that accept IDs
ffuf -u "http://target.com/FUZZ?id=1" -w endpoints.txt -mc 200

# Test ID parameter variations
ffuf -u "http://target.com/profile?FUZZ=1" -w id-params.txt -mc 200
# id-params.txt contains: id, user_id, userid, uid, account_id, cid, etc.

# Results feed into Burp Intruder for IDOR testing
```

**Why this matters:** Finding all ID-accepting endpoints is the first step in systematic IDOR testing.

### Workflow 3: Authentication Bypass Discovery
```bash
# Find admin paths
ffuf -u http://target.com/FUZZ -w admin-paths.txt -mc 200,301,302,401,403

# Test authentication bypass headers
ffuf -u http://target.com/admin -H "FUZZ: true" -w auth-headers.txt -mc 200
# auth-headers.txt: X-Admin, X-Internal-Request, X-Debug, X-Forwarded-For, etc.

# Test parameter-based bypass
ffuf -u "http://target.com/admin?FUZZ=true" -w bypass-params.txt -mc 200
# bypass-params.txt: debug, admin, internal, test, dev, etc.
```

**Example finding:**
```bash
# Normal request
curl http://target.com/admin
→ 401 Unauthorized

# After ffuf discovers bypass
curl -H "X-Debug-Mode: true" http://target.com/admin
→ 200 OK (admin panel accessible)
```

### Workflow 4: Subdomain Takeover Discovery
```bash
# Find subdomains
ffuf -u http://FUZZ.target.com -w subdomains.txt -mc 200,301,302

# Check for CNAME records pointing to external services
dig dev.target.com
→ dev.target.com CNAME mybucket.s3.amazonaws.com

# Verify bucket doesn't exist
curl http://mybucket.s3.amazonaws.com
→ NoSuchBucket (SUBDOMAIN TAKEOVER POSSIBLE)
```

**Business impact:** Subdomain takeover enables phishing, malware distribution, session hijacking.

---

## Wordlist Recommendations

### Essential Wordlists (SecLists)
```bash
# Install SecLists
git clone https://github.com/danielmiessler/SecLists.git

# Best general-purpose wordlists:
# Directories
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Files
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

# Parameters
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Subdomains
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# API endpoints
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

### Custom Wordlist Creation
```bash
# Generate wordlist from target's JavaScript files
# Step 1: Download JS files
wget -r -l 1 -H -t 1 -nd -N -np -A.js -erobots=off http://target.com

# Step 2: Extract potential endpoints
cat *.js | grep -oP '"/[a-zA-Z0-9_/-]*"' | sort -u > custom_endpoints.txt

# Step 3: Use in ffuf
ffuf -u http://target.com/FUZZ -w custom_endpoints.txt
```

**Why this works:** JavaScript often contains references to undocumented API endpoints, debug paths, and legacy features.

---

## Integration with Other Tools

### ffuf → Burp Suite
```bash
# Save ffuf results
ffuf -u http://target.com/FUZZ -w wordlist.txt -o endpoints.txt -of all

# Import discovered endpoints into Burp Suite
# 1. Open Burp → Target → Site map
# 2. Right-click → "Paste URL"
# 3. Paste each discovered endpoint
# 4. Use Burp Scanner/Intruder for deeper testing
```

### ffuf → Nuclei (Vulnerability Scanning)
```bash
# Discover endpoints with ffuf
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200 | tee endpoints.txt

# Extract URLs
cat endpoints.txt | grep -oP 'http://[^\s]+' > urls.txt

# Scan with Nuclei
nuclei -l urls.txt -t /path/to/templates/
```

### ffuf → SQLMap
```bash
# Find parameter injection points
ffuf -u "http://target.com/page?FUZZ=test" -w params.txt -mc 200 | grep "id\|user\|search"

# Test discovered parameters with SQLMap
sqlmap -u "http://target.com/page?id=1" --batch
```

---

## Rate Limiting and Evasion

### Avoiding Rate Limits
```bash
# Slow down requests
ffuf -u http://target.com/FUZZ -w wordlist.txt -rate 10

# Add random delay
ffuf -u http://target.com/FUZZ -w wordlist.txt -p 0.5-1.5

# Randomize User-Agent
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "User-Agent: FUZZ" -w user-agents.txt
```

### Bypassing WAF/Security Controls
```bash
# Custom User-Agent
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "User-Agent: Mozilla/5.0..."

# Use different HTTP methods
ffuf -u http://target.com/FUZZ -w wordlist.txt -X POST

# Encode payloads (URL encoding)
# ffuf automatically handles this in most cases

# Add cookies/authentication
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "Cookie: session=abc123"
```

---

## Common Pitfalls and Best Practices

### Pitfall 1: Not Filtering Results
```bash
# BAD: No filtering, thousands of 404s
ffuf -u http://target.com/FUZZ -w huge-wordlist.txt

# GOOD: Filter 404s and 403s
ffuf -u http://target.com/FUZZ -w huge-wordlist.txt -fc 404,403
```

### Pitfall 2: Using Wrong Wordlist
```bash
# BAD: Generic wordlist misses application-specific paths
ffuf -u http://djangoapp.com/FUZZ -w generic.txt

# GOOD: Django-specific wordlist finds framework paths
ffuf -u http://djangoapp.com/FUZZ -w django-paths.txt
# Contains: /admin/, /static/, /media/, /__debug__/, etc.
```

### Pitfall 3: Ignoring Response Content
```bash
# BAD: Only looking at status codes
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200

# GOOD: Also check response size and content
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200 -fs 0 -mr "admin\|debug\|api"
```

### Best Practice: Save All Results
```bash
# Always save results for later analysis
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.json -of json

# Parse later to find specific patterns
cat results.json | jq -r '.results[] | select(.status == 403) | .url'
```

---

## Defense and Detection

### How to Detect ffuf Scans

**WAF/IDS signatures:**
- High request rate from single IP
- Sequential URL enumeration patterns
- User-Agent: `ffuf/1.x.x` (default, can be changed)
- Requests to common wordlist paths (`/admin`, `/backup`, `/test`)

### Protecting Against Content Discovery
```bash
# Rate limit by IP
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute -j ACCEPT

# Fail2ban rule for rapid requests
[http-scan]
enabled = true
filter = http-scan
action = iptables-multiport[name=http, port="80,443"]
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime = 3600
```

### Security by Obscurity is Not Security

**Don't rely on:**
- Hidden paths staying hidden (they will be found)
- Security through obscurity for sensitive endpoints

**Do rely on:**
- Proper authentication on ALL endpoints
- Authorization checks on every request
- Logging and monitoring for suspicious access patterns

---

## Interview Talking Points

**If asked about ffuf in an interview:**

> "ffuf is my primary tool for content discovery and attack surface mapping. Before any penetration test, I use it to enumerate directories, files, API endpoints, and parameters. This reveals undocumented functionality that often lacks the same security controls as documented features. For example, I once discovered an `/api/internal/users` endpoint using ffuf that didn't require authentication, while the documented `/api/users` endpoint did. That led to finding an IDOR vulnerability allowing access to all user records. The key with ffuf is proper filtering—without filtering 404s and false positives, you'll drown in noise and miss real findings. I also integrate ffuf results with Burp Suite for deeper manual testing of discovered endpoints."

**Follow-up: "How do you avoid disrupting production systems with ffuf?"**

> "I carefully tune thread count and request rate. For production systems, I use `-t 20` to limit concurrent threads and `-rate 50` to cap requests per second. I also coordinate with DevOps to run scans during low-traffic windows and monitor application performance during the scan. If I see response times increasing or errors spiking, I pause and reduce the rate further. The goal is finding security issues without becoming an availability issue ourselves. I also use smaller, targeted wordlists rather than huge generic ones—quality over quantity."

**Follow-up: "What's the difference between ffuf and gobuster?"**

> "Both are content discovery tools, but ffuf is more flexible. Gobuster is simpler and faster for basic directory enumeration, but ffuf supports fuzzing any part of the request—URLs, parameters, headers, POST data. ffuf also has better filtering options and can handle multiple wordlists simultaneously for cluster bomb attacks. For example, testing username/password combinations or discovering backup files across multiple directories. I use gobuster for quick wins and ffuf when I need more sophisticated fuzzing or when I'm dealing with APIs that require specific headers or POST data."

---

## Quick Reference

### Essential Commands
```bash
# Basic directory fuzzing
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404

# Parameter discovery
ffuf -u "http://target.com/page?FUZZ=value" -w params.txt -mc 200

# Virtual host discovery
ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" -w subdomains.txt -fs 1234

# POST data fuzzing
ffuf -u http://target.com/api -X POST -d "FUZZ=value" -w params.txt -mc 200

# Header fuzzing
ffuf -u http://target.com/ -H "FUZZ: value" -w headers.txt -mc 200

# Multiple wordlists
ffuf -u http://target.com/FUZZ1/FUZZ2 -w dirs.txt:FUZZ1 -w files.txt:FUZZ2
```

### Key Flags

| Flag | Purpose |
|------|---------|
| `-u` | Target URL (use `FUZZ` as placeholder) |
| `-w` | Wordlist file path |
| `-mc` | Match HTTP status codes |
| `-fc` | Filter HTTP status codes |
| `-fs` | Filter response size |
| `-mr` | Match regex in response |
| `-o` | Output file |
| `-of` | Output format (json, csv, html, md) |
| `-t` | Number of threads (default: 40) |
| `-rate` | Rate limit (requests per second) |
| `-p` | Delay between requests (seconds) |
| `-e` | File extensions to fuzz |
| `-recursion` | Enable recursive enumeration |
| `-H` | Custom header |
| `-X` | HTTP method (GET, POST, etc.) |
| `-d` | POST data |

---

## Additional Resources

- **Official Documentation:** https://github.com/ffuf/ffuf
- **SecLists Wordlists:** https://github.com/danielmiessler/SecLists
- **ffuf Usage Guide:** https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html

---

## Testing Checklist

- [ ] Choose appropriate wordlist for target technology
- [ ] Set reasonable thread count for production systems
- [ ] Configure filtering to remove false positives
- [ ] Save results in parseable format (JSON)
- [ ] Analyze discovered endpoints for security issues
- [ ] Test authentication/authorization on new findings
- [ ] Document business impact of exposed endpoints
- [ ] Feed results into Burp Suite for deeper testing
